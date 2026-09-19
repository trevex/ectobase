//! `BPF_PROG_TEST_RUN` anchor for the guest-egress `tc_guest_tx` overlay-encap datapath (post-P2
//! Geneve retarget).
//!
//! ## P2 Task 2/7: no more outer flow-label — this used to be a flow-label anchor
//!
//! Before P2, `tc_guest_tx` wrote a hand-rolled outer IPv6 header itself, including an RFC
//! 6438-style flow label folded from the inner 5-tuple (`egress_flow_label`/`inner_flow_label`),
//! used for underlay ECMP entropy. This file used to anchor that fold byte-for-byte.
//!
//! P2 replaced the byte-written outer header with a Geneve tunnel-key DECISION
//! (`flowplane_core::encap::TunnelEncap`): `tc_guest_tx` now calls `bpf_skb_set_tunnel_key` +
//! redirects to the kernel's `collect_md` geneve device, which builds the real outer
//! Eth/IPv6/UDP/Geneve header on transmit — there is no outer IPv6 header, and so no outer flow
//! label, for this program to write anymore. Fabric ECMP entropy becomes the kernel's own Geneve
//! UDP-source-port hash, not something this crate computes (see `flowplane_sim::flow_label_test`'s
//! module doc, which reconciled the same fold-helpers-are-now-disconnected finding on the sim side).
//! The `flow_label20`/`hash5`/`inner_flow_label` helpers stay (still-correct, reusable hash-fold math
//! used elsewhere — e.g. LB/NAT port selection), but there is no end-to-end "guest_tx writes the
//! label into the outer header" property left to anchor.
//!
//! ## What this anchor proves now
//!
//! It loads the REAL compiled `tc_guest_tx` tc classifier, runs it on a guest frame that resolves to
//! an overlay encap (route with no local delivery target), and asserts the kernel-returned verdict is
//! `TC_ACT_REDIRECT` with the packet BYTE-FOR-BYTE UNCHANGED — the encap-side oracle P2 Task 7
//! settled on (`TC_ACT_REDIRECT` + inner-unchanged; see the plan doc's Task 1 Step 5 spike finding).
//! Byte parity against the native `SimNode::guest_tx` output continues to hold (trivially: neither
//! side writes any bytes on this path anymore), so this also still catches a regression that
//! reintroduces byte mutation on the encap arm.
//!
//! Unlike an XDP anchor, `tc_guest_tx` is a `SchedClassifier` that keys `PORT_META` on
//! `skb->ifindex` (tc.rs). So this test-run supplies a `struct __sk_buff` ctx with `ifindex` set to
//! the loopback ifindex (1, always present) and keys `PORT_META` on it. aya 0.13.1 exposes no tc
//! `test_run`, so we issue the raw `bpf(BPF_PROG_TEST_RUN, ...)` syscall on the fd of aya's loaded
//! `SchedClassifier`.
//!
//! ## The firewall classifier and the conntrack epoch
//!
//! The sim models the kernel's LPM tries and runs the core evaluator natively. The classifier
//! anchors below run the SAME compiled scopes through the real bytecode and the kernel's own tries
//! (`tc_guest_tx` for v4, `tc_guest_egress_v6` for v6): a divergence in the key layout (class byte
//! order, big-endian port prefixes, prefix lengths), in the two-probe arbitration or in the epoch
//! recheck shows up as a verdict mismatch. Every case asserts its expected verdict AND parity with
//! the native sim; the epoch anchor also reads the conntrack entries the bytecode wrote.
//!
//! Privileged: needs CAP_BPF + a kernel with tc test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap as AyaHashMap};
use aya::programs::SchedClassifier;
use flowplane_common::{
    CtEntry, CtKey, FwBind, FwMeta, FwRule, FwRule6, Local, PortMeta, RouteLpmData, RouteLpmData6,
    RouteValue, CT_F_DEFAULT, CT_F_REPLY, FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS,
};
use flowplane_core::pkt::Action;
use flowplane_sim::SimNode;

// --- Fixture (a guest frame that resolves to an overlay encap, no local delivery target) ---

/// Source ifindex the tc classifier keys PORT_META on. Loopback (1) always exists, so the kernel's
/// skb test-run can resolve `__sk_buff.ifindex` to a real device.
const IFINDEX: u32 = 1;
const UPLINK_IFINDEX: u32 = 7;
const VNI: u32 = 100;
const GUEST_IP: [u8; 4] = [10, 0, 2, 20];
const DEST_IP: [u8; 4] = [10, 1, 1, 1];
const NEXTHOP: [u8; 16] = [0x20, 1, 0xd, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const UNDERLAY: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const GUEST_MAC: [u8; 6] = [0xaa; 6];
const SPORT: u16 = 12345;
const DPORT: u16 = 53;

fn local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: UNDERLAY,
    }
}

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: GUEST_MAC,
        l3: 0,
        offloaded: 0,
        underlay_ipv6: UNDERLAY,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

fn route_value() -> RouteValue {
    // is_external:0 + no INTERFACES entry for DEST_IP → deliver returns Encap (no NAT rewrite), so
    // the label is computed from the unchanged inner 5-tuple.
    RouteValue {
        nexthop_vni: 0,
        nexthop_ipv6: NEXTHOP,
        is_external: 0,
        _pad: [0; 3],
    }
}

/// A permissive egress ALLOW rule on `IFINDEX` (the firewall is deny-by-default; the encap path is a
/// NEW flow, so it must pass an egress-allow rule).
fn egress_allow_rule() -> FwRule {
    FwRule {
        src_ip: [0; 4],
        src_mask: [0; 4],
        dst_ip: [0; 4],
        dst_mask: [0; 4],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: 0,
        dst_port_max: 65535,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto: 0,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_EGRESS,
        enabled: 1,
    }
}

/// Program the loaded object's firewall classifier for `ifindex` the way the dataplane does: compile
/// the interface's rules into per-direction scopes, build each scope's tries, insert them into the
/// outer maps, then bind the interface (`FW_BIND`).
fn seed_classifier(ebpf: &mut aya::Ebpf, ifindex: u32, rules: &[FwRule], rules6: &[FwRule6]) {
    use aya::maps::{lpm_trie::Key, of_maps::HashOfMaps, LpmTrie, MapData};
    use flowplane_common::{FwBind, FwPolKey, FW_DIR_EGRESS, FW_DIR_INGRESS};
    use flowplane_control::fwclass::compile_scope;

    fn trie<K: aya::Pod>(
        entries: impl ExactSizeIterator<Item = (u32, K, u32)>,
    ) -> LpmTrie<MapData, K, u32> {
        let mut t = LpmTrie::<MapData, K, u32>::create(entries.len().max(1) as u32, 1).unwrap();
        for (plen, k, v) in entries {
            t.insert(&Key::new(plen, k), v, 0).unwrap();
        }
        t
    }
    let mut bind = FwBind::default();
    for dir in [FW_DIR_INGRESS, FW_DIR_EGRESS] {
        let Some(scope) = compile_scope(dir, rules.iter(), rules6.iter()).unwrap() else {
            continue;
        };
        let c4 = trie(scope.v4.classes.iter().map(|&(a, l, c)| (l as u32, a, c)));
        let c6 = trie(scope.v6.classes.iter().map(|&(a, l, c)| (l as u32, a, c)));
        let p4 = trie(scope.v4.policy.iter().copied());
        let p6 = trie(scope.v6.policy.iter().copied());
        let mut class4: HashOfMaps<_, u64, LpmTrie<MapData, [u8; 4], u32>> =
            HashOfMaps::try_from(ebpf.map_mut("FW_CLASS").unwrap()).unwrap();
        class4.insert(scope.id, &c4, 0).unwrap();
        let mut class6: HashOfMaps<_, u64, LpmTrie<MapData, [u8; 16], u32>> =
            HashOfMaps::try_from(ebpf.map_mut("FW_CLASS6").unwrap()).unwrap();
        class6.insert(scope.id, &c6, 0).unwrap();
        let mut pol4: HashOfMaps<_, u64, LpmTrie<MapData, FwPolKey, u32>> =
            HashOfMaps::try_from(ebpf.map_mut("FW_POLICY").unwrap()).unwrap();
        pol4.insert(scope.id, &p4, 0).unwrap();
        let mut pol6: HashOfMaps<_, u64, LpmTrie<MapData, FwPolKey, u32>> =
            HashOfMaps::try_from(ebpf.map_mut("FW_POLICY6").unwrap()).unwrap();
        pol6.insert(scope.id, &p6, 0).unwrap();
        if dir == FW_DIR_EGRESS {
            bind.egress_scope = scope.id;
        } else {
            bind.ingress_scope = scope.id;
        }
    }
    let mut fw_bind: AyaHashMap<_, u32, FwBind> =
        AyaHashMap::try_from(ebpf.map_mut("FW_BIND").expect("FW_BIND map")).unwrap();
    fw_bind.insert(ifindex, bind, 0).expect("insert FW_BIND");
}

/// A guest Ethernet frame `[Eth][IPv4][UDP]` from GUEST_IP:SPORT -> DEST_IP:DPORT.
fn guest_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let mut frame = Vec::new();
    PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6])
        .ipv4(GUEST_IP, DEST_IP, 64)
        .udp(SPORT, DPORT)
        .write(&mut frame, &[])
        .unwrap();
    frame
}

/// Build the native (pure-core) expected output for the fixture: the same map state the eBPF maps
/// get, run through `SimNode::guest_tx`.
fn native_output(frame: &[u8]) -> (Action, Vec<u8>) {
    let mut node = SimNode::new();
    node.src_ifindex = IFINDEX;
    node.maps.local = Some(local());
    node.maps.add_route4(VNI, DEST_IP, route_value());
    node.maps.fw_meta.insert(
        IFINDEX,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps.fw_rules.insert((IFINDEX, 0), egress_allow_rule());
    let out = node.guest_tx(frame, &port_meta());
    (out.action, out.pkt)
}

// --- Raw BPF_PROG_TEST_RUN syscall (with a __sk_buff ctx) --------------------------------------

const BPF_PROG_TEST_RUN: libc::c_int = 10;
const TC_ACT_REDIRECT: u32 = 7;

/// `sizeof(struct __sk_buff)` and `offsetof(ifindex)` on this kernel's stable UAPI (uapi/linux/bpf.h:
/// `ifindex` is the 11th u32 → offset 40; the struct totals 192 bytes).
const SK_BUFF_SIZE: usize = 192;
const SKB_IFINDEX_OFF: usize = 40;

/// The `test` arm of `union bpf_attr` (uapi/linux/bpf.h). `#[repr(C)]` + explicit padding matches
/// the kernel struct layout exactly.
#[repr(C)]
#[derive(Default)]
struct BpfAttrTest {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
    _pad: u32,
}

struct TestRunOut {
    retval: u32,
    data: Vec<u8>,
}

/// Issue `bpf(BPF_PROG_TEST_RUN)` on `prog_fd` with `input` as `data_in` and a `__sk_buff` ctx whose
/// `ifindex` field is `ifindex`. Returns the kernel's return code (the tc action) + the (grown,
/// mutated) output packet.
fn bpf_prog_test_run_skb(
    prog_fd: RawFd,
    input: &[u8],
    ifindex: u32,
) -> std::io::Result<TestRunOut> {
    // Encap grows the frame by 40 bytes; size the out buffer generously so data_size_out is never
    // clipped.
    let mut out_buf = vec![0u8; input.len() + 256];
    let mut ctx_in = [0u8; SK_BUFF_SIZE];
    ctx_in[SKB_IFINDEX_OFF..SKB_IFINDEX_OFF + 4].copy_from_slice(&ifindex.to_ne_bytes());
    let mut ctx_out = [0u8; SK_BUFF_SIZE];
    let mut attr = BpfAttrTest {
        prog_fd: prog_fd as u32,
        data_in: input.as_ptr() as u64,
        data_size_in: input.len() as u32,
        data_out: out_buf.as_mut_ptr() as u64,
        data_size_out: out_buf.len() as u32,
        ctx_in: ctx_in.as_ptr() as u64,
        ctx_size_in: ctx_in.len() as u32,
        ctx_out: ctx_out.as_mut_ptr() as u64,
        ctx_size_out: ctx_out.len() as u32,
        repeat: 1,
        ..Default::default()
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_TEST_RUN,
            &mut attr as *mut BpfAttrTest as *mut libc::c_void,
            std::mem::size_of::<BpfAttrTest>() as libc::c_uint,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    out_buf.truncate(attr.data_size_out as usize);
    Ok(TestRunOut {
        retval: attr.retval,
        data: out_buf,
    })
}

// --- The anchor test --------------------------------------------------------------------------

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel tc test-run)"]
fn guest_tx_encap_redirect_inner_unchanged_matches_native_sim() {
    // 1. Build the guest frame + the native pure-core expected output for the SAME fixture.
    let frame = guest_frame();
    let (native_action, native_pkt) = native_output(&frame);
    assert_eq!(
        native_action,
        Action::Redirect(UPLINK_IFINDEX),
        "sanity: native sim encaps (tunnel-key decision) + redirects out the uplink"
    );

    // 2. Load the real eBPF object the same way the daemon does, and populate the maps tc_guest_tx
    //    reads on the v4 encap path: PORT_META (keyed by skb ifindex), ROUTES (LPM /32), LOCAL[0],
    //    FW_META/FW_RULES (egress allow). CONNTRACK is left empty (fresh bpffs) so the flow is NEW
    //    and the egress firewall is enforced — exactly as the native SimNode sees it.
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    let pin = tempfile::Builder::new()
        .prefix("flowplane-anchor-guest-tx-")
        .tempdir_in("/sys/fs/bpf")
        .expect("bpffs tempdir");
    let mut ebpf = aya::EbpfLoader::new()
        .default_map_pin_directory(pin.path())
        .load(bytes)
        .expect("load compiled eBPF object");

    {
        let mut port_meta_map: AyaHashMap<_, u32, PortMeta> =
            AyaHashMap::try_from(ebpf.map_mut("PORT_META").expect("PORT_META map")).unwrap();
        port_meta_map
            .insert(IFINDEX, port_meta(), 0)
            .expect("insert PORT_META");
    }
    {
        let mut routes: LpmTrie<_, RouteLpmData, RouteValue> =
            LpmTrie::try_from(ebpf.map_mut("ROUTES").expect("ROUTES map")).unwrap();
        // Lookup key is Key::new(64, {vni: vni.to_be_bytes(), ipv4: dst}) — a /32 host route (32 VNI
        // bits + 32 host bits), matching coreimpl::route4_get.
        routes
            .insert(
                &Key::new(
                    64,
                    RouteLpmData {
                        vni: VNI.to_be_bytes(),
                        ipv4: DEST_IP,
                    },
                ),
                route_value(),
                0,
            )
            .expect("insert ROUTES");
    }
    {
        let mut local_map: Array<_, Local> =
            Array::try_from(ebpf.map_mut("LOCAL").expect("LOCAL map")).unwrap();
        local_map.set(0, local(), 0).expect("write LOCAL[0]");
    }
    seed_classifier(&mut ebpf, IFINDEX, &[egress_allow_rule()], &[]);

    // 3. Load (verify) the tc_guest_tx classifier and get its kernel fd.
    let prog: &mut SchedClassifier = ebpf
        .program_mut("tc_guest_tx")
        .expect("tc_guest_tx program present")
        .try_into()
        .expect("tc_guest_tx is a SchedClassifier program");
    prog.load().expect("verify/load tc_guest_tx");
    let prog_fd = prog.fd().expect("tc_guest_tx fd").as_fd().as_raw_fd();

    // 4. Run the real bytecode on the guest frame via BPF_PROG_TEST_RUN with skb ifindex = IFINDEX.
    let out = bpf_prog_test_run_skb(prog_fd, &frame, IFINDEX)
        .expect("BPF_PROG_TEST_RUN on tc_guest_tx (needs CAP_BPF + kernel tc test-run support)");

    // The encap path stamps the Geneve tunnel key (bpf_skb_set_tunnel_key) and redirects to the
    // geneve device — no byte write, so data_out is the UNCHANGED inner frame and the verdict is
    // TC_ACT_REDIRECT. This is the encap-side oracle P2 Task 7 settled on (see the module doc): we
    // can no longer observe the tunnel key itself from BPF_PROG_TEST_RUN (a decap-side
    // `get_tunnel_key` on the SAME skb, later in the SAME run, would show it, but `tc_guest_tx` never
    // reads it back), so redirect + inner-unchanged is the strongest claim provable here.
    assert_eq!(
        out.retval, TC_ACT_REDIRECT,
        "native pure-core diverged from real bytecode: expected TC_ACT_REDIRECT ({TC_ACT_REDIRECT}), \
         bytecode returned action {}",
        out.retval
    );

    // Primary anchor: the real bytecode must not write ANY outer bytes on the encap path anymore —
    // its output is byte-identical to both the native sim's (also-unchanged) output and the original
    // input frame.
    assert_eq!(
        out.data, native_pkt,
        "native pure-core diverged from real bytecode: tc_guest_tx must leave the packet UNCHANGED \
         on the encap path (the kernel geneve device builds the outer header, not this program)"
    );
    assert_eq!(
        out.data, frame,
        "tc_guest_tx must not mutate the inner frame on the encap arm"
    );
}

// --- The firewall classifier and the conntrack epoch in real bytecode --------------------------

const TC_ACT_SHOT: u32 = 2;
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;
const ICMP6: u8 = 58;
const ANY_PORT: (u16, u16) = (0, 65535);
const NO_ICMP: u16 = 0xffff;
const GUEST_IP6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20];

fn prefix_mask<const N: usize>(len: u8) -> [u8; N] {
    let mut m = [0u8; N];
    for i in 0..len as usize {
        m[i / 8] |= 0x80 >> (i % 8);
    }
    m
}

/// An egress rule toward the peer `dst/len`. `proto` 0 is any protocol; `ports` is the destination
/// port range (TCP/UDP); `icmp` is the ICMP type (ICMP only).
fn rule4(dst: [u8; 4], len: u8, proto: u8, ports: (u16, u16), icmp: u16, allow: bool) -> FwRule {
    FwRule {
        dst_ip: dst,
        dst_mask: prefix_mask(len),
        src_port_max: 65535,
        dst_port_min: ports.0,
        dst_port_max: ports.1,
        icmp_type: icmp,
        icmp_code: NO_ICMP,
        proto,
        action: if allow { FW_ACTION_ACCEPT } else { FW_ACTION_DROP },
        direction: FW_DIR_EGRESS,
        enabled: 1,
        ..Default::default()
    }
}

fn rule6(dst: [u8; 16], len: u8, proto: u8, ports: (u16, u16), icmp: u16, allow: bool) -> FwRule6 {
    FwRule6 {
        dst_ip: dst,
        dst_mask: prefix_mask(len),
        src_port_max: 65535,
        dst_port_min: ports.0,
        dst_port_max: ports.1,
        icmp_type: icmp,
        icmp_code: NO_ICMP,
        proto,
        action: if allow { FW_ACTION_ACCEPT } else { FW_ACTION_DROP },
        direction: FW_DIR_EGRESS,
        enabled: 1,
        ..Default::default()
    }
}

/// First match wins, in this order. Chosen so every classifier mechanism decides some case: a
/// narrow deny above a wider allow (per-class shadowing of the expansion), a port range (masked
/// prefixes, both edges), a class-0 rule above a class's later deny (the two-probe arbitration),
/// and a /8 port rule behind a /16 deny-any.
fn rules4() -> Vec<FwRule> {
    vec![
        rule4([10, 1, 1, 0], 24, TCP, (22, 22), NO_ICMP, false),
        rule4([10, 1, 0, 0], 16, TCP, ANY_PORT, NO_ICMP, true),
        rule4([10, 2, 0, 0], 16, UDP, (8000, 8100), NO_ICMP, true),
        rule4([0; 4], 0, ICMP, ANY_PORT, 8, true),
        rule4([10, 3, 0, 0], 16, 0, ANY_PORT, NO_ICMP, false),
        rule4([10, 0, 0, 0], 8, TCP, (443, 443), NO_ICMP, true),
    ]
}

const NET6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fn v6(net: [u8; 16], sub: u8, host: u8) -> [u8; 16] {
    let mut a = net;
    a[5] = sub;
    a[15] = host;
    a
}

fn rules6() -> Vec<FwRule6> {
    vec![
        rule6(v6(NET6, 1, 0), 64, TCP, (22, 22), NO_ICMP, false),
        rule6(NET6, 32, TCP, ANY_PORT, NO_ICMP, true),
        rule6([0; 16], 0, ICMP6, ANY_PORT, 128, true),
    ]
}

#[derive(Clone, Copy, Debug)]
enum L4 {
    Tcp(u16),
    Udp(u16),
    Echo(u8),
}

/// A guest frame from the guest to `dst`: a TCP SYN / UDP datagram from `sport`, or an ICMP message
/// of type `t` (8/0 on v4, 128/129 on v6) with id `sport`.
fn frame4(dst: [u8; 4], l4: L4, sport: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let b = PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6]).ipv4(GUEST_IP, dst, 64);
    let mut f = Vec::new();
    match l4 {
        L4::Tcp(p) => b.tcp(sport, p, 1, 1024).syn().write(&mut f, &[]),
        L4::Udp(p) => b.udp(sport, p).write(&mut f, &[]),
        L4::Echo(8) => b.icmpv4_echo_request(sport, 1).write(&mut f, &[]),
        L4::Echo(_) => b.icmpv4_echo_reply(sport, 1).write(&mut f, &[]),
    }
    .unwrap();
    f
}

fn frame6(dst: [u8; 16], l4: L4, sport: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let b = PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6]).ipv6(GUEST_IP6, dst, 64);
    let mut f = Vec::new();
    match l4 {
        L4::Tcp(p) => b.tcp(sport, p, 1, 1024).syn().write(&mut f, &[]),
        L4::Udp(p) => b.udp(sport, p).write(&mut f, &[]),
        L4::Echo(128) => b.icmpv6_echo_request(sport, 1).write(&mut f, &[]),
        L4::Echo(_) => b.icmpv6_echo_reply(sport, 1).write(&mut f, &[]),
    }
    .unwrap();
    f
}

fn port_meta6() -> PortMeta {
    PortMeta {
        guest_ipv6: GUEST_IP6,
        ..port_meta()
    }
}

/// The real object with the maps the encap path reads, the given rules compiled into the classifier
/// on `IFINDEX`, a host route to every destination, and both guest-egress programs loaded. The
/// native twin gets the same rules (as the legacy seeds its classifier state derives from) and
/// routes.
struct Rig {
    ebpf: aya::Ebpf,
    _pin: tempfile::TempDir,
    fd4: RawFd,
    fd6: RawFd,
    sim: SimNode,
}

impl Rig {
    fn new(rules: &[FwRule], rules6: &[FwRule6], dsts: &[[u8; 4]], dsts6: &[[u8; 16]]) -> Self {
        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
        let pin = tempfile::Builder::new()
            .prefix("flowplane-anchor-fw-")
            .tempdir_in("/sys/fs/bpf")
            .expect("bpffs tempdir");
        let mut ebpf = aya::EbpfLoader::new()
            .default_map_pin_directory(pin.path())
            .load(bytes)
            .expect("load compiled eBPF object");
        let mut sim = SimNode::new();
        sim.src_ifindex = IFINDEX;
        sim.maps.local = Some(local());
        {
            let mut m: AyaHashMap<_, u32, PortMeta> =
                AyaHashMap::try_from(ebpf.map_mut("PORT_META").unwrap()).unwrap();
            m.insert(IFINDEX, port_meta6(), 0).unwrap();
        }
        {
            let mut r: LpmTrie<_, RouteLpmData, RouteValue> =
                LpmTrie::try_from(ebpf.map_mut("ROUTES").unwrap()).unwrap();
            for d in dsts {
                let k = RouteLpmData {
                    vni: VNI.to_be_bytes(),
                    ipv4: *d,
                };
                r.insert(&Key::new(64, k), route_value(), 0).unwrap();
                sim.maps.add_route4(VNI, *d, route_value());
            }
        }
        {
            let mut r: LpmTrie<_, RouteLpmData6, RouteValue> =
                LpmTrie::try_from(ebpf.map_mut("ROUTES6").unwrap()).unwrap();
            for d in dsts6 {
                let k = RouteLpmData6 {
                    vni: VNI.to_be_bytes(),
                    ipv6: *d,
                };
                r.insert(&Key::new(160, k), route_value(), 0).unwrap();
                sim.maps.add_route6(VNI, *d, route_value());
            }
        }
        {
            let mut l: Array<_, Local> = Array::try_from(ebpf.map_mut("LOCAL").unwrap()).unwrap();
            l.set(0, local(), 0).unwrap();
        }
        seed_classifier(&mut ebpf, IFINDEX, rules, rules6);
        let count = |dir| rules.iter().filter(|r| r.direction == dir).count() as u32;
        sim.maps.fw_meta.insert(
            IFINDEX,
            FwMeta {
                ingress_count: 0,
                egress_count: count(FW_DIR_EGRESS),
            },
        );
        for (i, r) in rules.iter().enumerate() {
            sim.maps.fw_rules.insert((IFINDEX, i as u32), *r);
        }
        sim.maps.fw_meta6.insert(
            IFINDEX,
            FwMeta {
                ingress_count: 0,
                egress_count: rules6.len() as u32,
            },
        );
        for (i, r) in rules6.iter().enumerate() {
            sim.maps.fw_rules6.insert((IFINDEX, i as u32), *r);
        }
        let mut fd = |name: &str| {
            let prog: &mut SchedClassifier =
                ebpf.program_mut(name).unwrap().try_into().unwrap();
            prog.load().unwrap_or_else(|e| panic!("verify/load {name}: {e}"));
            prog.fd().unwrap().as_fd().as_raw_fd()
        };
        let (fd4, fd6) = (fd("tc_guest_tx"), fd("tc_guest_egress_v6"));
        Rig {
            ebpf,
            _pin: pin,
            fd4,
            fd6,
            sim,
        }
    }

    /// Run `frame` through the real program and the native twin; assert they agree (verdict and
    /// bytes) and return whether the packet was forwarded.
    fn run(&mut self, frame: &[u8], v6: bool, what: &str) -> bool {
        let (fd, native) = if v6 {
            (self.fd6, self.sim.guest_tx_v6(frame, &port_meta6()))
        } else {
            (self.fd4, self.sim.guest_tx(frame, &port_meta6()))
        };
        let out = bpf_prog_test_run_skb(fd, frame, IFINDEX).expect("BPF_PROG_TEST_RUN");
        let allowed = match out.retval {
            TC_ACT_REDIRECT => true,
            TC_ACT_SHOT => false,
            other => panic!("{what}: unexpected tc action {other}"),
        };
        let native_allowed = match native.action {
            Action::Redirect(_) => true,
            Action::Drop => false,
            other => panic!("{what}: unexpected native action {other:?}"),
        };
        assert_eq!(
            allowed, native_allowed,
            "{what}: real bytecode {} but the native sim {}",
            if allowed { "forwards" } else { "drops" },
            if native_allowed { "forwards" } else { "drops" },
        );
        if allowed {
            assert_eq!(out.data, frame, "{what}: the encap path writes no bytes");
            assert_eq!(native.pkt, frame, "{what}: native wrote bytes");
        }
        allowed
    }

    fn ct(&self, key: &CtKey) -> Option<CtEntry> {
        let m: AyaHashMap<_, CtKey, CtEntry> =
            AyaHashMap::try_from(self.ebpf.map("CONNTRACK").unwrap()).unwrap();
        m.get(key, 0).ok()
    }

    fn set_epoch(&mut self, epoch: u32) {
        let mut a: Array<_, u32> = Array::try_from(self.ebpf.map_mut("FW_EPOCH").unwrap()).unwrap();
        a.set(0, epoch, 0).unwrap();
        self.sim.maps.fw_epoch = epoch;
    }

    /// Rebind `IFINDEX` to no scopes (every rule revoked), in both the kernel and the twin.
    fn revoke_all(&mut self) {
        let mut b: AyaHashMap<_, u32, FwBind> =
            AyaHashMap::try_from(self.ebpf.map_mut("FW_BIND").unwrap()).unwrap();
        b.insert(IFINDEX, FwBind::default(), 0).unwrap();
        self.sim.maps.fw_bind.insert(IFINDEX, FwBind::default());
    }
}

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel tc test-run)"]
fn classifier_v4_verdicts_match_native_sim() {
    use L4::*;
    let cases: &[([u8; 4], L4, bool, &str)] = &[
        ([10, 1, 1, 5], Tcp(22), false, "a narrow deny outranks the wider allow"),
        ([10, 1, 1, 5], Tcp(80), true, "the wider allow, expanded into the narrow class"),
        ([10, 1, 2, 5], Tcp(22), true, "outside the narrow class"),
        ([10, 1, 1, 5], Udp(53), false, "no UDP rule covers 10.1/16"),
        ([10, 2, 0, 9], Udp(8000), true, "port range, low edge"),
        ([10, 2, 0, 9], Udp(8100), true, "port range, high edge"),
        ([10, 2, 0, 9], Udp(8101), false, "just past the range"),
        ([10, 2, 0, 9], Udp(7999), false, "just below the range"),
        ([10, 3, 0, 1], Tcp(443), false, "a /16 deny-any outranks the later /8 port allow"),
        ([10, 4, 0, 1], Tcp(443), true, "the /8 port allow"),
        ([10, 4, 0, 1], Tcp(444), false, "the /8 allow is port 443 only"),
        ([192, 168, 1, 1], Echo(8), true, "class 0 (any peer): echo request"),
        ([192, 168, 1, 1], Echo(0), false, "an echo reply is not an echo request"),
        ([10, 3, 0, 1], Echo(8), true, "the class-0 rule outranks the class's later deny"),
        ([192, 168, 1, 1], Tcp(443), false, "no rule for this peer and port"),
    ];
    let dsts: Vec<[u8; 4]> = cases.iter().map(|c| c.0).collect();
    let mut rig = Rig::new(&rules4(), &[], &dsts, &[]);
    for (i, &(dst, l4, want, what)) in cases.iter().enumerate() {
        // A fresh source port per case: every case is a NEW flow, so it meets the firewall.
        let got = rig.run(&frame4(dst, l4, 40000 + i as u16), false, what);
        assert_eq!(got, want, "{what}: {dst:?} {l4:?}");
    }
}

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel tc test-run)"]
fn classifier_v6_verdicts_match_native_sim() {
    use L4::*;
    let other = [0x20, 1, 0xd, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let cases: &[([u8; 16], L4, bool, &str)] = &[
        (v6(NET6, 1, 5), Tcp(22), false, "a narrow /64 deny outranks the /32 allow"),
        (v6(NET6, 1, 5), Tcp(80), true, "the /32 allow, expanded into the /64 class"),
        (v6(NET6, 2, 5), Tcp(22), true, "outside the /64"),
        (other, Tcp(80), false, "no rule for this peer"),
        (other, Echo(128), true, "class 0 (any peer): ICMPv6 echo request"),
        (other, Echo(129), false, "an echo reply is not an echo request"),
    ];
    let dsts: Vec<[u8; 16]> = cases.iter().map(|c| c.0).collect();
    let mut rig = Rig::new(&[], &rules6(), &[], &dsts);
    for (i, &(dst, l4, want, what)) in cases.iter().enumerate() {
        let got = rig.run(&frame6(dst, l4, 40000 + i as u16), true, what);
        assert_eq!(got, want, "{what}: {l4:?}");
    }
}

/// A TCP segment of an established guest flow toward `dst:443` (ACK set, no SYN).
fn ack4(dst: [u8; 4], sport: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let mut f = Vec::new();
    PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6])
        .ipv4(GUEST_IP, dst, 64)
        .tcp(sport, 443, 2, 1024)
        .ack(1)
        .write(&mut f, &[])
        .unwrap();
    f
}

fn ct_key(dst: [u8; 4], sport: u16) -> CtKey {
    CtKey {
        vni: VNI,
        src_ip: GUEST_IP,
        dst_ip: dst,
        src_port: sport,
        dst_port: 443,
        proto: TCP,
        _pad: [0; 3],
    }
}

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel tc test-run)"]
fn conntrack_epoch_revocation_matches_native_sim() {
    const PEER: [u8; 4] = [10, 4, 0, 1];
    let (f, g) = (50001, 50002);
    let mut rig = Rig::new(&rules4(), &[], &[PEER], &[]);

    // A new flow is stamped with the epoch it was admitted under; its reverse entry is a reply.
    assert!(rig.run(&frame4(PEER, L4::Tcp(443), f), false, "F: new, allowed"));
    let e = rig.ct(&ct_key(PEER, f)).expect("F tracked");
    assert_eq!(e.policy_epoch, 0);
    let rev = CtKey {
        src_ip: PEER,
        dst_ip: GUEST_IP,
        src_port: 443,
        dst_port: f,
        ..ct_key(PEER, f)
    };
    assert_eq!(
        rig.ct(&rev).expect("reverse pre-seeded").flags,
        CT_F_DEFAULT | CT_F_REPLY
    );

    // A bump with the policy unchanged: re-evaluated once, still allowed, re-stamped.
    rig.set_epoch(1);
    assert!(rig.run(&ack4(PEER, f), false, "F: stale, still allowed"));
    assert_eq!(rig.ct(&ct_key(PEER, f)).unwrap().policy_epoch, 1);
    assert!(rig.run(&frame4(PEER, L4::Tcp(443), g), false, "G: new, allowed"));

    // Revoked without a bump: established flows keep their verdict until the epoch moves...
    rig.revoke_all();
    assert!(rig.run(&ack4(PEER, f), false, "F: current epoch, fast path"));
    assert!(rig.run(&ack4(PEER, g), false, "G: current epoch, fast path"));
    // ...except a bare SYN, which is a new connection on a reused tuple.
    assert!(!rig.run(&frame4(PEER, L4::Tcp(443), g), false, "G: SYN meets the policy"));
    assert!(rig.ct(&ct_key(PEER, g)).is_none(), "the refused flow is forgotten");

    // The bump reaches F on its next packet, and the refusal forgets both of its entries.
    rig.set_epoch(2);
    assert!(!rig.run(&ack4(PEER, f), false, "F: stale, now refused"));
    assert!(rig.ct(&ct_key(PEER, f)).is_none(), "forward entry forgotten");
    assert!(rig.ct(&rev).is_none(), "its reply entry too");
}

