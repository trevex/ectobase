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
//! Privileged: needs CAP_BPF + a kernel with tc test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap as AyaHashMap};
use aya::programs::SchedClassifier;
use flowplane_common::{
    FwMeta, FwRule, FwRuleKey, Local, PortMeta, RouteLpmData, RouteValue, FW_ACTION_ACCEPT,
    FW_DIR_EGRESS,
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
        _pad: [0; 2],
        underlay_ipv6: UNDERLAY,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

fn route_value() -> RouteValue {
    // is_external:0 + no UNDERLAY entry for NEXTHOP → deliver returns Encap (no NAT rewrite), so the
    // label is computed from the unchanged inner 5-tuple.
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
        .map_pin_path(pin.path())
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
    {
        let mut fw_meta: AyaHashMap<_, u32, FwMeta> =
            AyaHashMap::try_from(ebpf.map_mut("FW_META").expect("FW_META map")).unwrap();
        fw_meta
            .insert(
                IFINDEX,
                FwMeta {
                    ingress_count: 0,
                    egress_count: 1,
                },
                0,
            )
            .expect("insert FW_META");
    }
    {
        let mut fw_rules: AyaHashMap<_, FwRuleKey, FwRule> =
            AyaHashMap::try_from(ebpf.map_mut("FW_RULES").expect("FW_RULES map")).unwrap();
        fw_rules
            .insert(
                FwRuleKey {
                    ifindex: IFINDEX,
                    idx: 0,
                },
                egress_allow_rule(),
                0,
            )
            .expect("insert FW_RULES");
    }

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
