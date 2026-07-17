//! BPF_PROG_TEST_RUN byte-parity anchor for the guest-egress `guest_tx` SNAT datapath.
//!
//! Companion to `anchor_uplink.rs` (N-S deliver) and `anchor_lb.rs` (LB local-deliver). This one
//! anchors the guest-egress routing + network-NAT SNAT path that was extracted into `flowplane-core`
//! (`egress::route4`/`deliver` + `nat::snat_egress`): a guest sends a fresh flow to an EXTERNAL
//! destination whose route is marked `is_external`. The datapath enforces the egress firewall,
//! SNATs the inner src IP -> nat_ip and src port / ICMP id -> an allocated nat_port (+ IP/L4
//! checksums), tracks the flow, and encapsulates IP-in-IPv6 toward the underlay nexthop.
//!
//! # Two independent checks (the second breaks a circularity)
//!
//! 1. `guest_tx_snat_bytecode_matches_native_sim` — loads the REAL compiled `guest_tx`, runs it on a
//!    crafted TCP guest frame via `BPF_PROG_TEST_RUN`, and asserts the kernel output equals the
//!    native `flowplane-sim` `SimNode::guest_tx` for the same input + map state. Because the
//!    extraction made BOTH the production `guest_tx` and `SimNode::guest_tx` call the SAME
//!    `flowplane_core::nat::snat_egress`, this cross-check alone would NOT catch a source-level
//!    behavior change introduced by the extraction — it would change both sides identically.
//!
//! 2. `guest_tx_bytecode_matches_original_golden` — asserts the CURRENT compiled bytecode output
//!    equals hardcoded GOLDEN bytes captured from the ORIGINAL, PRE-extraction inline-eBPF program
//!    (`git` commit `148ea68`, before `flowplane_core::nat::snat_egress` existed) via
//!    `BPF_PROG_TEST_RUN` on the identical fixtures. This is INDEPENDENT of `SimNode` and so proves
//!    the rewired core is byte-faithful to the deleted inline impl. It covers all four SNAT branches
//!    the inline path had: TCP, UDP (incl. the non-zero-checksum fold), ICMP (id + checksum), and a
//!    TCP flow whose hash-start port slot is pre-occupied so the allocator must linear-probe. The
//!    goldens were produced by `tests/capture_golden.rs` in a scratch worktree checked out at
//!    `148ea68` (that file is NOT in the tree — it only ran against the original program).
//!
//! Residual limitation: the goldens pin the byte output for the SPECIFIC map state below (empty
//! conntrack except the seeded probe entry; the fixed NAT/route/fw config). They are a faithful
//! anchor to the original for THESE vectors, not an exhaustive proof over all inputs. Together with
//! check (1) and the source-level Part-2 review they give strong coverage of the extraction.
//!
//! Privileged: needs CAP_BPF + a kernel that supports XDP test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::{
    lpm_trie::{Key, LpmTrie},
    Array, HashMap as AyaHashMap, ProgramArray,
};
use aya::programs::{ProgramFd, Xdp};
use aya::{Ebpf, EbpfLoader};
use flowplane_common::{
    CtEntry, CtKey, FwMeta, FwRule, FwRuleKey, Local, NatKey, NatValue, PortMeta, RouteLpmData,
    RouteValue, CT_F_SRC_NAT, CT_REWRITE_DST, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
};
use flowplane_core::encap::{ETH_LEN, IPV6_LEN};
use flowplane_core::pkt::Action;
use flowplane_sim::SimNode;

// --- Guest-egress SNAT fixture ---------------------------------------------------------------

const VNI: u32 = 100;
// `BPF_PROG_TEST_RUN`'s synthetic `xdp_md` sets `ingress_ifindex == 1` (not 0), so the guest_tx
// PORT_META / FW_META / FW_RULES the datapath keys on `ingress_ifindex` must be installed under 1.
// The native sim mirrors this via `SimNode::src_ifindex = 1` for the egress-firewall key. The value
// does not affect the emitted packet bytes (route/NAT key on `meta.vni`, not the ifindex) — it only
// has to make BOTH paths take the firewall ALLOW branch on the fresh flow.
const SRC_IFINDEX: u32 = 1;
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const EXT_IP: [u8; 4] = [203, 0, 113, 9]; // external destination (is_external route)
const NAT_IP: [u8; 4] = [198, 51, 100, 7]; // the guest's public NAT IPv4
const PORT_MIN: u16 = 20000;
const PORT_MAX: u16 = 20064;
const SPORT: u16 = 40000;
const DPORT: u16 = 443;
const SELF_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
const NEXTHOP_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];
const UPLINK_IFINDEX: u32 = 7;
const UPLINK_MAC: [u8; 6] = [2; 6];
const GATEWAY_MAC: [u8; 6] = [1; 6];

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// A full guest Ethernet frame `[Eth][IPv4][TCP]` from `GUEST_IP:SPORT` -> `EXT_IP:DPORT`.
fn tcp_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(GUEST_IP, EXT_IP, 64)
        .tcp(SPORT, DPORT, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

/// `[Eth][IPv4][UDP]` with a non-zero payload (so the UDP checksum is non-zero and gets folded).
fn udp_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(GUEST_IP, EXT_IP, 64)
        .udp(SPORT, DPORT);
    let mut out = Vec::new();
    builder.write(&mut out, &[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
    out
}

/// `[Eth][IPv4][ICMP echo]` — identifier == SPORT so `l4_ports` returns `(SPORT, SPORT)` and the
/// SNAT rewrites the ICMP id to nat_port (+folds the ICMP checksum), mirroring the inline path.
fn icmp_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(GUEST_IP, EXT_IP, 64)
        .icmpv4_echo_request(SPORT, 1);
    let mut out = Vec::new();
    builder.write(&mut out, &[0xde, 0xad, 0xbe, 0xef]).unwrap();
    out
}

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: [0x22; 6],
        _pad: [0; 2],
        underlay_ipv6: SELF_UNDERLAY,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

fn nat_value() -> NatValue {
    NatValue {
        nat_ipv4: NAT_IP,
        port_min: PORT_MIN,
        port_max: PORT_MAX,
    }
}

/// External route for EXT_IP in VNI (is_external=1, nexthop = NEXTHOP_UNDERLAY).
fn route_value() -> RouteValue {
    RouteValue {
        nexthop_vni: VNI,
        nexthop_ipv6: NEXTHOP_UNDERLAY,
        is_external: 1,
        _pad: [0; 3],
    }
}

fn local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: UPLINK_MAC,
        gateway_mac: GATEWAY_MAC,
        underlay_ipv6: SELF_UNDERLAY,
    }
}

/// An egress ALLOW rule on SRC_IFINDEX for `proto`, `GUEST_IP:* -> EXT_IP:*`. Ports are wide-open so
/// the same rule shape admits TCP/UDP/ICMP (ICMP uses id, not port; the rule's icmp fields are
/// wildcarded). The golden vectors install this per-proto; the SimNode cross-check uses TCP/DPORT.
fn allow_rule(proto: u8, dst_port_min: u16, dst_port_max: u16) -> FwRule {
    FwRule {
        src_ip: GUEST_IP,
        src_mask: [255, 255, 255, 255],
        dst_ip: EXT_IP,
        dst_mask: [255, 255, 255, 255],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min,
        dst_port_max,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_EGRESS,
        enabled: 1,
    }
}

/// Build the guest input frame AND the native (pure-core) expected `SimOut` for the TCP fixture. The
/// native side installs the identical NAT config + route + firewall rule the eBPF maps get.
fn build_input_and_native() -> (Vec<u8>, Action, Vec<u8>) {
    let frame = tcp_frame();

    let mut node = SimNode::with_local(local());
    node.src_ifindex = SRC_IFINDEX;
    node.maps.local = Some(local());
    node.maps.nat.insert(
        NatKey {
            vni: VNI,
            ipv4: GUEST_IP,
        },
        nat_value(),
    );
    node.maps.add_route4(VNI, EXT_IP, route_value());
    // No UNDERLAY[NEXTHOP] entry -> deliver() takes the Encap branch (external egress).
    node.maps.fw_meta.insert(
        SRC_IFINDEX,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps
        .fw_rules
        .insert((SRC_IFINDEX, 0), allow_rule(IPPROTO_TCP, DPORT, DPORT));

    let out = node.guest_tx(&frame, &port_meta());
    (frame, out.action, out.pkt)
}

// --- Raw BPF_PROG_TEST_RUN syscall ----------------------------------------------------------

const BPF_PROG_TEST_RUN: libc::c_int = 10;
const XDP_REDIRECT: u32 = 4;

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

/// Issue `bpf(BPF_PROG_TEST_RUN)` on `prog_fd` with `input` as `data_in`. Returns the kernel's
/// return code (the XDP action) + the (possibly resized/mutated) output packet buffer.
fn bpf_prog_test_run(prog_fd: RawFd, input: &[u8]) -> std::io::Result<TestRunOut> {
    // The encap path GROWS the frame by 40 bytes (adjust_head(-40)); size the out buffer generously.
    let mut out_buf = vec![0u8; input.len() + 256];
    let mut attr = BpfAttrTest {
        prog_fd: prog_fd as u32,
        data_in: input.as_ptr() as u64,
        data_size_in: input.len() as u32,
        data_out: out_buf.as_mut_ptr() as u64,
        data_size_out: out_buf.len() as u32,
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

// --- Shared eBPF load + map population -------------------------------------------------------

/// Load the compiled object, populate every map `guest_tx` reads for the egress SNAT fixture
/// (PORT_META, NAT, ROUTES, FW_META/FW_RULES, LOCAL), register `guest_dhcp` in GUEST_PROGS (the
/// verifier requires the tail-call slot to resolve), and — if `probe_seed` is set — pre-occupy the
/// reverse conntrack key at the FIRST candidate port so the allocator must linear-probe past it.
///
/// Returns the loaded `Ebpf` (kept alive by the caller) and the verified `guest_tx` fd.
fn load_prog(proto: u8, dst_port_min: u16, dst_port_max: u16, probe_seed: bool) -> (Ebpf, RawFd) {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    // Leak the pin dir: it must outlive the maps for the whole test; dropping it mid-run would
    // unlink the pinned maps. One tempdir per load; the OS reclaims /sys/fs/bpf on unmount.
    let pin = Box::leak(Box::new(
        tempfile::Builder::new()
            .prefix("flowplane-anchor-guest-tx-")
            .tempdir_in("/sys/fs/bpf")
            .expect("bpffs tempdir"),
    ));
    let mut ebpf = EbpfLoader::new()
        .map_pin_path(pin.path())
        .load(bytes)
        .expect("load compiled eBPF object");

    {
        let mut m: AyaHashMap<_, u32, PortMeta> =
            AyaHashMap::try_from(ebpf.map_mut("PORT_META").expect("PORT_META map")).unwrap();
        m.insert(SRC_IFINDEX, port_meta(), 0)
            .expect("insert PORT_META");
    }
    {
        let mut m: AyaHashMap<_, NatKey, NatValue> =
            AyaHashMap::try_from(ebpf.map_mut("NAT").expect("NAT map")).unwrap();
        m.insert(
            NatKey {
                vni: VNI,
                ipv4: GUEST_IP,
            },
            nat_value(),
            0,
        )
        .expect("insert NAT");
    }
    {
        let mut m: LpmTrie<_, RouteLpmData, RouteValue> =
            LpmTrie::try_from(ebpf.map_mut("ROUTES").expect("ROUTES map")).unwrap();
        // prefix_len 64 = 32 VNI bits + 32 host bits (full /32 route), matching the datapath lookup.
        m.insert(
            &Key::new(
                64,
                RouteLpmData {
                    vni: VNI.to_be_bytes(),
                    ipv4: EXT_IP,
                },
            ),
            route_value(),
            0,
        )
        .expect("insert ROUTES");
    }
    {
        let mut m: AyaHashMap<_, u32, FwMeta> =
            AyaHashMap::try_from(ebpf.map_mut("FW_META").expect("FW_META map")).unwrap();
        m.insert(
            SRC_IFINDEX,
            FwMeta {
                ingress_count: 0,
                egress_count: 1,
            },
            0,
        )
        .expect("insert FW_META");
    }
    {
        let mut m: AyaHashMap<_, FwRuleKey, FwRule> =
            AyaHashMap::try_from(ebpf.map_mut("FW_RULES").expect("FW_RULES map")).unwrap();
        m.insert(
            FwRuleKey {
                ifindex: SRC_IFINDEX,
                idx: 0,
            },
            allow_rule(proto, dst_port_min, dst_port_max),
            0,
        )
        .expect("insert FW_RULES");
    }
    {
        let mut m: Array<_, Local> =
            Array::try_from(ebpf.map_mut("LOCAL").expect("LOCAL map")).unwrap();
        m.set(0, local(), 0).expect("write LOCAL[0]");
    }
    if probe_seed {
        // Pre-occupy the reverse key at the FIRST candidate (hash-start slot) so `snat_egress` must
        // linear-probe to start+1. `hash5` is the shared pure fn (identical since 148ea68), so this
        // matches the datapath's own start-slot computation.
        let start = (flowplane_core::parse::hash5(&GUEST_IP, &EXT_IP, SPORT, DPORT, proto)
            % (PORT_MAX - PORT_MIN) as u32) as u16;
        let first_cand = PORT_MIN.wrapping_add(start);
        let mut m: AyaHashMap<_, CtKey, CtEntry> =
            AyaHashMap::try_from(ebpf.map_mut("CONNTRACK").expect("CONNTRACK map")).unwrap();
        m.insert(
            CtKey {
                vni: VNI,
                src_ip: [0; 4],
                dst_ip: NAT_IP,
                src_port: 0,
                dst_port: first_cand,
                proto,
                _pad: [0; 3],
            },
            CtEntry {
                last_seen: 0,
                xlate_ip: [9, 9, 9, 9],
                xlate_port: 1,
                flags: CT_REWRITE_DST | CT_F_SRC_NAT,
                tcp_state: 0,
                fwall_action: 0,
                _pad: [0; 7],
            },
            0,
        )
        .expect("seed probe-collision reverse key");
    }

    // `guest_tx` DHCP-classifies with a tail call into GUEST_PROGS[GUEST_PROG_DHCP]; the verifier
    // requires that slot to resolve, so load `guest_dhcp` and register it — exactly what the daemon's
    // `loader::register_guest_dhcp` does at startup. GUEST_PROGS is leaked so its fd stays open.
    {
        let prog: &mut Xdp = ebpf
            .program_mut("guest_dhcp")
            .expect("guest_dhcp program present")
            .try_into()
            .expect("guest_dhcp is an XDP program");
        prog.load().expect("verify/load guest_dhcp");
    }
    let guest_progs: &mut ProgramArray<_> = Box::leak(Box::new(
        ebpf.take_map("GUEST_PROGS")
            .expect("GUEST_PROGS map")
            .try_into()
            .expect("GUEST_PROGS is a ProgramArray"),
    ));
    {
        let dhcp: &Xdp = ebpf
            .program("guest_dhcp")
            .expect("guest_dhcp program present")
            .try_into()
            .expect("guest_dhcp is an XDP program");
        let fd: &ProgramFd = dhcp.fd().expect("guest_dhcp fd");
        guest_progs
            .set(flowplane_common::GUEST_PROG_DHCP, fd, 0)
            .expect("register guest_dhcp in GUEST_PROGS");
    }

    let prog: &mut Xdp = ebpf
        .program_mut("guest_tx")
        .expect("guest_tx program present")
        .try_into()
        .expect("guest_tx is an XDP program");
    prog.load().expect("verify/load guest_tx");
    let prog_fd = prog.fd().expect("guest_tx fd").as_fd().as_raw_fd();
    (ebpf, prog_fd)
}

// --- The anchor tests -----------------------------------------------------------------------

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel)"]
fn guest_tx_snat_bytecode_matches_native_sim() {
    // 1. Build the guest input + the native pure-core expected output for the SAME TCP fixture.
    let (frame, native_action, native_pkt) = build_input_and_native();
    assert_eq!(
        native_action,
        Action::Redirect(UPLINK_IFINDEX),
        "sanity: native sim encaps the SNAT'd flow out the uplink"
    );
    assert_eq!(
        native_pkt.len(),
        frame.len() + IPV6_LEN,
        "sanity: native output = input + outer IPv6 (inner Ethernet consumed by the outer header)"
    );
    let inner_src = ETH_LEN + IPV6_LEN + 12;
    assert_eq!(
        &native_pkt[inner_src..inner_src + 4],
        &NAT_IP,
        "sanity: native SNAT rewrote the inner src IP to NAT_IP"
    );

    // 2. Load the real bytecode + maps, run guest_tx on the TCP frame.
    let (_ebpf, prog_fd) = load_prog(IPPROTO_TCP, DPORT, DPORT, false);
    let out = bpf_prog_test_run(prog_fd, &frame)
        .expect("BPF_PROG_TEST_RUN on guest_tx (needs CAP_BPF + kernel test-run support)");

    assert_eq!(
        out.retval, XDP_REDIRECT,
        "native pure-core diverged from real bytecode: expected XDP_REDIRECT ({XDP_REDIRECT}), \
         bytecode returned action {}",
        out.retval
    );
    // Primary cross-check: full-frame byte parity between the native sim and the real bytecode.
    assert_eq!(
        out.data, native_pkt,
        "native pure-core diverged from real bytecode: encapped+SNAT'd output bytes differ from SimNode"
    );
    // Belt-and-suspenders on the SNAT contract.
    assert_eq!(
        &out.data[inner_src..inner_src + 4],
        &NAT_IP,
        "inner src IP SNAT'd to NAT_IP"
    );
    assert_eq!(
        &out.data[ETH_LEN + 24..ETH_LEN + 40],
        &NEXTHOP_UNDERLAY,
        "outer IPv6 dst = route nexthop underlay"
    );
    assert_eq!(
        out.data.len(),
        frame.len() + IPV6_LEN,
        "outer IPv6 (40B) prepended; inner frame kept (frame + 40)"
    );
}

// --- Goldens captured from the ORIGINAL (pre-extraction) inline-eBPF guest_tx @ 148ea68 --------
//
// Produced by `tests/capture_golden.rs` in a scratch worktree checked out at commit `148ea68`
// (the commit BEFORE `flowplane_core::nat::snat_egress` existed — `guest_tx` ran its own inline
// `nat::nat_snat_egress`). Each `*_IN` is the exact input frame the fixture builders below emit; the
// `*_OUT` is that original program's `BPF_PROG_TEST_RUN` output for the map state `load_prog`
// installs. Asserting the CURRENT bytecode reproduces these proves the extraction is byte-faithful,
// INDEPENDENTLY of `SimNode` (which now shares the extracted core with the production path).

#[rustfmt::skip]
const TCP_OUT: [u8; 94] = [
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x86, 0xdd, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x28, 0x04, 0x40, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xbb, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06,
    0xd4, 0x8b, 0xc6, 0x33, 0x64, 0x07, 0xcb, 0x00, 0x71, 0x09, 0x4e, 0x32, 0x01, 0xbb, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x04, 0x00, 0xf5, 0xb2, 0x00, 0x00,
];

#[rustfmt::skip]
const UDP_OUT: [u8; 86] = [
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x86, 0xdd, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x20, 0x04, 0x40, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xbb, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
    0xd4, 0x88, 0xc6, 0x33, 0x64, 0x07, 0xcb, 0x00, 0x71, 0x09, 0x4e, 0x43, 0x01, 0xbb, 0x00, 0x0c,
    0xd1, 0xf9, 0xaa, 0xbb, 0xcc, 0xdd,
];

#[rustfmt::skip]
const ICMP_OUT: [u8; 86] = [
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x86, 0xdd, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x20, 0x04, 0x40, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xbb, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01,
    0xd4, 0x98, 0xc6, 0x33, 0x64, 0x07, 0xcb, 0x00, 0x71, 0x09, 0x08, 0x00, 0x0c, 0x32, 0x4e, 0x2f,
    0x00, 0x01, 0xde, 0xad, 0xbe, 0xef,
];

// TCP flow whose hash-start port slot (20018) is pre-occupied -> allocator linear-probes to 20019
// (src port 0x4e 0x33, TCP checksum 0xf5 0xb1). Exercises the PROBE_LIMIT loop in the original.
#[rustfmt::skip]
const TCP_PROBE_OUT: [u8; 94] = [
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x86, 0xdd, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x28, 0x04, 0x40, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xbb, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06,
    0xd4, 0x8b, 0xc6, 0x33, 0x64, 0x07, 0xcb, 0x00, 0x71, 0x09, 0x4e, 0x33, 0x01, 0xbb, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x04, 0x00, 0xf5, 0xb1, 0x00, 0x00,
];

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel)"]
fn guest_tx_bytecode_matches_original_golden() {
    // Each vector: (name, input frame, per-proto firewall rule params, probe-seed?, golden output).
    struct Vector {
        name: &'static str,
        frame: Vec<u8>,
        proto: u8,
        dport_min: u16,
        dport_max: u16,
        probe_seed: bool,
        golden: &'static [u8],
    }
    let vectors = [
        Vector {
            name: "TCP",
            frame: tcp_frame(),
            proto: IPPROTO_TCP,
            dport_min: DPORT,
            dport_max: DPORT,
            probe_seed: false,
            golden: &TCP_OUT,
        },
        Vector {
            name: "UDP",
            frame: udp_frame(),
            proto: IPPROTO_UDP,
            dport_min: DPORT,
            dport_max: DPORT,
            probe_seed: false,
            golden: &UDP_OUT,
        },
        Vector {
            // ICMP echo: dst-port fields are irrelevant (the rule wildcards icmp type/code); use a
            // wide range so the egress firewall admits it.
            name: "ICMP",
            frame: icmp_frame(),
            proto: IPPROTO_ICMP,
            dport_min: 0,
            dport_max: 65535,
            probe_seed: false,
            golden: &ICMP_OUT,
        },
        Vector {
            name: "TCP_PROBE",
            frame: tcp_frame(),
            proto: IPPROTO_TCP,
            dport_min: DPORT,
            dport_max: DPORT,
            probe_seed: true,
            golden: &TCP_PROBE_OUT,
        },
    ];

    for v in &vectors {
        let (_ebpf, prog_fd) = load_prog(v.proto, v.dport_min, v.dport_max, v.probe_seed);
        let out = bpf_prog_test_run(prog_fd, &v.frame)
            .unwrap_or_else(|e| panic!("BPF_PROG_TEST_RUN on guest_tx [{}] failed: {e}", v.name));
        assert_eq!(
            out.retval, XDP_REDIRECT,
            "[{}] expected XDP_REDIRECT, got action {}",
            v.name, out.retval
        );
        assert_eq!(
            out.data, v.golden,
            "[{}] current bytecode output diverged from the ORIGINAL (148ea68) inline-eBPF golden \
             — the flowplane-core extraction is NOT byte-faithful for this branch",
            v.name
        );
    }
}
