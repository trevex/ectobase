//! BPF_PROG_TEST_RUN byte-parity anchor for the NAT64 EGRESS datapath (guest IPv6 → external IPv4
//! translation + SNAT), extracted into `flowplane-core` (`nat64::{nat64_egress_parse,
//! nat64_egress_write}`). The eBPF `nat64_egress` (reached from `guest_tx` → `v6_guest_tx`) now CALLS
//! that shared core; this anchor proves the compiled bytecode still emits the exact same bytes as the
//! ORIGINAL pre-extraction inline program.
//!
//! # Two independent checks (the second breaks a circularity)
//!
//! 1. `nat64_egress_bytecode_matches_native_sim` — loads the REAL compiled `guest_tx`, runs it on a
//!    crafted NAT64 IPv6 guest frame via `BPF_PROG_TEST_RUN`, and asserts the kernel output equals the
//!    native `flowplane-sim` `SimNode::guest_tx_nat64` for the same input + map state. Because the
//!    extraction made BOTH the production `nat64_egress` and `SimNode::guest_tx_nat64` call the SAME
//!    `flowplane_core::nat64` fns, this cross-check alone would NOT catch a source-level behavior
//!    change introduced by the extraction — it would change both sides identically.
//!
//! 2. `nat64_egress_bytecode_matches_original_golden` — asserts the CURRENT compiled bytecode output
//!    equals hardcoded GOLDEN bytes captured from the ORIGINAL, PRE-extraction inline-eBPF program
//!    (HEAD `125726e`, before `flowplane_core::nat64` existed — `nat64_egress` ran its own inline
//!    v6→v4 translation) via `BPF_PROG_TEST_RUN` on the identical fixtures. INDEPENDENT of `SimNode`.
//!    Covers TCP, UDP (non-zero-checksum fold), and ICMPv6→ICMPv4 echo.
//!
//! Residual limitation: the goldens pin the byte output for the SPECIFIC map state below. They are a
//! faithful anchor to the original for THESE vectors, not an exhaustive proof over all inputs.
//! Together with check (1) + a source review they give strong coverage of the extraction.
//!
//! Privileged: needs CAP_BPF + a kernel that supports XDP test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::{
    lpm_trie::{Key, LpmTrie},
    Array, HashMap as AyaHashMap, ProgramArray,
};
use aya::programs::{ProgramFd, Xdp};
use aya::{Ebpf, EbpfLoader};
use flowplane_common::{Local, NatKey, NatValue, PortMeta, RouteLpmData, RouteValue};
use flowplane_core::encap::{ETH_LEN, IPV6_LEN};
use flowplane_core::pkt::Action;
use flowplane_sim::SimNode;

// --- NAT64 egress fixture --------------------------------------------------------------------

const VNI: u32 = 300;
// BPF_PROG_TEST_RUN's synthetic xdp_md sets ingress_ifindex == 1; PORT_META keys on it.
const SRC_IFINDEX: u32 = 1;
const GUEST_IP: [u8; 4] = [10, 0, 0, 42];
const GUEST_IP6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
];
const NAT_IP: [u8; 4] = [198, 51, 100, 7];
const PORT_MIN: u16 = 20000;
const PORT_MAX: u16 = 20512;
const EXT_V4: [u8; 4] = [203, 0, 113, 9];
const SPORT: u16 = 40000;
const DPORT: u16 = 443;
const SELF_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
const NEXTHOP_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];
const UPLINK_IFINDEX: u32 = 7;
const UPLINK_MAC: [u8; 6] = [2; 6];
const GATEWAY_MAC: [u8; 6] = [1; 6];

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// The NAT64-embedded IPv6 dst = `64:ff9b::EXT_V4`.
fn nat64_dst() -> [u8; 16] {
    [
        0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, EXT_V4[0], EXT_V4[1], EXT_V4[2], EXT_V4[3],
    ]
}

/// `[Eth][IPv6][TCP]` guest frame `GUEST_IP6:SPORT` → `64:ff9b::EXT_V4:DPORT`.
fn tcp_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x22; 6], [0x11; 6])
        .ipv6(GUEST_IP6, nat64_dst(), 64)
        .tcp(SPORT, DPORT, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

/// `[Eth][IPv6][UDP]` guest frame (non-empty payload → non-zero UDP checksum).
fn udp_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x22; 6], [0x11; 6])
        .ipv6(GUEST_IP6, nat64_dst(), 64)
        .udp(SPORT, DPORT);
    let mut out = Vec::new();
    builder.write(&mut out, &[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
    out
}

/// `[Eth][IPv6][ICMPv6 echo request]` — id == SPORT.
fn icmpv6_echo_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x22; 6], [0x11; 6])
        .ipv6(GUEST_IP6, nat64_dst(), 64)
        .icmpv6_echo_request(SPORT, 1);
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
        guest_ipv6: GUEST_IP6,
    }
}

fn nat_value() -> NatValue {
    NatValue {
        nat_ipv4: NAT_IP,
        port_min: PORT_MIN,
        port_max: PORT_MAX,
    }
}

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

/// Build the guest input frame AND the native (pure-core) expected `SimOut` for the TCP fixture.
fn build_input_and_native() -> (Vec<u8>, Action, Vec<u8>) {
    let frame = tcp_frame();
    let mut node = SimNode::with_local(local());
    node.maps.local = Some(local());
    node.maps.nat.insert(
        NatKey {
            vni: VNI,
            ipv4: GUEST_IP,
        },
        nat_value(),
    );
    node.maps.add_route4(VNI, EXT_V4, route_value());
    let out = node.guest_tx_nat64(&frame, &port_meta());
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

fn bpf_prog_test_run(prog_fd: RawFd, input: &[u8]) -> std::io::Result<TestRunOut> {
    // NAT64 egress is net +20 bytes (-20 inner v6→v4 + 40 outer encap); size the out buffer generously.
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

/// Load the compiled object, populate every map `nat64_egress` reads (PORT_META, NAT, ROUTES,
/// LOCAL), register `guest_dhcp` in GUEST_PROGS (the verifier requires the DHCP tail-call slot to
/// resolve). Returns the loaded `Ebpf` (kept alive by the caller) and the verified `guest_tx` fd.
fn load_prog() -> (Ebpf, RawFd) {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    let pin = Box::leak(Box::new(
        tempfile::Builder::new()
            .prefix("flowplane-anchor-nat64-")
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
        m.insert(
            &Key::new(
                64,
                RouteLpmData {
                    vni: VNI.to_be_bytes(),
                    ipv4: EXT_V4,
                },
            ),
            route_value(),
            0,
        )
        .expect("insert ROUTES");
    }
    {
        let mut m: Array<_, Local> =
            Array::try_from(ebpf.map_mut("LOCAL").expect("LOCAL map")).unwrap();
        m.set(0, local(), 0).expect("write LOCAL[0]");
    }

    // guest_tx DHCP-classifies with a tail call into GUEST_PROGS[GUEST_PROG_DHCP]; the verifier
    // requires that slot to resolve, so load guest_dhcp and register it (as the daemon does).
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
fn nat64_egress_bytecode_matches_native_sim() {
    // 1. Build the guest input + the native pure-core expected output for the TCP fixture.
    let (frame, native_action, native_pkt) = build_input_and_native();
    assert_eq!(
        native_action,
        Action::Redirect(UPLINK_IFINDEX),
        "sanity: native sim translates + encaps the NAT64 flow out the uplink"
    );
    // sanity: native SNAT rewrote the inner IPv4 src to NAT_IP (decapped inner IPv4 at ETH_LEN+IPV6_LEN).
    let inner_src = ETH_LEN + IPV6_LEN + 12;
    assert_eq!(
        &native_pkt[inner_src..inner_src + 4],
        &NAT_IP,
        "sanity: native NAT64 rewrote the inner IPv4 src to NAT_IP"
    );

    // 2. Load the real bytecode + maps, run guest_tx on the NAT64 IPv6 frame.
    let (_ebpf, prog_fd) = load_prog();
    let out = bpf_prog_test_run(prog_fd, &frame)
        .expect("BPF_PROG_TEST_RUN on guest_tx (needs CAP_BPF + kernel test-run support)");

    assert_eq!(
        out.retval, XDP_REDIRECT,
        "native pure-core diverged from real bytecode: expected XDP_REDIRECT ({XDP_REDIRECT}), \
         bytecode returned action {}",
        out.retval
    );
    assert_eq!(
        out.data, native_pkt,
        "native pure-core diverged from real bytecode: translated+encapped NAT64 output bytes differ \
         from SimNode"
    );
    assert_eq!(
        &out.data[inner_src..inner_src + 4],
        &NAT_IP,
        "inner IPv4 src NAT'd to NAT_IP"
    );
    assert_eq!(
        &out.data[ETH_LEN + 24..ETH_LEN + 40],
        &NEXTHOP_UNDERLAY,
        "outer IPv6 dst = route nexthop underlay"
    );
    // NAT64 egress net size change: input (v6, 54+payload) → output (outer 54 + inner 20 + payload) =
    // input + 20 (−20 inner v6→v4, +40 outer encap).
    assert_eq!(
        out.data.len(),
        frame.len() + 20,
        "NAT64 egress is net +20 bytes"
    );
}

// --- Goldens captured from the ORIGINAL (pre-extraction) inline-eBPF nat64_egress @ 125726e ----
//
// Produced by running the ORIGINAL program (HEAD `125726e`, before `flowplane_core::nat64` existed)
// via BPF_PROG_TEST_RUN on the identical fixtures + map state `load_prog` installs, in a throwaway
// worktree. Asserting the CURRENT bytecode reproduces these proves the extraction is byte-faithful,
// INDEPENDENTLY of SimNode (which now shares the extracted core with the production path).

include!("goldens/nat64.rs");

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel)"]
fn nat64_egress_bytecode_matches_original_golden() {
    struct Vector {
        name: &'static str,
        frame: Vec<u8>,
        golden: &'static [u8],
    }
    let vectors = [
        Vector {
            name: "TCP",
            frame: tcp_frame(),
            golden: GOLDEN_TCP,
        },
        Vector {
            name: "UDP",
            frame: udp_frame(),
            golden: GOLDEN_UDP,
        },
        Vector {
            name: "ICMP",
            frame: icmpv6_echo_frame(),
            golden: GOLDEN_ICMP,
        },
    ];

    for v in &vectors {
        let (_ebpf, prog_fd) = load_prog();
        let out = bpf_prog_test_run(prog_fd, &v.frame)
            .unwrap_or_else(|e| panic!("BPF_PROG_TEST_RUN on guest_tx [{}] failed: {e}", v.name));
        assert_eq!(
            out.retval, XDP_REDIRECT,
            "[{}] expected XDP_REDIRECT, got action {}",
            v.name, out.retval
        );
        assert_eq!(
            out.data, v.golden,
            "[{}] current bytecode output diverged from the ORIGINAL (125726e) inline-eBPF golden — \
             the flowplane-core NAT64-egress extraction is NOT byte-faithful for this branch",
            v.name
        );
    }
}

// Ignore usages so unused-const lints stay quiet for the two ports referenced only in fixtures.
const _: (u8, u8) = (IPPROTO_TCP, IPPROTO_UDP);
