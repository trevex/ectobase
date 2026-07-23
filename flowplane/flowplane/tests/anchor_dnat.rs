//! BPF_PROG_TEST_RUN byte-parity anchor for the return-path (reverse) DNAT datapath: the
//! `uplink_rx` conntrack rewrite-apply (`ct_apply`) that was extracted into `flowplane-core`
//! (`conntrack::ct_apply`).
//!
//! A previously-SNAT'd guest flow's REPLY returns from the external peer, encapped IP-in-IPv6 to the
//! owning hypervisor. The egress SNAT (`snat_egress`) had installed a peer-independent reverse
//! conntrack entry `(vni,0,nat_ip,0,nat_port)` carrying `CT_REWRITE_DST` + the guest's original
//! `(xlate_ip, xlate_port)`. On the return, `uplink_rx` looks that entry up (zeroing the external
//! src ip+port because the inner dst is a registered nat_ip), applies the reverse-DNAT — inner dst IP
//! nat_ip -> guest, dst L4 port nat_port -> orig sport, + IP/L4 checksums — decaps, and delivers to
//! the guest tap.
//!
//! # Two independent checks (the second breaks a circularity)
//!
//! 1. `dnat_return_bytecode_matches_native_sim` — loads the REAL compiled `uplink_rx`, runs it on a
//!    crafted encapped reply via `BPF_PROG_TEST_RUN`, and asserts the kernel output equals the native
//!    `flowplane-sim` `SimNode::uplink_nat_return` for the same input + map state. Because the
//!    extraction made BOTH the production `uplink_rx` and `SimNode::uplink_nat_return` call the SAME
//!    `flowplane_core::conntrack::ct_apply`, this cross-check alone would NOT catch a source-level
//!    behavior change introduced by the extraction — it would change both sides identically.
//!
//! 2. `dnat_return_bytecode_matches_original_golden` — asserts the CURRENT compiled bytecode output
//!    equals hardcoded GOLDEN bytes captured from the ORIGINAL, PRE-extraction inline-eBPF program
//!    (HEAD `0f0ec06`, before `flowplane_core::conntrack::ct_apply` existed — `uplink_rx` ran its own
//!    inline phase1-read / phase3-write `ct_apply`) via `BPF_PROG_TEST_RUN` on the identical fixtures.
//!    This is INDEPENDENT of `SimNode` and so proves the rewired core is byte-faithful to the deleted
//!    inline impl. It covers the DNAT branches the inline path had: TCP (addr + port + L4 csum), UDP
//!    (addr + port + non-zero-csum fold), and ICMP (id + icmp csum).
//!
//! Residual limitation: the goldens pin the byte output for the SPECIFIC map state below (one seeded
//! reverse CT entry + the fixed UNDERLAY/NAT_IPS/firewall config). They are a faithful anchor to the
//! original for THESE vectors, not an exhaustive proof over all inputs. Together with check (1) and a
//! line-by-line source review they give strong coverage of the extraction.
//!
//! Privileged: needs CAP_BPF + a kernel that supports XDP test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::{Array, HashMap as AyaHashMap};
use aya::programs::Xdp;
use aya::{Ebpf, EbpfLoader};
use flowplane_common::{
    CtEntry, CtKey, FwMeta, FwRule, FwRuleKey, Local, UnderlayValue, VipKey, CT_F_SRC_NAT,
    CT_REWRITE_DST, FW_ACTION_ACCEPT, FW_DIR_INGRESS,
};
use flowplane_core::encap::{EncapParams, ETH_LEN, IPV6_LEN};
use flowplane_core::pkt::Action;
use flowplane_sim::SimNode;

// --- Return-path DNAT fixture ----------------------------------------------------------------

const VNI: u32 = 100;
const TAP: u32 = 42;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const GUEST_IP: [u8; 4] = [10, 0, 0, 10]; // the guest's overlay IPv4 (reverse-DNAT target)
const NAT_IP: [u8; 4] = [198, 51, 100, 7]; // the guest's public NAT IPv4 (inner dst on the return)
const EXT_IP: [u8; 4] = [203, 0, 113, 9]; // the external peer (inner src on the return)
const ORIG_SPORT: u16 = 40000; // the guest's original L4 sport (restored on the return)
const NAT_PORT: u16 = 20018; // the allocated NAT port (inner dst port on the return)
const EXT_PORT: u16 = 443; // the external peer's port (inner src port on the return)
const EDGE_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
const HOST_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// A full guest Ethernet frame `[Eth][IPv4][TCP]` for the RETURN packet: `EXT_IP:EXT_PORT` ->
/// `NAT_IP:NAT_PORT` (the packet as it arrives from the peer, before reverse-DNAT).
fn tcp_return_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(EXT_IP, NAT_IP, 64)
        .tcp(EXT_PORT, NAT_PORT, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

/// UDP return with a non-zero payload (so the UDP checksum is non-zero and gets folded).
fn udp_return_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(EXT_IP, NAT_IP, 64)
        .udp(EXT_PORT, NAT_PORT);
    let mut out = Vec::new();
    builder.write(&mut out, &[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
    out
}

/// ICMP echo REPLY return — identifier == NAT_PORT so `l4_ports` returns `(NAT_PORT, NAT_PORT)`; the
/// reverse-DNAT restores the ICMP id to ORIG_SPORT (+folds the ICMP checksum), like the inline path.
fn icmp_return_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(EXT_IP, NAT_IP, 64)
        .icmpv4_echo_reply(NAT_PORT, 1);
    let mut out = Vec::new();
    builder.write(&mut out, &[0xde, 0xad, 0xbe, 0xef]).unwrap();
    out
}

fn encap_params() -> EncapParams {
    EncapParams {
        gateway_mac: [1; 6],
        uplink_mac: [2; 6],
        uplink_ifindex: 7,
        src_underlay: EDGE_UNDERLAY,
        nexthop_ipv6: HOST_UNDERLAY,
        inner_proto: 4, // IPPROTO_IPIP
        flow_label: 0,
    }
}

/// The peer-independent reverse conntrack entry the egress SNAT allocator stored:
/// key `(vni, 0, nat_ip, 0, nat_port, proto)` -> `CT_REWRITE_DST` with `xlate_ip=guest`,
/// `xlate_port=orig_sport`.
fn reverse_ct_key(proto: u8) -> CtKey {
    CtKey {
        vni: VNI,
        src_ip: [0; 4],
        dst_ip: NAT_IP,
        src_port: 0,
        dst_port: NAT_PORT,
        proto,
        _pad: [0; 3],
    }
}

fn reverse_ct_entry() -> CtEntry {
    CtEntry {
        last_seen: 0,
        xlate_ip: GUEST_IP,
        xlate_port: ORIG_SPORT,
        flags: CT_REWRITE_DST | CT_F_SRC_NAT,
        tcp_state: 0,
        fwall_action: 0,
        gen_bytes: [0; 4],
        _pad: [0; 3],
    }
}

/// An ingress ALLOW rule on TAP admitting the post-DNAT return flow (proto, `EXT_IP:* -> GUEST_IP:*`).
/// The datapath firewall runs on the post-DNAT 5-tuple after the return is not in the forward CT.
fn allow_rule(proto: u8) -> FwRule {
    FwRule {
        src_ip: [0; 4],
        src_mask: [0; 4],
        dst_ip: GUEST_IP,
        dst_mask: [255, 255, 255, 255],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: 0,
        dst_port_max: 65535,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_INGRESS,
        enabled: 1,
    }
}

/// Build the encapped return input + the native (pure-core) expected `SimOut` for it. The native side
/// seeds the identical reverse CT entry + NAT_IPS registration the eBPF maps get.
fn build_input_and_native(frame: &[u8], proto: u8) -> (Vec<u8>, Action, Vec<u8>) {
    let encapped = SimNode::new().edge_encap(frame, encap_params());
    // Outer IPv6 dst must be the host underlay (uplink_rx keys UNDERLAY on it).
    assert_eq!(&encapped[ETH_LEN + 24..ETH_LEN + 40], &HOST_UNDERLAY);

    let mut host = SimNode::new();
    host.maps
        .conntrack
        .insert(reverse_ct_key(proto), reverse_ct_entry());
    host.maps.nat_ips.insert((VNI, NAT_IP));
    let u = UnderlayValue {
        vni: VNI,
        tap_ifindex: TAP,
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
    };
    let out = host.uplink_nat_return(&encapped, VNI, u, GUEST_MAC);
    (encapped, out.action, out.pkt)
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
    // Decap shrinks the frame (strips 40 bytes); size the out buffer generously so it is never clipped.
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

/// Load the compiled object, populate every map `uplink_rx` reads on the NAT-return path:
/// UNDERLAY[host_underlay] (base tap), CONNTRACK (the seeded reverse CT_REWRITE_DST entry), NAT_IPS
/// (nat_ip registration for peer-independent demux), FW_META/FW_RULES (ingress allow on the post-DNAT
/// flow), LOCAL. Returns the loaded `Ebpf` (kept alive by the caller) and the verified `uplink_rx` fd.
fn load_prog(proto: u8) -> (Ebpf, RawFd) {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    let pin = Box::leak(Box::new(
        tempfile::Builder::new()
            .prefix("flowplane-anchor-dnat-")
            .tempdir_in("/sys/fs/bpf")
            .expect("bpffs tempdir"),
    ));
    let mut ebpf = EbpfLoader::new()
        .map_pin_path(pin.path())
        .load(bytes)
        .expect("load compiled eBPF object");

    {
        let mut underlay: AyaHashMap<_, [u8; 16], UnderlayValue> =
            AyaHashMap::try_from(ebpf.map_mut("UNDERLAY").expect("UNDERLAY map")).unwrap();
        underlay
            .insert(
                HOST_UNDERLAY,
                UnderlayValue {
                    vni: VNI,
                    tap_ifindex: TAP,
                    guest_mac: GUEST_MAC,
                    _pad: [0; 2],
                },
                0,
            )
            .expect("insert UNDERLAY");
    }
    {
        let mut ct: AyaHashMap<_, CtKey, CtEntry> =
            AyaHashMap::try_from(ebpf.map_mut("CONNTRACK").expect("CONNTRACK map")).unwrap();
        ct.insert(reverse_ct_key(proto), reverse_ct_entry(), 0)
            .expect("seed reverse CT_REWRITE_DST entry");
    }
    {
        let mut nat_ips: AyaHashMap<_, VipKey, u8> =
            AyaHashMap::try_from(ebpf.map_mut("NAT_IPS").expect("NAT_IPS map")).unwrap();
        nat_ips
            .insert(
                VipKey {
                    vni: VNI,
                    ipv4: NAT_IP,
                },
                1,
                0,
            )
            .expect("register NAT_IP");
    }
    {
        let mut fw_meta: AyaHashMap<_, u32, FwMeta> =
            AyaHashMap::try_from(ebpf.map_mut("FW_META").expect("FW_META map")).unwrap();
        fw_meta
            .insert(
                TAP,
                FwMeta {
                    ingress_count: 1,
                    egress_count: 0,
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
                    ifindex: TAP,
                    idx: 0,
                },
                allow_rule(proto),
                0,
            )
            .expect("insert FW_RULES");
    }
    {
        let mut local: Array<_, Local> =
            Array::try_from(ebpf.map_mut("LOCAL").expect("LOCAL map")).unwrap();
        local
            .set(
                0,
                Local {
                    uplink_ifindex: 7,
                    uplink_mac: [2; 6],
                    gateway_mac: [1; 6],
                    underlay_ipv6: HOST_UNDERLAY,
                },
                0,
            )
            .expect("write LOCAL[0]");
    }

    let prog: &mut Xdp = ebpf
        .program_mut("uplink_rx")
        .expect("uplink_rx program present")
        .try_into()
        .expect("uplink_rx is an XDP program");
    prog.load().expect("verify/load uplink_rx");
    let prog_fd = prog.fd().expect("uplink_rx fd").as_fd().as_raw_fd();
    (ebpf, prog_fd)
}

// --- The anchor tests -----------------------------------------------------------------------

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel)"]
fn dnat_return_bytecode_matches_native_sim() {
    // 1. Build the encapped return input + the native pure-core expected output for the TCP fixture.
    let frame = tcp_return_frame();
    let (encapped, native_action, native_pkt) = build_input_and_native(&frame, IPPROTO_TCP);
    assert_eq!(
        native_action,
        Action::Redirect(TAP),
        "sanity: native sim reverse-DNATs + delivers the return to the guest tap"
    );
    // sanity: native reverse-DNAT rewrote the inner dst IP nat_ip -> guest (decapped: inner at ETH_LEN).
    let inner_dst = ETH_LEN + 16;
    assert_eq!(
        &native_pkt[inner_dst..inner_dst + 4],
        &GUEST_IP,
        "sanity: native reverse-DNAT rewrote inner dst IP to GUEST_IP"
    );

    // 2. Load the real bytecode + maps, run uplink_rx on the encapped return.
    let (_ebpf, prog_fd) = load_prog(IPPROTO_TCP);
    let out = bpf_prog_test_run(prog_fd, &encapped)
        .expect("BPF_PROG_TEST_RUN on uplink_rx (needs CAP_BPF + kernel test-run support)");

    assert_eq!(
        out.retval, XDP_REDIRECT,
        "native pure-core diverged from real bytecode: expected XDP_REDIRECT ({XDP_REDIRECT}), \
         bytecode returned action {}",
        out.retval
    );
    assert_eq!(
        out.data, native_pkt,
        "native pure-core diverged from real bytecode: decapped+reverse-DNAT'd output bytes differ \
         from SimNode"
    );
    assert_eq!(
        &out.data[inner_dst..inner_dst + 4],
        &GUEST_IP,
        "inner dst IP reverse-DNAT'd to GUEST_IP"
    );
    // decap strips the outer IPv6 (40B): out == input - IPV6_LEN.
    assert_eq!(
        out.data.len(),
        encapped.len() - IPV6_LEN,
        "outer IPv6 (40B) stripped from the frame"
    );
}

// --- Goldens captured from the ORIGINAL (pre-extraction) inline-eBPF uplink_rx @ 0f0ec06 -------
//
// Produced by running the ORIGINAL program (HEAD `0f0ec06`, before `flowplane_core::conntrack::
// ct_apply` existed — `uplink_rx` ran its own inline phase1-read/phase3-write `ct_apply`) via
// `BPF_PROG_TEST_RUN` on the identical fixtures + map state `load_prog` installs. Asserting the
// CURRENT bytecode reproduces these proves the extraction is byte-faithful, INDEPENDENTLY of
// `SimNode` (which now shares the extracted core with the production path). Captured by a throwaway
// copy of this test built at `0f0ec06` that dumped `out.data` for each vector.

#[rustfmt::skip]
const TCP_OUT: &[u8] = &[
    0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x2c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0xf4, 0xb8, 0xcb, 0x00, 0x71, 0x09, 0x0a, 0x00,
    0x00, 0x0a, 0x01, 0xbb, 0x9c, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00,
    0x04, 0x00, 0xc3, 0xcb, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
];
#[rustfmt::skip]
const UDP_OUT: &[u8] = &[
    0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x20, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xf4, 0xb9, 0xcb, 0x00, 0x71, 0x09, 0x0a, 0x00,
    0x00, 0x0a, 0x01, 0xbb, 0x9c, 0x40, 0x00, 0x0c, 0xa4, 0x2d, 0xaa, 0xbb, 0xcc, 0xdd,
];
#[rustfmt::skip]
const ICMP_OUT: &[u8] = &[
    0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x20, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0xf4, 0xc9, 0xcb, 0x00, 0x71, 0x09, 0x0a, 0x00,
    0x00, 0x0a, 0x00, 0x00, 0xc6, 0x20, 0x9c, 0x40, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef,
];

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel)"]
fn dnat_return_bytecode_matches_original_golden() {
    struct Vector {
        name: &'static str,
        frame: Vec<u8>,
        proto: u8,
        golden: &'static [u8],
    }
    let vectors = [
        Vector {
            name: "TCP",
            frame: tcp_return_frame(),
            proto: IPPROTO_TCP,
            golden: TCP_OUT,
        },
        Vector {
            name: "UDP",
            frame: udp_return_frame(),
            proto: IPPROTO_UDP,
            golden: UDP_OUT,
        },
        Vector {
            name: "ICMP",
            frame: icmp_return_frame(),
            proto: IPPROTO_ICMP,
            golden: ICMP_OUT,
        },
    ];

    for v in &vectors {
        let encapped = SimNode::new().edge_encap(&v.frame, encap_params());
        let (_ebpf, prog_fd) = load_prog(v.proto);
        let out = bpf_prog_test_run(prog_fd, &encapped)
            .unwrap_or_else(|e| panic!("BPF_PROG_TEST_RUN on uplink_rx [{}] failed: {e}", v.name));
        assert_eq!(
            out.retval, XDP_REDIRECT,
            "[{}] expected XDP_REDIRECT, got action {}",
            v.name, out.retval
        );
        assert_eq!(
            out.data, v.golden,
            "[{}] current bytecode output diverged from the ORIGINAL (0f0ec06) inline-eBPF golden \
             — the flowplane-core ct_apply extraction is NOT byte-faithful for this branch",
            v.name
        );
    }
}
