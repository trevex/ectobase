//! BPF_PROG_TEST_RUN byte-parity anchor for the guest-facing gateway responders (ARP + IPv6 ND) that
//! were extracted into `flowplane-core` (`arp_nd::arp_reply` / `arp_nd::nd_reply`).
//!
//! A guest sends an ARP request for the virtual gateway IPv4, or an ICMPv6 Neighbor Solicitation for
//! the gateway IPv6. The `guest_tx` datapath head rewrites the frame IN PLACE into the corresponding
//! reply (ARP reply / Neighbor Advertisement, sourced from the port's gateway MAC) and reflects it
//! back to the guest via `bpf_redirect(ingress_ifindex)` (== XDP_REDIRECT). Both replies are
//! fixed-size in-place rewrites, so every packet access is constant-offset.
//!
//! # Two independent checks (the second breaks a circularity)
//!
//! 1. `arp_nd_bytecode_matches_native_sim` — loads the REAL compiled `guest_tx`, runs it on an ARP
//!    request and an NS via `BPF_PROG_TEST_RUN`, and asserts the kernel output equals the native
//!    `flowplane-sim` `SimNode::guest_arp_nd` for the same input + `PORT_META`. Because the extraction
//!    made BOTH the production `guest_tx` and `SimNode::guest_arp_nd` call the SAME
//!    `flowplane_core::arp_nd::{arp_reply, nd_reply}`, this cross-check alone would NOT catch a
//!    source-level behavior change from the extraction — it would change both sides identically.
//!
//! 2. `arp_nd_bytecode_matches_original_golden` — asserts the CURRENT compiled bytecode output equals
//!    hardcoded GOLDEN bytes captured from the ORIGINAL, PRE-extraction program (HEAD `242e8bc`, when
//!    the responders were the inline `flowplane_common::arp_nd::try_write_{arp,nd}_reply` raw-pointer
//!    builders) via `BPF_PROG_TEST_RUN` on the identical fixtures + `PORT_META`. This is INDEPENDENT of
//!    `SimNode` and so proves the rewired core is byte-faithful to the deleted inline builders (ARP
//!    reply Ethernet+ARP swap; ND Neighbor Advertisement incl. the ICMPv6 pseudo-header checksum).
//!
//! Privileged: needs CAP_BPF + a kernel that supports XDP test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::{HashMap as AyaHashMap, ProgramArray};
use aya::programs::{ProgramFd, Xdp};
use aya::{Ebpf, EbpfLoader};
use flowplane_common::PortMeta;
use flowplane_core::pkt::Action;
use flowplane_sim::SimNode;

// --- Gateway + fixture config ----------------------------------------------------------------
//
// `BPF_PROG_TEST_RUN`'s synthetic `xdp_md` sets `ingress_ifindex == 1`, so `guest_tx` keys PORT_META
// on 1 AND `reflect` redirects to ifindex 1 (== the anchor's expected `Redirect(1)`).
const SRC_IFINDEX: u32 = 1;
const VNI: u32 = 100;
const GATEWAY_IPV4: [u8; 4] = [10, 0, 0, 1];
const GATEWAY_IPV6: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]; // GW_MAC / guest_mac in PORT_META
const REQUESTER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc];
const REQUESTER_IPV4: [u8; 4] = [10, 0, 0, 42];
const REQUESTER_IPV6: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42];

const ETH_LEN: usize = 14;
const IPV6_LEN: usize = 40;
const ARP_LEN: usize = 28;
const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_ICMPV6: u8 = 58;

/// PORT_META for the guest port: gateway IPv4/IPv6 the responders answer for; `guest_mac` is the reply
/// MAC (the datapath answers ARP/ND with the guest's own MAC, presenting a per-port virtual gateway).
fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: REQUESTER_IPV4,
        gateway_ipv4: GATEWAY_IPV4,
        guest_mac: GATEWAY_MAC,
        _pad: [0; 2],
        underlay_ipv6: [0; 16],
        gateway_ipv6: GATEWAY_IPV6,
        guest_ipv6: REQUESTER_IPV6,
    }
}

/// A guest ARP REQUEST `who-has GATEWAY_IPV4 tell REQUESTER_IPV4` (broadcast). Ethernet + 28-byte ARP.
fn arp_request_frame() -> Vec<u8> {
    let mut f = vec![0u8; ETH_LEN + ARP_LEN];
    f[0..6].copy_from_slice(&[0xff; 6]); // eth dst = broadcast
    f[6..12].copy_from_slice(&REQUESTER_MAC); // eth src
    f[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
    let a = ETH_LEN;
    f[a..a + 2].copy_from_slice(&1u16.to_be_bytes()); // htype = Ethernet
    f[a + 2..a + 4].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype = IPv4
    f[a + 4] = 6; // hlen
    f[a + 5] = 4; // plen
    f[a + 6..a + 8].copy_from_slice(&1u16.to_be_bytes()); // opcode = request
    f[a + 8..a + 14].copy_from_slice(&REQUESTER_MAC); // sha
    f[a + 14..a + 18].copy_from_slice(&REQUESTER_IPV4); // spa
                                                        // tha = 0 (unknown), tpa = gateway.
    f[a + 24..a + 28].copy_from_slice(&GATEWAY_IPV4); // tpa
    f
}

/// A guest ICMPv6 Neighbor Solicitation for GATEWAY_IPV6. Ethernet + 40-byte IPv6 + 32-byte ICMPv6
/// (NS header + target + target-LL-addr option), the exact fixed-size layout the responder rewrites.
fn ns_frame() -> Vec<u8> {
    let mut f = vec![0u8; ETH_LEN + IPV6_LEN + 32];
    // Ethernet: dst = solicited-node multicast MAC (irrelevant to the rewrite), src = requester.
    f[0..6].copy_from_slice(&[0x33, 0x33, 0xff, 0, 0, 0x42]);
    f[6..12].copy_from_slice(&REQUESTER_MAC);
    f[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
    let ip = ETH_LEN;
    f[ip] = 0x60; // version 6
    f[ip + 4..ip + 6].copy_from_slice(&32u16.to_be_bytes()); // payload length = 32
    f[ip + 6] = IPPROTO_ICMPV6; // next header
    f[ip + 7] = 255; // hop limit
    f[ip + 8..ip + 24].copy_from_slice(&REQUESTER_IPV6); // src = requester
                                                         // dst = solicited-node multicast (irrelevant to the rewrite); leave as the target-derived form.
    f[ip + 24..ip + 40].copy_from_slice(&[0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0x01]);
    let ic = ETH_LEN + IPV6_LEN;
    f[ic] = 135; // ICMPv6 type = Neighbor Solicitation
                 // code 0, checksum (ignored by the responder), reserved.
    f[ic + 8..ic + 24].copy_from_slice(&GATEWAY_IPV6); // target = gateway
    f[ic + 24] = 1; // option type = source LL addr
    f[ic + 25] = 1; // option len = 1 (8 bytes)
    f[ic + 26..ic + 32].copy_from_slice(&REQUESTER_MAC);
    f
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
    // ARP/ND replies are fixed-size in-place rewrites (out size == in size); size generously anyway.
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

/// Load the compiled object, install PORT_META[SRC_IFINDEX] (the gateway config the responders read),
/// register `guest_dhcp` in GUEST_PROGS (the verifier requires `guest_tx`'s DHCP tail-call slot to
/// resolve), and return the loaded `Ebpf` + the verified `guest_tx` fd.
fn load_prog() -> (Ebpf, RawFd) {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    let pin = Box::leak(Box::new(
        tempfile::Builder::new()
            .prefix("flowplane-anchor-arp-nd-")
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

    // `guest_tx` DHCP-classifies with a tail call into GUEST_PROGS[GUEST_PROG_DHCP]; the verifier
    // requires that slot to resolve, so load `guest_dhcp` and register it.
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
fn arp_nd_bytecode_matches_native_sim() {
    let meta = port_meta();
    let node = SimNode::new();

    for (name, frame) in [("ARP", arp_request_frame()), ("ND", ns_frame())] {
        // Native pure-core expected output (redirect back to the ingress ifindex == 1).
        let native = node.guest_arp_nd(&frame, &meta, SRC_IFINDEX);
        assert_eq!(
            native.action,
            Action::Redirect(SRC_IFINDEX),
            "[{name}] sanity: native sim reflects the reply back to the guest"
        );

        let (_ebpf, prog_fd) = load_prog();
        let out = bpf_prog_test_run(prog_fd, &frame)
            .unwrap_or_else(|e| panic!("BPF_PROG_TEST_RUN on guest_tx [{name}] failed: {e}"));
        assert_eq!(
            out.retval, XDP_REDIRECT,
            "[{name}] native pure-core diverged from real bytecode: expected XDP_REDIRECT, got {}",
            out.retval
        );
        assert_eq!(
            out.data, native.pkt,
            "[{name}] native pure-core diverged from real bytecode: reply bytes differ from SimNode"
        );
    }
}

// --- Goldens captured from the ORIGINAL (pre-extraction) inline-eBPF guest_tx @ 242e8bc --------
//
// Produced by running the ORIGINAL program (HEAD `242e8bc`, when the responders were the inline
// `flowplane_common::arp_nd::try_write_{arp,nd}_reply` raw-pointer builders) via BPF_PROG_TEST_RUN on
// the identical fixtures + PORT_META. Captured by a throwaway copy of this test built at 242e8bc in a
// scratch worktree that dumped `out.data` for each vector.

#[rustfmt::skip]
const ARP_OUT: &[u8] = &[
    0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x01,
    0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x01,
    0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc, 0x0a, 0x00, 0x00, 0x2a,
];
#[rustfmt::skip]
const ND_OUT: &[u8] = &[
    0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xdd, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x88, 0x00, 0x17, 0xdc, 0x60, 0x00, 0x00, 0x00, 0xfe, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
];

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel)"]
fn arp_nd_bytecode_matches_original_golden() {
    let vectors: [(&str, Vec<u8>, &[u8]); 2] = [
        ("ARP", arp_request_frame(), ARP_OUT),
        ("ND", ns_frame(), ND_OUT),
    ];
    for (name, frame, golden) in &vectors {
        let (_ebpf, prog_fd) = load_prog();
        let out = bpf_prog_test_run(prog_fd, frame)
            .unwrap_or_else(|e| panic!("BPF_PROG_TEST_RUN on guest_tx [{name}] failed: {e}"));
        assert_eq!(
            out.retval, XDP_REDIRECT,
            "[{name}] expected XDP_REDIRECT, got action {}",
            out.retval
        );
        assert_eq!(
            out.data, *golden,
            "[{name}] current bytecode output diverged from the ORIGINAL (242e8bc) inline-eBPF golden \
             — the flowplane-core arp_nd extraction is NOT byte-faithful for this branch",
        );
    }
}
