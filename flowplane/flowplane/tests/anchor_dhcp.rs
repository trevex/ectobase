//! BPF_PROG_TEST_RUN byte-parity anchor for the guest-facing DHCPv4 responder that was extracted
//! into `flowplane-core` (`dhcp::{parse, write}`, called by the eBPF `guest_dhcp` glue).
//!
//! A guest sends a DHCPv4 DISCOVER (UDP dport 67). The `guest_dhcp` datapath parses it, resizes the
//! frame to the fixed `REPLY_LEN`, builds the OFFER (assigned IP = the port's IPv4; virtual gateway =
//! server identity; MTU/DNS/host-name from `DHCP_CONFIG`/`DHCP_META`), and reflects it back to the
//! guest via `bpf_redirect(ingress_ifindex)` (== XDP_REDIRECT). The OFFER is a FIXED-LAYOUT response
//! (constant length, constant option offsets), so every packet write is constant-offset — the same
//! property that lets the extracted core cross the `Pkt` seam verifier-clean.
//!
//! # Two independent checks (the second breaks a circularity)
//!
//! 1. `dhcp_bytecode_matches_native_sim` — loads the REAL compiled `guest_dhcp`, runs it on a DISCOVER
//!    via `BPF_PROG_TEST_RUN`, and asserts the kernel output equals the native `flowplane-sim`
//!    `SimNode::guest_dhcp4` for the same input + `PORT_META` + `DHCP_CONFIG` + `DHCP_META`. Because
//!    the extraction made BOTH the production `guest_dhcp` and `SimNode::guest_dhcp4` call the SAME
//!    `flowplane_core::dhcp::{parse, write}`, this cross-check alone would NOT catch a source-level
//!    behavior change from the extraction — it would change both sides identically.
//!
//! 2. `dhcp_bytecode_matches_original_golden` — asserts the CURRENT compiled bytecode output equals
//!    hardcoded GOLDEN bytes captured from the ORIGINAL, PRE-extraction `guest_dhcp` (HEAD `69000b8`,
//!    when the DHCPv4 responder was the inline `flowplane_common::dhcp::{parse_dhcpv4_request,
//!    write_dhcpv4_reply}` raw-pointer builder) via `BPF_PROG_TEST_RUN` on the identical fixture +
//!    maps. This is INDEPENDENT of `SimNode` and so proves the rewired core is byte-faithful to the
//!    deleted inline builder (full OFFER frame incl. the IPv4 header checksum).
//!
//! Privileged: needs CAP_BPF + a kernel that supports XDP test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::{Array as AyaArray, HashMap as AyaHashMap};
use aya::programs::Xdp;
use aya::{Ebpf, EbpfLoader};
use flowplane_common::{DhcpConfig, DhcpMeta, PortMeta, DHCP_MAX_DNS};
use flowplane_core::pkt::Action;
use flowplane_sim::SimNode;

// BPF_PROG_TEST_RUN's synthetic xdp_md sets ingress_ifindex == 1, so `guest_dhcp` keys PORT_META /
// DHCP_META on 1 AND `reflect` redirects to ifindex 1 (== the anchor's expected Redirect(1)).
const SRC_IFINDEX: u32 = 1;
const VNI: u32 = 100;
const GUEST_IPV4: [u8; 4] = [10, 0, 0, 42];
const GATEWAY_IPV4: [u8; 4] = [10, 0, 0, 1];
const GUEST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const CLIENT_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc];

const MTU: u16 = 1400;
const DNS4_A: [u8; 4] = [8, 8, 8, 8];
const DNS4_B: [u8; 4] = [1, 1, 1, 1];
const HOSTNAME: &[u8] = b"vm-node-7";

const ETH_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
const F_BOOTP: usize = ETH_LEN + 20 + 8;
const BOOTP_MAGIC_OFF: usize = 236;
const F_OPTS: usize = F_BOOTP + 240;
const REPLY_LEN: usize = F_OPTS + 146;

const DHCP_MSG_DISCOVER: u8 = 1;

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IPV4,
        gateway_ipv4: GATEWAY_IPV4,
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
        underlay_ipv6: [0; 16],
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

fn dhcp_config() -> DhcpConfig {
    let mut dns4 = [[0u8; 4]; DHCP_MAX_DNS];
    dns4[0] = DNS4_A;
    dns4[1] = DNS4_B;
    DhcpConfig {
        mtu: MTU,
        dns4_len: 2,
        dns6_len: 0,
        dns4,
        dns6: [[0u8; 16]; DHCP_MAX_DNS],
    }
}

fn dhcp_meta() -> DhcpMeta {
    let mut hostname = [0u8; 64];
    hostname[..HOSTNAME.len()].copy_from_slice(HOSTNAME);
    DhcpMeta {
        hostname,
        hostname_len: HOSTNAME.len() as u8,
        boot_filename: [0u8; 64],
        boot_filename_len: 0,
        pxe_host: [0u8; 46],
        pxe_host_len: 0,
        _pad: [0; 1],
    }
}

/// Build a guest DHCPv4 DISCOVER frame (Ethernet + IPv4 + UDP + BOOTP + options).
fn discover_frame() -> Vec<u8> {
    let opts: &[u8] = &[53, 1, DHCP_MSG_DISCOVER, 255];
    let mut f = vec![0u8; F_OPTS + opts.len()];
    f[0..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&CLIENT_MAC);
    f[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
    f[ETH_LEN] = 0x45;
    f[ETH_LEN + 9] = IPPROTO_UDP;
    f[ETH_LEN + 20..ETH_LEN + 22].copy_from_slice(&68u16.to_be_bytes());
    f[ETH_LEN + 22..ETH_LEN + 24].copy_from_slice(&67u16.to_be_bytes());
    f[F_BOOTP] = 1;
    f[F_BOOTP + 4..F_BOOTP + 12].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 0, 0x80, 0]);
    f[F_BOOTP + 28..F_BOOTP + 34].copy_from_slice(&CLIENT_MAC);
    f[F_BOOTP + BOOTP_MAGIC_OFF..F_BOOTP + BOOTP_MAGIC_OFF + 4]
        .copy_from_slice(&0x6382_5363u32.to_be_bytes());
    f[F_OPTS..F_OPTS + opts.len()].copy_from_slice(opts);
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
    // The OFFER GROWS the frame to REPLY_LEN (> input); size the output buffer generously.
    let mut out_buf = vec![0u8; REPLY_LEN + 256];
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

/// Load the compiled object, install PORT_META[1] / DHCP_CONFIG[0] / DHCP_META[1], and return the
/// loaded `Ebpf` + the verified `guest_dhcp` fd (the DHCP responder is run directly here — it is a
/// tail-call target in production, but `BPF_PROG_TEST_RUN` invokes it as a standalone XDP program).
fn load_prog() -> (Ebpf, RawFd) {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    let pin = Box::leak(Box::new(
        tempfile::Builder::new()
            .prefix("flowplane-anchor-dhcp-")
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
        let mut m: AyaArray<_, DhcpConfig> =
            AyaArray::try_from(ebpf.map_mut("DHCP_CONFIG").expect("DHCP_CONFIG map")).unwrap();
        m.set(0, dhcp_config(), 0).expect("set DHCP_CONFIG");
    }
    {
        let mut m: AyaHashMap<_, u32, DhcpMeta> =
            AyaHashMap::try_from(ebpf.map_mut("DHCP_META").expect("DHCP_META map")).unwrap();
        m.insert(SRC_IFINDEX, dhcp_meta(), 0)
            .expect("insert DHCP_META");
    }

    let prog: &mut Xdp = ebpf
        .program_mut("guest_dhcp")
        .expect("guest_dhcp program present")
        .try_into()
        .expect("guest_dhcp is an XDP program");
    prog.load().expect("verify/load guest_dhcp");
    let prog_fd = prog.fd().expect("guest_dhcp fd").as_fd().as_raw_fd();
    (ebpf, prog_fd)
}

/// Build a native `SimNode` with the SAME maps the eBPF anchor installs.
fn sim_node() -> SimNode {
    let mut node = SimNode::new();
    node.maps.dhcp_config = Some(dhcp_config());
    node.maps.dhcp_meta.insert(SRC_IFINDEX, dhcp_meta());
    node
}

// --- The anchor tests -----------------------------------------------------------------------

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel)"]
fn dhcp_bytecode_matches_native_sim() {
    let meta = port_meta();
    let node = sim_node();
    let frame = discover_frame();

    // Native pure-core expected output (redirect back to the ingress ifindex == 1).
    let native = node.guest_dhcp4(&frame, &meta, SRC_IFINDEX);
    assert_eq!(
        native.action,
        Action::Redirect(SRC_IFINDEX),
        "sanity: native sim reflects the OFFER back to the guest"
    );

    let (_ebpf, prog_fd) = load_prog();
    let out = bpf_prog_test_run(prog_fd, &frame)
        .unwrap_or_else(|e| panic!("BPF_PROG_TEST_RUN on guest_dhcp failed: {e}"));
    assert_eq!(
        out.retval, XDP_REDIRECT,
        "native pure-core diverged from real bytecode: expected XDP_REDIRECT, got {}",
        out.retval
    );
    assert_eq!(
        out.data, native.pkt,
        "native pure-core diverged from real bytecode: OFFER bytes differ from SimNode"
    );
}

// --- Golden captured from the ORIGINAL (pre-extraction) inline-eBPF guest_dhcp @ 69000b8 --------
//
// Produced by running the ORIGINAL program (HEAD `69000b8`, when the DHCPv4 responder was the inline
// `flowplane_common::dhcp::{parse_dhcpv4_request, write_dhcpv4_reply}` raw-pointer builder) via
// BPF_PROG_TEST_RUN on the identical DISCOVER fixture + maps. Captured by a throwaway copy of this
// test built at 69000b8 in a scratch worktree that dumped `out.data`.

#[rustfmt::skip]
const OFFER_OUT: &[u8] = &[
    0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
    0x01, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x6f, 0x4f, 0x0a, 0x00, 0x00, 0x01, 0xff, 0xff,
    0xff, 0xff, 0x00, 0x43, 0x00, 0x44, 0x01, 0x8a, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xde, 0xad,
    0xbe, 0xef, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x2a, 0x0a, 0x00,
    0x00, 0x01, 0x0a, 0x00, 0x00, 0x01, 0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x02, 0x33, 0x04, 0xff,
    0xff, 0xff, 0xff, 0x36, 0x04, 0x0a, 0x00, 0x00, 0x01, 0x79, 0x0c, 0x10, 0xa9, 0xfe, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01, 0x04, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x02, 0x05,
    0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x08, 0x08, 0x08, 0x08, 0x08, 0x01, 0x01, 0x01,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x09, 0x76, 0x6d, 0x2d, 0x6e, 0x6f,
    0x64, 0x65, 0x2d, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
];

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel)"]
fn dhcp_bytecode_matches_original_golden() {
    let (_ebpf, prog_fd) = load_prog();
    let out = bpf_prog_test_run(prog_fd, &discover_frame())
        .unwrap_or_else(|e| panic!("BPF_PROG_TEST_RUN on guest_dhcp failed: {e}"));
    assert_eq!(
        out.retval, XDP_REDIRECT,
        "expected XDP_REDIRECT, got action {}",
        out.retval
    );
    assert_eq!(
        out.data, OFFER_OUT,
        "current bytecode output diverged from the ORIGINAL (69000b8) inline-eBPF golden — the \
         flowplane-core dhcp extraction is NOT byte-faithful",
    );
}
