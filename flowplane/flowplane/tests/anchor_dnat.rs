//! `BPF_PROG_TEST_RUN` anchor for the return-path (reverse) DNAT datapath (post-P2 Geneve retarget):
//! the `uplink_rx` conntrack rewrite-apply (`flowplane_core::conntrack::ct_apply`) reached on a
//! previously-SNAT'd guest flow's reply.
//!
//! ## Why this anchor no longer byte-compares the reverse-DNAT'd output
//!
//! `uplink_rx` is now a tc classifier on the geneve `collect_md` device (P2 Task 4b) — see
//! `anchor_uplink.rs`'s module doc for the full explanation. Its FIRST action is
//! `get_tunnel_key(ctx.skb.skb)`; on failure it returns `TC_ACT_OK` immediately, before the
//! base-vs-NAT-return dispatch (or any other map/CT read) ever runs. `BPF_PROG_TEST_RUN` cannot
//! construct the tunnel-key metadata a decap-side `get_tunnel_key` needs (confirmed empirically at
//! P2 Task 1's spike), so the reverse-DNAT branch this file used to byte-anchor — including its
//! ORIGINAL-golden-bytes cross-check against the pre-extraction inline implementation (HEAD
//! `0f0ec06`) — has no bytecode oracle anymore: there is no way to produce a "current bytecode
//! output" to compare against those goldens, because the real bytecode never reaches the code that
//! used to produce them.
//!
//! ## What this anchor still proves
//!
//! The real compiled `uplink_rx`, fed a post-decap TCP return frame (`EXT_IP:EXT_PORT ->
//! NAT_IP:NAT_PORT`) with the SAME reverse-CT / NAT_IPS / firewall map state a real host would
//! carry, still fails SAFE — `TC_ACT_OK`, packet unchanged — because the tunnel-key gate runs before
//! the reverse-DNAT dispatch. In production this is unreachable (the geneve device always stamps a
//! tunnel key), but it is exactly what `BPF_PROG_TEST_RUN` CAN exercise for this fixture shape.
//!
//! The reverse-DNAT rewrite itself (TCP/UDP address + port + checksum fold via `ct_apply`) is
//! exhaustively covered, bytecode-free, by `flowplane_sim::nat_test`'s
//! `dnat_return_tcp_rewrites_dst_ip_and_port` / `dnat_return_udp_rewrites_dst_ip_and_port`, which
//! drive the SAME `flowplane_core::conntrack::ct_apply` the real bytecode calls (via
//! `SimNode::uplink_nat_return`). The `df94251` firewall-skip regression this file used to guard
//! (an established NAT return must not be dropped by a deny-by-default ingress firewall) is likewise
//! covered, bytecode-free, by
//! `flowplane_sim::nat_test::uplink_rx_dispatches_nat_return_past_deny_by_default_firewall`, which
//! drives the SAME `flowplane_core::datapath::process_uplink_rx` dispatch the real bytecode's
//! base-vs-NAT-return branch delegates to. `native_reference` below re-derives the SAME fixture's
//! expected reverse-DNAT as a sanity check, not a byte-parity oracle.
//!
//! Privileged: needs CAP_BPF + a kernel that supports tc test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::programs::SchedClassifier;
use flowplane_common::{CtEntry, CtKey, Local, CT_F_SRC_NAT, CT_REWRITE_DST};
use flowplane_core::encap::ETH_LEN;
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

const IPPROTO_TCP: u8 = 6;

/// The POST-decap RETURN frame `[InnerEth(14)][IPv4][TCP]`: `EXT_IP:EXT_PORT` -> `NAT_IP:NAT_PORT`
/// (as it arrives from the peer, before reverse-DNAT) — exactly what the kernel `collect_md` geneve
/// device would hand `uplink_rx`. This is also the literal `BPF_PROG_TEST_RUN` input below.
fn tcp_return_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(EXT_IP, NAT_IP, 64)
        .tcp(EXT_PORT, NAT_PORT, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
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
        _pad: [0; 7],
    }
}

/// Native `flowplane_core::datapath::process_uplink_nat_return` reference for the TCP return
/// fixture: seeds the identical reverse CT entry + NAT_IPS registration a real host's eBPF maps
/// would carry. Sanity check on the fixture, not a byte-parity oracle.
fn native_reference(frame: &[u8]) -> (Action, Vec<u8>) {
    let mut host = SimNode::new();
    host.maps
        .conntrack
        .insert(reverse_ct_key(IPPROTO_TCP), reverse_ct_entry());
    host.maps.nat_ips.insert((VNI, NAT_IP));
    // Delivery-target reconstruction mechanism #2 (see `flowplane_core::datapath::
    // resolve_uplink_target`): the RESTORED guest IP (reverse CT's `xlate_ip`) is looked up via the
    // SAME `INTERFACES[(vni, guest_ip)]` local-delivery entry a base delivery would use.
    host.maps.add_iface(
        VNI,
        GUEST_IP,
        flowplane_common::IfaceValue {
            tap_ifindex: TAP,
            is_local: 1,
            underlay_ipv6: [0; 16],
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    let local = Local::default();
    let out = host.uplink_nat_return(frame, VNI, &local);
    (out.action, out.pkt)
}

// --- Raw BPF_PROG_TEST_RUN syscall (skb ctx — uplink_rx is a tc classifier, P2 Task 4b) ---------

const BPF_PROG_TEST_RUN: libc::c_int = 10;
const TC_ACT_OK: u32 = 0;

const SK_BUFF_SIZE: usize = 192;
const SKB_IFINDEX_OFF: usize = 40;

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

fn bpf_prog_test_run_skb(
    prog_fd: RawFd,
    input: &[u8],
    ifindex: u32,
) -> std::io::Result<TestRunOut> {
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

// --- The anchor test -----------------------------------------------------------------------

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel tc test-run)"]
fn dnat_return_bytecode_fails_safe_without_tunnel_key() {
    let frame = tcp_return_frame();

    // Sanity: what the native core reverse-DNATs + delivers for this fixture given a REAL tunnel
    // key (the sim is the oracle for this path — see the module doc).
    let (native_action, native_pkt) = native_reference(&frame);
    assert_eq!(
        native_action,
        Action::Redirect(TAP),
        "sanity: native sim reverse-DNATs + delivers the return to the guest tap given a real \
         tunnel key"
    );
    let inner_dst = ETH_LEN + 16;
    assert_eq!(
        &native_pkt[inner_dst..inner_dst + 4],
        &GUEST_IP,
        "sanity: native reverse-DNAT rewrote inner dst IP to GUEST_IP"
    );

    // Load the real eBPF object (aya-build embeds the bpfel object at $OUT_DIR/flowplane-prog;
    // flowplane is binary-only, so the load is inlined). No map population needed: the tunnel-key
    // gate is the FIRST thing `try_uplink_rx` does, before the base-vs-NAT-return dispatch or any
    // other map/CT read (see the module doc).
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    let pin = tempfile::Builder::new()
        .prefix("flowplane-anchor-dnat-")
        .tempdir_in("/sys/fs/bpf")
        .expect("bpffs tempdir");
    let mut ebpf = aya::EbpfLoader::new()
        .map_pin_path(pin.path())
        .load(bytes)
        .expect("load compiled eBPF object");

    let prog: &mut SchedClassifier = ebpf
        .program_mut("uplink_rx")
        .expect("uplink_rx program present")
        .try_into()
        .expect("uplink_rx is a SchedClassifier (tcx) program");
    prog.load().expect("verify/load uplink_rx");
    let prog_fd = prog.fd().expect("uplink_rx fd").as_fd().as_raw_fd();

    // Run the real bytecode on the (undecorated) return frame — no tunnel-key metadata attached.
    let out = bpf_prog_test_run_skb(prog_fd, &frame, 1 /* loopback, always present */)
        .expect("BPF_PROG_TEST_RUN on uplink_rx (needs CAP_BPF + kernel tc test-run support)");

    assert_eq!(
        out.retval, TC_ACT_OK,
        "uplink_rx must fail SAFE (TC_ACT_OK passthrough) when no tunnel-key metadata is present, \
         even for a return-DNAT-shaped fixture with a matching reverse CT entry — the tunnel-key \
         gate runs before the base-vs-NAT-return dispatch (see the module doc); production never \
         reaches this branch"
    );
    assert_eq!(
        out.data, frame,
        "uplink_rx must not mutate the packet before its tunnel-key gate"
    );
}
