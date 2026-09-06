//! `BPF_PROG_TEST_RUN` anchor for the LB **local-deliver** `uplink_rx` datapath (post-P2 Geneve
//! retarget).
//!
//! Companion to `anchor_uplink.rs` (the base N-S deliver anchor) — see that file's module doc for
//! the full explanation of why this file no longer byte-compares delivery output: `uplink_rx` is now
//! a tc classifier on the geneve `collect_md` device, and its FIRST action is
//! `get_tunnel_key(ctx.skb.skb)` — on failure it returns `TC_ACT_OK` immediately, before the LB
//! dispatch (or any other map read) ever runs. `BPF_PROG_TEST_RUN` cannot construct the tunnel-key
//! metadata a decap-side `get_tunnel_key` needs (confirmed empirically at P2 Task 1's spike), so the
//! LB local-deliver branch this file used to byte-anchor has no bytecode oracle anymore.
//!
//! What this anchor still proves: the real compiled `uplink_rx`, fed a post-decap inner frame whose
//! IPv4 dst is the overlay LB VIP (the exact fixture that used to drive the LB local-deliver path)
//! and with the SAME LB/Maglev/firewall map state a real LB backend would carry, still fails SAFE —
//! `TC_ACT_OK`, packet unchanged — because the tunnel-key gate runs before the LB dispatch. In
//! production this is unreachable (the geneve device always stamps a tunnel key), but it is exactly
//! what `BPF_PROG_TEST_RUN` CAN exercise for this fixture shape.
//!
//! The LB local-deliver scenario itself (Maglev selects THIS node's own underlay → deliver to the
//! local tap, DSR, no conntrack) is exhaustively covered, bytecode-free, by
//! `flowplane_sim::lb_scenario_test::ew_lb_local_deliver_no_reforward` and its siblings, which drive
//! the SAME `flowplane_core::datapath::process_uplink` the real bytecode calls. `native_reference`
//! below re-derives the SAME fixture's expected delivery as a sanity check, not a byte-parity oracle.
//!
//! Privileged: needs CAP_BPF + a kernel that supports tc test-run. Run via `make sim-anchor`.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use flowplane_common::{
    FwMeta, FwRule, IfaceValue, LbBackend, LbKey, LbValue, Local, MaglevKey, FW_ACTION_ACCEPT,
    FW_DIR_INGRESS,
};

use aya::programs::SchedClassifier;
use flowplane_core::pkt::Action;
use flowplane_sim::SimNode;

// --- LB local-deliver fixture (mirrors flowplane_sim::lb_scenario_test::ew_lb_local_deliver_no_reforward) ----

const VNI: u32 = 100;
const TAP: u32 = 42;
const TABLE_ID: u32 = 1;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const GUEST_IP: [u8; 4] = [10, 0, 0, 20]; // the client guest (LB source)
const OVERLAY_VIP: [u8; 4] = [10, 0, 100, 1]; // the balanced overlay VIP (inner dst, DSR)
const BACKEND_UL: [u8; 16] = ul(0xbb); // this node's underlay == the Maglev backend
const DPORT: u16 = 443;

const fn ul(last: u8) -> [u8; 16] {
    [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last]
}

fn local() -> Local {
    Local {
        uplink_ifindex: 9,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: BACKEND_UL,
    }
}

/// Local-delivery `INTERFACES` row for the backend's own overlay VIP (what `process_interface`
/// would program for the guest tap this LB VIP is backed by, DSR-style: same VIP, no NAT).
fn iface_value() -> IfaceValue {
    IfaceValue {
        tap_ifindex: TAP,
        is_local: 1,
        underlay_ipv6: BACKEND_UL,
        guest_mac: GUEST_MAC,
        peer_capable: 0,
        _pad: [0; 1],
    }
}

/// This node's own underlay as the Maglev-selected `LbBackend` (self-selection => local deliver,
/// DSR): `node_vtep == self` and `overlay_ip`/`vni` resolve delivery via `INTERFACES`.
fn backend() -> LbBackend {
    LbBackend {
        node_vtep: BACKEND_UL,
        overlay_ip: [
            OVERLAY_VIP[0],
            OVERLAY_VIP[1],
            OVERLAY_VIP[2],
            OVERLAY_VIP[3],
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
        vni: VNI,
        is_v6: 0,
        _pad: [0; 3],
    }
}

/// The POST-decap inner frame `[InnerEth(14)][IPv4][TCP]` from `GUEST_IP` -> `OVERLAY_VIP:DPORT` —
/// exactly what the kernel `collect_md` geneve device would hand `uplink_rx`. This is also the
/// literal `BPF_PROG_TEST_RUN` input below — there is no outer wrapper to build anymore.
fn inner_eth_frame() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(GUEST_IP, OVERLAY_VIP, 64)
        .tcp(40000, DPORT, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

/// The single ingress ALLOW rule the backend installs on `TAP`, covering the VIP dst (DSR: the
/// inner dst stays the VIP, so the policy MUST cover `VIP:443`, not the backend's own IP).
fn allow_vip_rule() -> FwRule {
    FwRule {
        src_ip: [0; 4],
        src_mask: [0; 4],
        dst_ip: OVERLAY_VIP,
        dst_mask: [255, 255, 255, 255],
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min: DPORT,
        dst_port_max: DPORT,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto: 6,
        action: FW_ACTION_ACCEPT,
        direction: FW_DIR_INGRESS,
        enabled: 1,
    }
}

/// Native `flowplane_core::datapath::process_uplink` reference for the LB local-deliver fixture: a
/// backend node whose INTERFACES local-delivery row + overlay LB + Maglev self-selection +
/// VIP-allow firewall match exactly the eBPF maps the (unreachable, see the module doc) LB
/// dispatch would read. Sanity check on the fixture, not a byte-parity oracle.
fn native_reference(inner: &[u8]) -> (Action, Vec<u8>) {
    let mut node = SimNode::with_local(local());
    // INTERFACES local-delivery row for the backend's own overlay VIP (replaces the old
    // UNDERLAY[backend] fiction — local-vs-remote is now `LbBackend.node_vtep == self`, and local
    // delivery resolves the tap via INTERFACES[(vni, overlay_ip)]).
    node.maps.add_iface(VNI, OVERLAY_VIP, iface_value());
    // Overlay LB VIP -> Maglev table 1.
    node.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: OVERLAY_VIP,
            port: DPORT,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: TABLE_ID,
            size: 1,
        },
    );
    // Maglev slot 0 -> this node's own underlay as an LbBackend (LB selects self => local
    // deliver, DSR).
    node.maps.maglev.insert(
        MaglevKey {
            table_id: TABLE_ID,
            slot: 0,
        },
        backend(),
    );
    // Firewall: one ingress rule on TAP covering VIP:443 (enforcement is unconditional).
    node.maps.fw_meta.insert(
        TAP,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    node.maps.fw_rules.insert((TAP, 0), allow_vip_rule());

    let l = local();
    let out = node.uplink(inner, VNI, &l);
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

// --- The anchor test ------------------------------------------------------------------------

#[test]
#[ignore = "privileged: run via `make sim-anchor` (needs CAP_BPF + kernel tc test-run)"]
fn uplink_rx_lb_deliver_bytecode_fails_safe_without_tunnel_key() {
    let inner = inner_eth_frame();

    // Sanity: what the native core delivers for this fixture given a REAL tunnel key (the sim is
    // the oracle for the LB local-deliver path — see the module doc).
    let (native_action, _native_pkt) = native_reference(&inner);
    assert_eq!(
        native_action,
        Action::Redirect(TAP),
        "sanity: native LB sim delivers the fixture to the backend's tap given a real tunnel key"
    );

    // Load the real eBPF object (aya-build embeds the bpfel object at $OUT_DIR/flowplane-prog;
    // flowplane is binary-only, so the load is inlined). No map population needed: the tunnel-key
    // gate is the FIRST thing `try_uplink_rx` does, before the LB dispatch or any other map read
    // (see the module doc).
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    let pin = tempfile::Builder::new()
        .prefix("flowplane-anchor-lb-")
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

    // Run the real bytecode on the (undecorated) inner LB-VIP frame — no tunnel-key metadata attached.
    let out = bpf_prog_test_run_skb(prog_fd, &inner, 1 /* loopback, always present */)
        .expect("BPF_PROG_TEST_RUN on uplink_rx (needs CAP_BPF + kernel tc test-run support)");

    assert_eq!(
        out.retval, TC_ACT_OK,
        "uplink_rx must fail SAFE (TC_ACT_OK passthrough) when no tunnel-key metadata is present, \
         even for an LB-VIP-shaped fixture — the tunnel-key gate runs before the LB dispatch (see \
         the module doc); production never reaches this branch"
    );
    assert_eq!(
        out.data, inner,
        "uplink_rx must not mutate the packet before its tunnel-key gate"
    );
}
