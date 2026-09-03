//! Full North-South walking-skeleton scenario, end to end through the REAL datapath core:
//! external packet -> (P2 Task 5: kernel decap, modeled as already-happened) -> host uplink ingress
//! firewall + conntrack -> guest. Every processing step is a real `flowplane_core` fn (via
//! `SimNode`); nothing is reimplemented here.

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, Local, UnderlayValue, FW_ACTION_ACCEPT, FW_DIR_INGRESS, UNDERLAY_LOCAL_DELIVER,
};
use flowplane_core::conntrack::ct_key;
use flowplane_core::encap::ETH_LEN;
use flowplane_core::maps::Maps;
use flowplane_core::pkt::Action;
use flowplane_core::uplink::GW_MAC;

use crate::{SimNode, VecPkt};

const VNI: u32 = 100;
const TAP: u32 = 42;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const EXT_IP: [u8; 4] = [203, 0, 113, 9];
const HOST_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];

/// A full guest Ethernet frame `[InnerEth(14)][IPv4][TCP]` — the POST-decap frame the kernel
/// `collect_md` geneve device hands the ingress tcx program (see `sim.rs`'s module doc), from
/// `EXT_IP` -> `GUEST_IP` on `dport`.
fn inner_eth_frame(dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(EXT_IP, GUEST_IP, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

/// Install an ingress ALLOW rule on `tap` for TCP -> GUEST_IP:port.
fn allow_tcp(node: &mut SimNode, port: u16) {
    node.maps.fw_meta.insert(
        TAP,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    node.maps.fw_rules.insert(
        (TAP, 0),
        FwRule {
            src_ip: [0; 4],
            src_mask: [0; 4],
            dst_ip: GUEST_IP,
            dst_mask: [255, 255, 255, 255],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: port,
            dst_port_max: port,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        },
    );
}

#[test]
fn external_to_guest_encap_decap_fw_allow_ct() {
    // POST-decap frame as it arrives at the host's uplink_rx (the kernel already decapped — see
    // the module doc); `host_uplink` synthesizes the ROUTES/UNDERLAY self-route toward HOST_UNDERLAY.
    let inner = inner_eth_frame(443);

    // Host runs the real uplink base path: ingress FW allow (new flow) + CT create + inner-Eth
    // rewrite (no resize — the frame arrives already decapped).
    let mut host = SimNode::new();
    allow_tcp(&mut host, 443);
    let out = host.host_uplink(&inner, VNI, GUEST_IP, TAP, GUEST_MAC);

    assert_eq!(
        out.action,
        Action::Redirect(TAP),
        "delivered to the guest tap"
    );
    assert_eq!(&out.pkt[0..6], &GUEST_MAC, "inner eth dst = guest MAC");
    assert_eq!(&out.pkt[6..12], &GW_MAC, "inner eth src = gateway MAC");
    assert_eq!(&out.pkt[12..14], &[0x08, 0x00], "inner ethertype = IPv4");
    assert_eq!(
        out.pkt.len(),
        inner.len(),
        "inner Ethernet rewritten in place; the frame does not resize (no outer header to strip)"
    );
    // A new flow seeds the forward key (and a reverse key). Assert the forward entry exists.
    let fwd_key = ct_key(&VecPkt::from_bytes(&inner), ETH_LEN, VNI).unwrap();
    assert!(
        host.maps.conntrack_get(&fwd_key).is_some(),
        "forward conntrack entry created"
    );
}

#[test]
fn external_to_guest_firewall_drop_on_unopened_port() {
    // Allow only :443, but the flow targets :80 -> ingress firewall drops the new flow.
    let inner = inner_eth_frame(80);

    let mut host = SimNode::new();
    allow_tcp(&mut host, 443);
    let out = host.host_uplink(&inner, VNI, GUEST_IP, TAP, GUEST_MAC);

    assert_eq!(
        out.action,
        Action::Drop,
        "unopened port dropped by ingress firewall"
    );
    assert_eq!(
        host.maps.conntrack.len(),
        0,
        "dropped flow leaves no conntrack entry"
    );
}

// ─── Mechanism #4: WAN-edge local-deliver sentinel + genuine-miss drop ────────────────────────────
//
// On a `ROUTES` miss, `resolve_uplink_target` checks whether THIS node is the WAN edge
// (`UNDERLAY[LOCAL.underlay_ipv6]` carries the `UNDERLAY_LOCAL_DELIVER` sentinel, programmed once by
// `Control::attach_edge` under the edge's own `Local.underlay_ipv6`): a sentinel hit means edge role
// (decap-only + L2 rewrite + hand off to the kernel via `Pass`); anything else is a genuine miss —
// SECURITY DEFAULT: `Drop`, never `Pass` (never leak decapped overlay bytes into a random node's
// kernel netns).

const UNROUTABLE_DST: [u8; 4] = [203, 0, 113, 200]; // no ROUTES entry exists for this address anywhere

fn edge_local() -> Local {
    Local {
        uplink_ifindex: 11,
        uplink_mac: [0x07; 6],
        gateway_mac: [0x08; 6],
        underlay_ipv6: HOST_UNDERLAY,
    }
}

/// A POST-decap `[InnerEth][IPv4][TCP]` frame `EXT_IP -> UNROUTABLE_DST`. No ROUTES entry is ever
/// programmed for `UNROUTABLE_DST` in these tests.
fn unroutable_inner_frame() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(EXT_IP, UNROUTABLE_DST, 64)
        .tcp(40000, 443, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

/// Sentinel hit: this node is registered as the WAN edge, so a `ROUTES` miss decaps-only + rewrites
/// the inner Ethernet for local-kernel hand-off (`Action::Pass`) instead of guest delivery.
#[test]
fn wan_edge_sentinel_decaps_and_passes_to_kernel_on_routes_miss() {
    let encapped = unroutable_inner_frame();
    let mut node = SimNode::with_local(edge_local());
    node.maps.underlay.insert(
        HOST_UNDERLAY, // == edge_local().underlay_ipv6
        UnderlayValue {
            vni: 0,
            tap_ifindex: UNDERLAY_LOCAL_DELIVER,
            guest_mac: [0; 6],
            _pad: [0; 2],
        },
    );

    let out = node.uplink(&encapped, VNI, &edge_local());

    assert_eq!(
        out.action,
        Action::Pass,
        "edge local-deliver hands off to the kernel via Pass, not a guest Redirect"
    );
    assert_eq!(
        &out.pkt[0..6],
        &edge_local().uplink_mac,
        "inner eth dst = our uplink MAC"
    );
    assert_eq!(
        &out.pkt[6..12],
        &GW_MAC,
        "inner eth src = gateway MAC placeholder"
    );
    assert_eq!(&out.pkt[12..14], &[0x08, 0x00], "inner ethertype = IPv4");
    assert_eq!(
        out.pkt.len(),
        unroutable_inner_frame().len(),
        "inner Eth rewritten in place, no resize (same shape as guest delivery)"
    );
}

/// Genuine miss: no `ROUTES` entry for the dst AND this node is NOT the WAN edge (no
/// `UNDERLAY[LOCAL.underlay_ipv6]` entry at all). Must DROP — never PASS decapped overlay bytes
/// into this node's own kernel.
#[test]
fn genuine_routes_miss_drops_not_passes() {
    let encapped = unroutable_inner_frame();
    let mut node = SimNode::new(); // no UNDERLAY[Local.underlay_ipv6] entry at all

    let out = node.uplink(&encapped, VNI, &edge_local());

    assert_eq!(
        out.action,
        Action::Drop,
        "a genuine miss must drop, never pass, decapped overlay bytes"
    );
}

/// Genuine miss even when an UNDERLAY[LOCAL.underlay_ipv6] entry exists but is NOT the sentinel
/// (an ordinary local interface happens to share the node's own underlay identity) — only the exact
/// `UNDERLAY_LOCAL_DELIVER` tap_ifindex value means edge role.
#[test]
fn routes_miss_with_non_sentinel_local_underlay_entry_still_drops() {
    let encapped = unroutable_inner_frame();
    let mut node = SimNode::with_local(edge_local());
    node.maps.underlay.insert(
        HOST_UNDERLAY,
        UnderlayValue {
            vni: VNI,
            tap_ifindex: TAP, // a REAL tap ifindex, not the sentinel
            guest_mac: GUEST_MAC,
            _pad: [0; 2],
        },
    );

    let out = node.uplink(&encapped, VNI, &edge_local());

    assert_eq!(
        out.action,
        Action::Drop,
        "a non-sentinel UNDERLAY[LOCAL.underlay_ipv6] entry must NOT be treated as edge role"
    );
}
