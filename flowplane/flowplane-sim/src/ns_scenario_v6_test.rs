//! v6 mirror of `ns_scenario_test.rs`: exhaustive coverage of
//! `flowplane_core::datapath::process_uplink_v6` (P2 Task 4c) — the shared-core v6-ingress
//! orchestrator `v6.rs::v6_uplink_rx` now delegates to, closing the pre-existing "no core/sim
//! coverage for v6 ingress" gap AND the interim v6 fail-OPEN-on-`ROUTES6`-miss security hole (HEAD's
//! hand-inlined path fell through to `TC_ACT_OK`/`Pass` on a miss; this orchestrator DROPs).
//!
//! Every test here drives [`SimNode::uplink_v6`] / [`SimNode::host_uplink_v6`] over a POST-decap
//! `[InnerEth(14)][InnerIPv6(40)][L4]` fixture — exactly what the kernel `collect_md` geneve device
//! hands the real tcx program (see `sim.rs`'s module doc for the v4 version of this contract).

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule6, LbBackend, LbKey, LbValue, Local, MaglevKey, PortMeta, UnderlayValue,
    FW_ACTION_ACCEPT, FW_DIR_INGRESS, UNDERLAY_LOCAL_DELIVER,
};
use flowplane_core::conntrack::ct_key6;
use flowplane_core::encap::{TunnelEncap, ETH_LEN};
use flowplane_core::maps::Maps;
use flowplane_core::pkt::Action;
use flowplane_core::uplink::GW_MAC;

use crate::{SimNode, VecPkt};

const VNI: u32 = 100;
const TAP: u32 = 42;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const GUEST_IP6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];
const EXT_IP6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
];
const HOST_UNDERLAY6: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];

/// A full guest Ethernet frame `[InnerEth(14)][IPv6][TCP]` — the POST-decap frame the kernel
/// `collect_md` geneve device hands the ingress tcx program, from `EXT_IP6` -> `GUEST_IP6` on `dport`.
fn inner_eth6_frame(dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv6(EXT_IP6, GUEST_IP6, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

/// Install an ingress ALLOW rule on `tap` for TCP -> GUEST_IP6:port.
fn allow_tcp6(node: &mut SimNode, tap: u32, port: u16) {
    node.maps.fw_meta6.insert(
        tap,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    node.maps.fw_rules6.insert(
        (tap, 0),
        FwRule6 {
            src_ip: [0; 16],
            src_mask: [0; 16],
            dst_ip: GUEST_IP6,
            dst_mask: [0xff; 16],
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

// ─── Mechanism #1: normal v6 guest delivery (ROUTES6 self-route -> UNDERLAY) ──────────────────────

#[test]
fn v6_external_to_guest_decap_fw_allow_ct6() {
    let inner = inner_eth6_frame(443);

    let mut host = SimNode::new();
    allow_tcp6(&mut host, TAP, 443);
    let out = host.host_uplink_v6(&inner, VNI, GUEST_IP6, TAP, GUEST_MAC);

    assert_eq!(
        out.action,
        Action::Redirect(TAP),
        "delivered to the guest tap"
    );
    assert_eq!(&out.pkt[0..6], &GUEST_MAC, "inner eth dst = guest MAC");
    assert_eq!(&out.pkt[6..12], &GW_MAC, "inner eth src = gateway MAC");
    assert_eq!(
        &out.pkt[12..14],
        &[0x86, 0xdd],
        "inner ethertype = IPv6 (0x86DD)"
    );
    assert_eq!(
        out.pkt.len(),
        inner.len(),
        "inner Ethernet rewritten in place; the frame does not resize"
    );
    let fwd_key = ct_key6(&VecPkt::from_bytes(&inner), ETH_LEN, VNI).unwrap();
    assert!(
        host.maps.conntrack6_get(&fwd_key).is_some(),
        "forward conntrack6 entry created for the new flow"
    );
}

/// Seed `PORT_META[tap]` marking the v6 delivery target an L3 netkit pod (`l3 = 1`). Keyed by tap
/// ifindex, exactly how `resolve_delivery_l3` looks it up (`maps.port_meta_get(tap)`).
fn mark_l3_pod6(node: &mut SimNode, tap: u32) {
    node.maps.port_meta.insert(
        tap,
        PortMeta {
            vni: VNI,
            guest_ipv4: [0; 4],
            gateway_ipv4: [0; 4],
            guest_mac: GUEST_MAC,
            l3: 1,
            _pad: [0; 1],
            underlay_ipv6: HOST_UNDERLAY6,
            gateway_ipv6: [0; 16],
            guest_ipv6: GUEST_IP6,
        },
    );
}

/// v6 mirror of `external_to_guest_l3_pod_delivery_zero_dst_mac`: `PORT_META[tap].l3 == 1` makes the
/// v6 delivery rewrite the inner eth **dst = all-zero MAC** (netkit device) instead of `guest_mac`.
/// src (`GW_MAC`), the IPv6 ethertype (0x86DD), and the inner IPv6 payload are byte-identical to the
/// `l3 == 0` case (`v6_external_to_guest_decap_fw_allow_ct6`).
#[test]
fn v6_external_to_guest_l3_pod_delivery_zero_dst_mac() {
    let inner = inner_eth6_frame(443);

    let mut host = SimNode::new();
    allow_tcp6(&mut host, TAP, 443);
    mark_l3_pod6(&mut host, TAP);
    let out = host.host_uplink_v6(&inner, VNI, GUEST_IP6, TAP, GUEST_MAC);

    assert_eq!(
        out.action,
        Action::Redirect(TAP),
        "delivered to the L3 pod tap"
    );
    assert_eq!(
        &out.pkt[0..6],
        &[0u8; 6],
        "L3 pod: inner eth dst = all-zero (netkit device) MAC, NOT guest MAC"
    );
    assert_eq!(
        &out.pkt[6..12],
        &GW_MAC,
        "inner eth src = gateway MAC (unchanged vs the L2 case)"
    );
    assert_eq!(
        &out.pkt[12..14],
        &[0x86, 0xdd],
        "inner ethertype = IPv6 (0x86DD, unchanged vs the L2 case)"
    );
    assert_eq!(
        &out.pkt[14..],
        &inner[14..],
        "inner IPv6 payload byte-identical (only the 6-byte dst MAC changed vs the L2 case)"
    );
    assert_eq!(
        out.pkt.len(),
        inner.len(),
        "inner Ethernet rewritten in place; the frame does not resize"
    );
}

#[test]
fn v6_firewall_drop_on_unopened_port() {
    // Allow only :443, but the flow targets :80 -> ingress firewall drops the new flow.
    let inner = inner_eth6_frame(80);

    let mut host = SimNode::new();
    allow_tcp6(&mut host, TAP, 443);
    let out = host.host_uplink_v6(&inner, VNI, GUEST_IP6, TAP, GUEST_MAC);

    assert_eq!(
        out.action,
        Action::Drop,
        "unopened port dropped by ingress firewall"
    );
    assert_eq!(
        host.maps.conntrack6.len(),
        0,
        "dropped flow leaves no conntrack6 entry"
    );
}

#[test]
fn v6_established_flow_refreshes_conntrack6_and_bypasses_firewall_reeval() {
    // First packet: allow rule present -> delivered, ct6 seeded.
    let inner = inner_eth6_frame(443);
    let mut host = SimNode::new();
    allow_tcp6(&mut host, TAP, 443);
    let out1 = host.host_uplink_v6(&inner, VNI, GUEST_IP6, TAP, GUEST_MAC);
    assert_eq!(out1.action, Action::Redirect(TAP));

    // Remove the firewall entirely (simulating a policy change mid-flow): a NEW flow would now be
    // denied-by-default, but this is the SAME 5-tuple, so the conntrack6 HIT must bypass the
    // firewall re-evaluation entirely (mirrors the v4 established-flow behavior).
    host.maps.fw_meta6.remove(&TAP);
    host.maps.fw_rules6.remove(&(TAP, 0));

    let out2 = host.host_uplink_v6(&inner, VNI, GUEST_IP6, TAP, GUEST_MAC);
    assert_eq!(
        out2.action,
        Action::Redirect(TAP),
        "an established flow (CT hit) is delivered without re-evaluating the firewall"
    );
}

// ─── v6 LB dispatch (E/W): local backend deliver, remote backend reforward ────────────────────────

const OVERLAY_VIP6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xa8, 0xc8, 0x01,
];
const GUEST_A6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
];
const REMOTE_BACKEND_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];

fn local_for(underlay: [u8; 16], ifindex: u32) -> Local {
    Local {
        uplink_ifindex: ifindex,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: underlay,
    }
}

/// A full guest Ethernet frame `[Eth(0x86DD)][IPv6][TCP]` src -> dst on `dport`.
fn eth_ipv6_tcp(src: [u8; 16], dst: [u8; 16], dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv6(src, dst, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// Install a v6 LB service `(VNI, OVERLAY_VIP6, 443, TCP)` -> Maglev table pointing at `backend`.
fn install_lb6(node: &mut SimNode, backend: [u8; 16]) {
    let last4 = [
        OVERLAY_VIP6[12],
        OVERLAY_VIP6[13],
        OVERLAY_VIP6[14],
        OVERLAY_VIP6[15],
    ];
    node.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: last4,
            port: 443,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 5,
            size: 1,
        },
    );
    node.maps.maglev.insert(
        MaglevKey {
            table_id: 5,
            slot: 0,
        },
        LbBackend {
            node_vtep: backend,
            vni: VNI,
            is_v6: 1,
            ..Default::default()
        },
    );
}

#[test]
fn v6_lb_local_backend_delivered_no_conntrack6_created() {
    // The LB backend re-selects itself (DSR): UNDERLAY[HOSTB_UL] is THIS node's own tap.
    const HOSTB_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xdd];
    let mut node = SimNode::with_local(local_for(HOSTB_UL, 9));
    node.maps.underlay.insert(
        HOSTB_UL,
        UnderlayValue {
            vni: VNI,
            tap_ifindex: TAP,
            guest_mac: GUEST_MAC,
            _pad: [0; 2],
        },
    );
    install_lb6(&mut node, HOSTB_UL);
    allow_tcp6(&mut node, TAP, 443);
    // The firewall matches on GUEST_IP6 above; for the LB/DSR path the inner dst stays the VIP, so
    // widen the allow rule to the VIP instead.
    node.maps.fw_rules6.insert(
        (TAP, 0),
        FwRule6 {
            src_ip: [0; 16],
            src_mask: [0; 16],
            dst_ip: OVERLAY_VIP6,
            dst_mask: [0xff; 16],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 443,
            dst_port_max: 443,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        },
    );

    let inner = eth_ipv6_tcp(GUEST_A6, OVERLAY_VIP6, 443);
    let out = node.uplink_v6(&inner, VNI, &local_for(HOSTB_UL, 9));

    assert_eq!(
        out.action,
        Action::Redirect(TAP),
        "LB-selected local backend delivered to its own tap"
    );
    let key = ct_key6(&VecPkt::from_bytes(&inner), ETH_LEN, VNI).unwrap();
    assert!(
        node.maps.conntrack6_get(&key).is_none(),
        "LB (DSR) delivery must NOT create a conntrack6 entry — step 3 is skipped for LB"
    );
}

#[test]
fn v6_lb_remote_backend_reforwards_with_tunnel_decision_no_decap() {
    // The Maglev-selected backend has NO local UNDERLAY entry on this node -> remote reforward: same
    // vni, no decap, byte-unchanged, tunnel-key decision toward the backend.
    let mut node = SimNode::with_local(local_for(
        [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xee],
        8,
    ));
    install_lb6(&mut node, REMOTE_BACKEND_UL);

    let inner = eth_ipv6_tcp(GUEST_A6, OVERLAY_VIP6, 443);
    let local = local_for([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xee], 8);
    let out = node.uplink_v6(&inner, VNI, &local);

    assert_eq!(
        out.action,
        Action::Redirect(8),
        "reforward redirects out this node's own uplink ifindex"
    );
    assert_eq!(
        out.tunnel,
        Some(TunnelEncap {
            vni: VNI,
            remote: REMOTE_BACKEND_UL
        }),
        "tunnel decision targets the Maglev-selected remote backend, same VNI"
    );
    assert_eq!(
        out.pkt, inner,
        "reforward never decaps or rewrites — byte-unchanged"
    );
}

// ─── Mechanism #4: WAN-edge local-deliver sentinel + genuine-miss drop (the security fix) ─────────

const UNROUTABLE_DST6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe,
]; // no ROUTES6 entry exists for this address anywhere

fn edge_local() -> Local {
    Local {
        uplink_ifindex: 11,
        uplink_mac: [0x07; 6],
        gateway_mac: [0x08; 6],
        underlay_ipv6: HOST_UNDERLAY6,
    }
}

/// A POST-decap `[InnerEth][IPv6][TCP]` frame `EXT_IP6 -> UNROUTABLE_DST6`. No ROUTES6 entry is ever
/// programmed for `UNROUTABLE_DST6` in these tests.
fn unroutable_inner6_frame() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv6(EXT_IP6, UNROUTABLE_DST6, 64)
        .tcp(40000, 443, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

/// Sentinel hit: this node is registered as the WAN edge, so a `ROUTES6` miss decaps-only + rewrites
/// the inner Ethernet for local-kernel hand-off (`Action::Pass`) instead of guest delivery.
#[test]
fn v6_wan_edge_sentinel_decaps_and_passes_to_kernel_on_routes6_miss() {
    let encapped = unroutable_inner6_frame();
    let mut node = SimNode::with_local(edge_local());
    node.maps.underlay.insert(
        HOST_UNDERLAY6, // == edge_local().underlay_ipv6
        UnderlayValue {
            vni: 0,
            tap_ifindex: UNDERLAY_LOCAL_DELIVER,
            guest_mac: [0; 6],
            _pad: [0; 2],
        },
    );

    let out = node.uplink_v6(&encapped, VNI, &edge_local());

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
    assert_eq!(
        &out.pkt[12..14],
        &[0x86, 0xdd],
        "inner ethertype = IPv6 (0x86DD)"
    );
    assert_eq!(
        out.pkt.len(),
        unroutable_inner6_frame().len(),
        "inner Eth rewritten in place, no resize (same shape as guest delivery)"
    );
}

/// Genuine miss: no `ROUTES6` entry for the dst AND this node is NOT the WAN edge (no
/// `UNDERLAY[LOCAL.underlay_ipv6]` entry at all). Must DROP — never PASS decapped overlay bytes into
/// this node's own kernel. **This is the P2 Task 4c security fix**: HEAD's hand-inlined
/// `v6_uplink_rx` fell through to `TC_ACT_OK` (pass) here.
#[test]
fn v6_genuine_routes6_miss_drops_not_passes() {
    let encapped = unroutable_inner6_frame();
    let mut node = SimNode::new(); // no UNDERLAY[Local.underlay_ipv6] entry at all

    let out = node.uplink_v6(&encapped, VNI, &edge_local());

    assert_eq!(
        out.action,
        Action::Drop,
        "a genuine v6 miss must drop, never pass, decapped overlay bytes"
    );
}

/// Genuine miss even when an `UNDERLAY[LOCAL.underlay_ipv6]` entry exists but is NOT the sentinel (an
/// ordinary local interface happens to share the node's own underlay identity) — only the exact
/// `UNDERLAY_LOCAL_DELIVER` tap_ifindex value means edge role.
#[test]
fn v6_routes6_miss_with_non_sentinel_local_underlay_entry_still_drops() {
    let encapped = unroutable_inner6_frame();
    let mut node = SimNode::with_local(edge_local());
    node.maps.underlay.insert(
        HOST_UNDERLAY6,
        UnderlayValue {
            vni: VNI,
            tap_ifindex: TAP, // a REAL tap ifindex, not the sentinel
            guest_mac: GUEST_MAC,
            _pad: [0; 2],
        },
    );

    let out = node.uplink_v6(&encapped, VNI, &edge_local());

    assert_eq!(
        out.action,
        Action::Drop,
        "a non-sentinel UNDERLAY[LOCAL.underlay_ipv6] entry must NOT be treated as edge role"
    );
}
