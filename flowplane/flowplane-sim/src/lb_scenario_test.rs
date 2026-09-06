//! East-West + North-South load-balancer coverage, driven end-to-end through the `Fabric` and the
//! REAL datapath core. This is the synthetic reproduction of the clab "LB packets dropped" failure
//! and its explicit-firewall fix — no clab, no root.
//!
//! Firewall model under test (matches `compilednic::apply` + the agent's `compiledToFw`): an INGRESS
//! rule's `cidr` matches the packet's **source** (k8s `from` semantics), `port` is the destination
//! port. LB is DSR — the inner dst stays the VIP — and the traffic's SOURCE is the external/remote
//! client. So a backend policy that only permits INTERNAL sources does NOT cover external N/S LB
//! traffic (its source is external) → dropped; a policy permitting the LB source (or any) → delivered.
//! Coverage proves LB flows IFF an explicit rule permits its source on the port.

use etherparse::PacketBuilder;
use flowplane_common::{LbBackend, LbKey, LbValue};
use flowplane_common::{Local, RouteValue};

use crate::compilednic::{apply, CompiledNic};
use crate::fabric::{Fabric, Outcome, Prog};
use crate::{MemMaps, SimNode};

// ---- addressing ----
const VNI: u32 = 100;
const HOSTB_UL: [u8; 16] = ul(0xbb);
const RELAY_UL: [u8; 16] = ul(0xcc);
const EDGE_UL: [u8; 16] = ul(0xaa);

const HOSTB_TAP: u32 = 42;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];

const WAN_VIP: [u8; 4] = [203, 0, 113, 50]; // N/S public VIP (edge, vni=0)
const WAN_SRC: [u8; 4] = [203, 0, 113, 9];
// v6 N/S public VIP (edge, vni=0). LB is keyed by the last-4 bytes (control-plane `last4`).
const WAN_VIP6: [u8; 16] = [
    0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xa8, 0xc8, 0x32,
];
const WAN_SRC6: [u8; 16] = [
    0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xa8, 0xc8, 0x09,
];
const OVERLAY_VIP: [u8; 4] = [10, 0, 100, 1]; // E/W overlay VIP (vni=100)
const GUEST_A: [u8; 4] = [10, 0, 0, 20]; // an internal E/W client (in 10.0.0.0/8)
                                         // hostB's own concrete backend overlay IP (distinct from any VIP): the real `INTERFACES` delivery
                                         // key for local LB-backend delivery is `(vni, backend's OWN overlay ip)`, never the VIP itself (DSR
                                         // keeps the inner dst as the VIP) -- see `flowplane_core::datapath::process_uplink`'s LB arm.
const BACKEND_OVERLAY_IP: [u8; 4] = [10, 0, 0, 181];

const fn ul(last: u8) -> [u8; 16] {
    [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last]
}

/// Left-justify a v4 addr into the 16-byte `LbBackend.overlay_ip` representation (`is_v6 == 0`).
const fn v4_in_16(ip: [u8; 4]) -> [u8; 16] {
    [
        ip[0], ip[1], ip[2], ip[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
}

fn local_for(underlay: [u8; 16], ifindex: u32) -> Local {
    Local {
        uplink_ifindex: ifindex,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: underlay,
    }
}

/// A full guest Ethernet frame `[Eth][IPv4][TCP]` src→dst on `dport`.
fn eth_ipv4_tcp(src: [u8; 4], dst: [u8; 4], dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(src, dst, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// A full guest Ethernet frame `[Eth(0x86DD)][IPv6][TCP]` src→dst on `dport`.
fn eth_ipv6_tcp(src: [u8; 16], dst: [u8; 16], dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv6(src, dst, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[]).unwrap();
    out
}

/// Standing in for "the packet already arrived at this node's uplink_rx" as an input fixture for
/// the `Prog::UplinkRx` tests below: under Geneve `collect_md` the kernel has already decapped by
/// the time a tcx ingress program runs, so the fixture the ingress-side entrypoints consume IS the
/// inner frame, unwrapped — no outer bytes to build (see `sim.rs`'s module doc). The VNI/remote
/// that used to be encoded in an outer header now ride entirely on `Fabric`'s `Prog`/`TunnelEncap`
/// plumbing instead.
fn encap_to(inner: &[u8]) -> Vec<u8> {
    inner.to_vec()
}

/// Parse a CompiledNIC firewall JSON snippet and apply it to `tap` on `maps`.
fn apply_fw(maps: &mut MemMaps, tap: u32, ingress_json: &str) {
    let json = format!(
        r#"{{"spec":{{"vni":100,"underlayRoute":"2001:db8::1","firewall":{{"ingress":{},"egress":[]}}}}}}"#,
        ingress_json
    );
    let c: CompiledNic = serde_json::from_str(&json).expect("parse fw json");
    apply(maps, &c, tap);
}

/// Ingress allow from ANY source on 443 — permits external N/S LB traffic.
fn allow_from_any_443() -> &'static str {
    r#"[{"cidr":"0.0.0.0/0","proto":"TCP","port":443,"action":"Allow"}]"#
}
/// Ingress allow only INTERNAL sources (10.0.0.0/8) on 443. Delivers E/W LB (internal guest source);
/// DROPS external N/S LB (its source is a public client, not in 10.0.0.0/8) — the clab reproduction.
fn allow_internal_443() -> &'static str {
    r#"[{"cidr":"10.0.0.0/8","proto":"TCP","port":443,"action":"Allow"}]"#
}
fn allow_all() -> &'static str {
    r#"[{"cidr":"0.0.0.0/0","action":"Allow"}]"#
}

/// Build a backend node (hostB): an `INTERFACES` local-delivery row for hostB's own concrete
/// backend overlay IP + mesh-replicated WAN-VIP LB (mirroring `edge_node()`'s config — a REAL
/// Maglev backend carries the same LB state every participating node does, via mesh gossip) +
/// optional overlay-LB self-registration. The WAN LB replication is what lets `hostB`'s OWN
/// `uplink_rx` recognize "I own this VIP" on ingress: WAN VIPs are anycast, not a guest's own
/// overlay IP, so they have no `ROUTES` self-route for the ingress delivery-target reconstruction to
/// find — `lb_select_forward` re-selecting itself (`be.node_vtep == local.underlay_ipv6`) and then
/// resolving the delivery tap via `INTERFACES[(vni, be.overlay_ip)]` is the ONLY mechanism that
/// resolves VIP delivery.
fn backend_node(with_overlay_lb: bool) -> SimNode {
    let mut n = SimNode::with_local(local_for(HOSTB_UL, 9));
    n.maps.add_iface(
        VNI,
        BACKEND_OVERLAY_IP,
        flowplane_common::IfaceValue {
            tap_ifindex: HOSTB_TAP,
            is_local: 1,
            underlay_ipv6: HOSTB_UL,
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    n.maps.lb.insert(
        LbKey {
            vni: 0,
            ipv4: WAN_VIP,
            port: 443,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 1,
            size: 1,
        },
    );
    n.maps.add_maglev(
        1,
        0,
        LbBackend {
            node_vtep: HOSTB_UL,
            overlay_ip: v4_in_16(BACKEND_OVERLAY_IP),
            vni: VNI,
            is_v6: 0,
            _pad: [0; 3],
        },
    );
    if with_overlay_lb {
        n.maps.lb.insert(
            LbKey {
                vni: VNI,
                ipv4: OVERLAY_VIP,
                port: 443,
                proto: 6,
                _pad: 0,
            },
            LbValue {
                table_id: 2,
                size: 1,
            },
        );
        n.maps.add_maglev(
            2,
            0,
            LbBackend {
                node_vtep: HOSTB_UL,
                overlay_ip: v4_in_16(BACKEND_OVERLAY_IP),
                vni: VNI,
                is_v6: 0,
                _pad: [0; 3],
            },
        );
    }
    n
}

/// Edge node with the WAN-VIP LB (vni=0) → hostB.
fn edge_node() -> SimNode {
    let mut e = SimNode::with_local(local_for(EDGE_UL, 7));
    e.maps.lb.insert(
        LbKey {
            vni: 0,
            ipv4: WAN_VIP,
            port: 443,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 1,
            size: 1,
        },
    );
    e.maps.add_maglev(
        1,
        0,
        LbBackend {
            node_vtep: HOSTB_UL,
            overlay_ip: v4_in_16(BACKEND_OVERLAY_IP),
            vni: VNI,
            is_v6: 0,
            _pad: [0; 3],
        },
    );
    e
}

// ============================ North-South ============================

#[test]
fn ns_lb_delivered_with_vip_allow() {
    let mut fab = Fabric::new();
    fab.add_node("edge", edge_node());
    let mut b = backend_node(false);
    apply_fw(&mut b.maps, HOSTB_TAP, allow_from_any_443());
    fab.add_node("hostB", b);
    fab.route(HOSTB_UL, "hostB");

    let frame = eth_ipv4_tcp(WAN_SRC, WAN_VIP, 443);
    let t = fab.deliver("edge", Prog::WanRx, &frame);
    assert_eq!(
        t.outcome,
        Outcome::Delivered {
            node: "hostB",
            tap: HOSTB_TAP
        },
        "hops: {}",
        t.hops.len()
    );
    assert_eq!(t.hops.len(), 2, "edge wan_rx -> hostB uplink");
}

#[test]
fn ns_lb_dropped_when_policy_misses_vip() {
    // THE CLAB REPRODUCTION: the backend's policy only permits INTERNAL sources (10.0.0.0/8) on 443,
    // but N/S LB traffic arrives with an EXTERNAL source (a public client) — so it is denied.
    let mut fab = Fabric::new();
    fab.add_node("edge", edge_node());
    let mut b = backend_node(false);
    apply_fw(&mut b.maps, HOSTB_TAP, allow_internal_443());
    fab.add_node("hostB", b);
    fab.route(HOSTB_UL, "hostB");

    let frame = eth_ipv4_tcp(WAN_SRC, WAN_VIP, 443);
    let t = fab.deliver("edge", Prog::WanRx, &frame);
    assert_eq!(
        t.outcome,
        Outcome::Dropped { node: "hostB" },
        "external-sourced LB traffic must be dropped by a policy that only permits internal sources"
    );
}

#[test]
fn ns_lb_delivered_unpolicied_allow_all() {
    let mut fab = Fabric::new();
    fab.add_node("edge", edge_node());
    let mut b = backend_node(false);
    apply_fw(&mut b.maps, HOSTB_TAP, allow_all()); // control-plane default-allow
    fab.add_node("hostB", b);
    fab.route(HOSTB_UL, "hostB");

    let frame = eth_ipv4_tcp(WAN_SRC, WAN_VIP, 443);
    let t = fab.deliver("edge", Prog::WanRx, &frame);
    assert_eq!(
        t.outcome,
        Outcome::Delivered {
            node: "hostB",
            tap: HOSTB_TAP
        }
    );
}

// ============================ East-West ============================

#[test]
fn ew_lb_reforward_delivered() {
    // guestA -> OVERLAY_VIP; origin encaps to the LB relay underlay; relay Maglev-selects hostB
    // (remote) and reforwards; hostB delivers. Trace shows the reforward hop.
    let mut fab = Fabric::new();

    let mut relay = SimNode::with_local(local_for(RELAY_UL, 8));
    // NOTE: no `relay.maps.underlay` self-entry needed — the relay's own underlay is never looked
    // up: the reforward decision is `be.node_vtep == local.underlay_ipv6` (RELAY_UL != HOSTB_UL, so
    // remote), and `reforward()` redirects out `local.uplink_ifindex` directly, no map lookup.
    relay.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: OVERLAY_VIP,
            port: 443,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 2,
            size: 1,
        },
    );
    // Mesh-gossiped copy of hostB's Maglev slot: same backend identity (node_vtep + overlay_ip) as
    // `backend_node(true)`'s own table-2 slot, so hostB's self-reselection after the reforward hits
    // the SAME `INTERFACES` row.
    relay.maps.add_maglev(
        2,
        0,
        LbBackend {
            node_vtep: HOSTB_UL,
            overlay_ip: v4_in_16(BACKEND_OVERLAY_IP),
            vni: VNI,
            is_v6: 0,
            _pad: [0; 3],
        },
    );
    fab.add_node("relay", relay);

    let mut b = backend_node(true); // hostB re-selects itself (DSR)
    apply_fw(&mut b.maps, HOSTB_TAP, allow_internal_443());
    fab.add_node("hostB", b);

    fab.route(RELAY_UL, "relay");
    fab.route(HOSTB_UL, "hostB");

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let encapped = encap_to(&inner);
    let t = fab.deliver("relay", Prog::UplinkRx(VNI), &encapped);
    assert_eq!(
        t.outcome,
        Outcome::Delivered {
            node: "hostB",
            tap: HOSTB_TAP
        },
        "hops: {}",
        t.hops.len()
    );
    assert_eq!(t.hops.len(), 2, "relay reforward -> hostB deliver");
}

#[test]
fn ew_lb_local_deliver_no_reforward() {
    // Relay node IS the backend: single uplink_rx, LB selects self, no reforward hop.
    let mut fab = Fabric::new();
    let mut b = backend_node(true);
    apply_fw(&mut b.maps, HOSTB_TAP, allow_internal_443());
    fab.add_node("hostB", b);
    fab.route(HOSTB_UL, "hostB");

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let encapped = encap_to(&inner);
    let t = fab.deliver("hostB", Prog::UplinkRx(VNI), &encapped);
    assert_eq!(
        t.outcome,
        Outcome::Delivered {
            node: "hostB",
            tap: HOSTB_TAP
        }
    );
    assert_eq!(t.hops.len(), 1, "single uplink, no reforward");
}

#[test]
fn ew_lb_reforward_converges_no_loop() {
    // Maglev is deterministic (relay and backend agree), so the reforward converges — the hop cap
    // is never hit. Same setup as reforward_delivered; assert NOT LoopHalted.
    let mut fab = Fabric::new();
    let mut relay = SimNode::with_local(local_for(RELAY_UL, 8));
    // NOTE: no `relay.maps.underlay` self-entry needed — the relay's own underlay is never looked
    // up: the reforward decision is `be.node_vtep == local.underlay_ipv6` (RELAY_UL != HOSTB_UL, so
    // remote), and `reforward()` redirects out `local.uplink_ifindex` directly, no map lookup.
    relay.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: OVERLAY_VIP,
            port: 443,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 2,
            size: 1,
        },
    );
    // Mesh-gossiped copy of hostB's Maglev slot: same backend identity (node_vtep + overlay_ip) as
    // `backend_node(true)`'s own table-2 slot, so hostB's self-reselection after the reforward hits
    // the SAME `INTERFACES` row.
    relay.maps.add_maglev(
        2,
        0,
        LbBackend {
            node_vtep: HOSTB_UL,
            overlay_ip: v4_in_16(BACKEND_OVERLAY_IP),
            vni: VNI,
            is_v6: 0,
            _pad: [0; 3],
        },
    );
    fab.add_node("relay", relay);
    let mut b = backend_node(true);
    apply_fw(&mut b.maps, HOSTB_TAP, allow_all());
    fab.add_node("hostB", b);
    fab.route(RELAY_UL, "relay");
    fab.route(HOSTB_UL, "hostB");

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let encapped = encap_to(&inner);
    let t = fab.deliver("relay", Prog::UplinkRx(VNI), &encapped);
    assert_ne!(
        t.outcome,
        Outcome::LoopHalted,
        "deterministic Maglev must converge"
    );
    assert!(matches!(t.outcome, Outcome::Delivered { .. }));
}

#[test]
fn ew_lb_anycast_delivered_with_policy() {
    // Model A: the E/W VIP is an anycast route → guest encaps straight to the backend /128.
    // The backend has NO LB maps; uplink_rx base-delivers after the ingress firewall. Internal
    // source (10.0.0.0/8) is permitted on 443, so it is delivered.
    let mut fab = Fabric::new();
    let mut b = backend_node(false);
    apply_fw(&mut b.maps, HOSTB_TAP, allow_internal_443());
    // The anycast VIP's ingress delivery-target marker (`resolve_uplink_target`'s mechanism #1):
    // hostB's own control plane self-registers an `INTERFACES[(vni, VIP)]` local-delivery entry for
    // the VIP it serves (distinct from the LB path — no `LB`/`MAGLEV` maps here), the same way a
    // guest's own overlay IP entry does.
    b.maps.add_iface(
        VNI,
        OVERLAY_VIP,
        flowplane_common::IfaceValue {
            tap_ifindex: HOSTB_TAP,
            is_local: 1,
            underlay_ipv6: [0; 16],
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    fab.add_node("hostB", b);
    fab.route(HOSTB_UL, "hostB");

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let encapped = encap_to(&inner);
    let t = fab.deliver("hostB", Prog::UplinkRx(VNI), &encapped);
    assert_eq!(
        t.outcome,
        Outcome::Delivered {
            node: "hostB",
            tap: HOSTB_TAP
        },
        "hops: {}",
        t.hops.len()
    );
    assert_eq!(
        t.hops.len(),
        1,
        "single uplink base-deliver, no maglev/reforward"
    );
}

#[test]
fn ew_lb_anycast_dropped_without_policy() {
    // Same anycast delivery, but the backend has a policy that does NOT permit the guest source
    // (only 1.2.3.0/24 on 443). Deny-by-default drops it — LB membership grants no permission.
    let mut fab = Fabric::new();
    let mut b = backend_node(false);
    apply_fw(
        &mut b.maps,
        HOSTB_TAP,
        r#"[{"cidr":"1.2.3.0/24","proto":"TCP","port":443,"action":"Allow"}]"#,
    );
    // Same anycast ROUTE self-registration as `ew_lb_anycast_delivered_with_policy` — without it,
    // this test would (mis-)pass via a ROUTES-miss drop instead of the firewall drop it claims to
    // exercise.
    b.maps.add_route4(
        VNI,
        OVERLAY_VIP,
        RouteValue {
            nexthop_vni: VNI,
            nexthop_ipv6: HOSTB_UL,
            is_external: 0,
            _pad: [0; 3],
        },
    );
    fab.add_node("hostB", b);
    fab.route(HOSTB_UL, "hostB");

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let encapped = encap_to(&inner);
    let t = fab.deliver("hostB", Prog::UplinkRx(VNI), &encapped);
    assert_eq!(
        t.outcome,
        Outcome::Dropped { node: "hostB" },
        "LB delivery must be dropped when no FirewallPolicy admits the source"
    );
}

// ============================ North-South (v6 VIP) ============================

/// Direct edge `wan_rx` test for a v6 WAN VIP. We assert on the EDGE hop only — not a full
/// `Prog::WanRx → Delivered` Fabric trace — because the sim's Fabric/`SimNode::uplink` assumes a
/// v4 inner and does NOT yet model v6-inner backend delivery (see fabric.rs:104-106). This proves
/// the FIRST behavioral DSR change (B6): `wan_rx` now Geneve-dispatches with a VIP option — the
/// edge captures the ORIGINAL VIP into a `DsrOpt` (from the packet's dst BEFORE rewriting), rewrites
/// the inner dst to the backend's OWN overlay IP (the guest only accepts its own IP), and leaves the
/// inner SRC as the real client (so the backend can key its DSR conntrack on the real client flow).
#[test]
fn ns_lb_v6_wan_rx_dsr_encode() {
    use flowplane_common::DsrOpt;
    use flowplane_core::encap::TunnelEncap;
    use flowplane_core::encap::ETH_LEN;
    use flowplane_core::pkt::Action;

    const BE_IP6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x61];
    let mut e = SimNode::with_local(local_for(EDGE_UL, 7));
    let last4 = [WAN_VIP6[12], WAN_VIP6[13], WAN_VIP6[14], WAN_VIP6[15]];
    e.maps.lb.insert(
        LbKey {
            vni: 0,
            ipv4: last4,
            port: 443,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 1,
            size: 1,
        },
    );
    e.maps.add_maglev(
        1,
        0,
        LbBackend {
            node_vtep: HOSTB_UL,
            overlay_ip: BE_IP6,
            vni: VNI,
            is_v6: 1,
            _pad: [0; 3],
        },
    );

    let frame = eth_ipv6_tcp(WAN_SRC6, WAN_VIP6, 443);
    let out = e.wan_rx(&frame);

    assert_eq!(
        out.action,
        Action::Redirect(7),
        "edge must redirect out its uplink ifindex (EDGE_UL local ifindex=7)"
    );
    assert_eq!(
        out.tunnel,
        Some(TunnelEncap {
            vni: VNI,
            remote: HOSTB_UL,
        }),
        "tunnel decision targets the Maglev-selected backend at its OWN vni"
    );
    assert_eq!(
        out.dsr,
        Some(DsrOpt {
            family: 1,
            _pad: 0,
            port: 443,
            vip: WAN_VIP6
        }),
        "wan_rx carries a DSR option with the ORIGINAL VIP"
    );
    assert_eq!(
        &out.pkt[ETH_LEN + 24..ETH_LEN + 40],
        &BE_IP6,
        "inner v6 dst rewritten -> backend overlay"
    );
    assert_eq!(
        &out.pkt[ETH_LEN + 8..ETH_LEN + 24],
        &WAN_SRC6,
        "inner v6 src unchanged (client)"
    );

    // Negative sub-case: a non-VIP v6 dst (last-4 != VIP key) → Pass, no encap, no rewrite.
    let non_vip = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 5];
    let miss = eth_ipv6_tcp(WAN_SRC6, non_vip, 443);
    let out2 = e.wan_rx(&miss);
    assert_eq!(out2.action, Action::Pass, "non-VIP v6 dst must Pass");
    assert_eq!(out2.tunnel, None, "non-VIP dst emits no tunnel decision");
    assert_eq!(out2.dsr, None, "non-VIP dst emits no DSR option");
    assert_eq!(out2.pkt, miss, "non-VIP frame is byte-for-byte unchanged");
}

/// v4 mirror of [`ns_lb_v6_wan_rx_dsr_encode`]: the edge captures the ORIGINAL v4 VIP into a
/// `DsrOpt { family: 0, .. }` (vip left-justified in the 16-byte field) and rewrites the inner v4
/// dst to the backend's own overlay IP, using the existing `vip_dnat_rewrite` v4 helper's checksum
/// fixups (reused from the floating-IP DNAT arm).
#[test]
fn ns_lb_v4_wan_rx_dsr_encode() {
    use flowplane_common::DsrOpt;
    use flowplane_core::encap::TunnelEncap;
    use flowplane_core::encap::ETH_LEN;
    use flowplane_core::pkt::Action;

    const BE_IP4: [u8; 4] = [10, 0, 0, 181];
    let edge = edge_node();

    let frame = eth_ipv4_tcp(WAN_SRC, WAN_VIP, 443);
    let out = edge.wan_rx(&frame);

    assert_eq!(
        out.action,
        Action::Redirect(7),
        "edge must redirect out its uplink ifindex (EDGE_UL local ifindex=7)"
    );
    let mut vip16 = [0u8; 16];
    vip16[0..4].copy_from_slice(&WAN_VIP);
    assert_eq!(
        out.tunnel,
        Some(TunnelEncap {
            vni: VNI,
            remote: HOSTB_UL,
        }),
        "tunnel decision targets the Maglev-selected backend at its OWN vni"
    );
    assert_eq!(
        out.dsr,
        Some(DsrOpt {
            family: 0,
            _pad: 0,
            port: 443,
            vip: vip16
        }),
        "wan_rx carries a DSR option with the ORIGINAL v4 VIP left-justified in the 16-byte field"
    );
    assert_eq!(
        &out.pkt[ETH_LEN + 16..ETH_LEN + 20],
        &BE_IP4,
        "inner v4 dst rewritten -> backend overlay"
    );
    assert_eq!(
        &out.pkt[ETH_LEN + 12..ETH_LEN + 16],
        &WAN_SRC,
        "inner v4 src unchanged (client)"
    );
}

// ================= Local LB-backend delivery: distinct taps per backend =================
//
// Reproduces (as a regression test) the delivery-collapse bug: the OLD LB local-backend arm
// resolved the selected backend via `UNDERLAY[backend_underlay]` — a single per-NODE tap — so
// every backend hosted on the SAME node collapsed onto that one tap, no matter which backend
// Maglev actually picked. The FIX makes `LbBackend` self-describing: local iff
// `be.node_vtep == in_.local.underlay_ipv6`, and the delivery tap is then resolved per-BACKEND
// via `INTERFACES[(vni, overlay_ip)]` (v4) / `INTERFACES6[(vni, overlay_ip)]` (v6) — so two
// backends on one node, with distinct overlay IPs, now reach their OWN distinct taps.

/// Install an ingress ALLOW rule on `tap` for TCP -> ANY dst : 443 (v6 firewall). Mirrors
/// `ns_scenario_v6_test.rs::allow_tcp6`, but wildcards `dst_ip`/`dst_mask` (this file's `apply_fw`
/// v4 helper — `allow_from_any_443` — is source-wildcarded, dest-agnostic; the v6 mirror needs the
/// same shape since the LB/DSR delivery keeps the inner dst as the VIP, not either backend's own
/// overlay IP). No `apply6`/`compilednic` v6 helper exists in this sim yet (checked: only a v4
/// `apply()` — see `compilednic.rs`), so this seeds `FW_META6`/`FW_RULES6` directly, the same way
/// `ns_scenario_v6_test.rs` and `firewall_test.rs` do.
fn apply_fw6(maps: &mut MemMaps, tap: u32, port: u16) {
    maps.fw_meta6.insert(
        tap,
        flowplane_common::FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    maps.fw_rules6.insert(
        (tap, 0),
        flowplane_common::FwRule6 {
            src_ip: [0; 16],
            src_mask: [0; 16],
            dst_ip: [0; 16],
            dst_mask: [0; 16],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: port,
            dst_port_max: port,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: flowplane_common::FW_ACTION_ACCEPT,
            direction: flowplane_common::FW_DIR_INGRESS,
            enabled: 1,
        },
    );
}

#[test]
fn ns_lb_two_backends_one_node_deliver_to_distinct_taps_v4() {
    use flowplane_common::{IfaceValue, LbBackend, LbKey, LbValue, MaglevKey};
    use flowplane_core::pkt::Action;

    const BE1_IP: [u8; 4] = [10, 0, 0, 61];
    const BE2_IP: [u8; 4] = [10, 0, 0, 62];
    const BE1_TAP: u32 = 61;
    const BE2_TAP: u32 = 62;

    let mut n = SimNode::with_local(local_for(HOSTB_UL, 9));
    n.maps.add_iface(
        VNI,
        BE1_IP,
        IfaceValue {
            tap_ifindex: BE1_TAP,
            is_local: 1,
            underlay_ipv6: HOSTB_UL,
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    n.maps.add_iface(
        VNI,
        BE2_IP,
        IfaceValue {
            tap_ifindex: BE2_TAP,
            is_local: 1,
            underlay_ipv6: HOSTB_UL,
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    apply_fw(&mut n.maps, BE1_TAP, allow_from_any_443());
    apply_fw(&mut n.maps, BE2_TAP, allow_from_any_443());

    n.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: OVERLAY_VIP,
            port: 443,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 7,
            size: 2,
        },
    );
    let mk = |ip: [u8; 4]| LbBackend {
        node_vtep: HOSTB_UL,
        overlay_ip: [
            ip[0], ip[1], ip[2], ip[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        vni: VNI,
        is_v6: 0,
        _pad: [0; 3],
    };
    n.maps.maglev.insert(
        MaglevKey {
            table_id: 7,
            slot: 0,
        },
        mk(BE1_IP),
    );
    n.maps.maglev.insert(
        MaglevKey {
            table_id: 7,
            slot: 1,
        },
        mk(BE2_IP),
    );

    let mut seen_taps = std::collections::HashSet::new();
    for src in [[10u8, 0, 9, 1], [10, 0, 9, 2], [10, 0, 9, 3], [10, 0, 9, 4]] {
        let inner = eth_ipv4_tcp(src, OVERLAY_VIP, 443);
        let out = n.uplink(&inner, VNI, &local_for(HOSTB_UL, 9));
        if let Action::Redirect(tap) = out.action {
            seen_taps.insert(tap);
        }
    }
    assert!(
        seen_taps.contains(&BE1_TAP) && seen_taps.contains(&BE2_TAP),
        "both same-node backends must be reachable (got {seen_taps:?})"
    );
}

#[test]
fn ns_lb_two_backends_one_node_deliver_to_distinct_taps_v6() {
    use flowplane_common::{IfaceValue, LbBackend, LbKey, LbValue, MaglevKey};
    use flowplane_core::pkt::Action;

    const BE1_IP6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x61];
    const BE2_IP6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x62];
    const BE1_TAP: u32 = 61;
    const BE2_TAP: u32 = 62;
    let vip6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 100, 1];
    let vip_last4 = [vip6[12], vip6[13], vip6[14], vip6[15]];

    let mut n = SimNode::with_local(local_for(HOSTB_UL, 9));
    for (ip6, tap) in [(BE1_IP6, BE1_TAP), (BE2_IP6, BE2_TAP)] {
        n.maps.add_iface6(
            VNI,
            ip6,
            IfaceValue {
                tap_ifindex: tap,
                is_local: 1,
                underlay_ipv6: HOSTB_UL,
                guest_mac: GUEST_MAC,
                peer_capable: 0,
                _pad: [0; 1],
            },
        );
        apply_fw6(&mut n.maps, tap, 443);
    }
    n.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: vip_last4,
            port: 443,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 8,
            size: 2,
        },
    );
    let mk = |ip6: [u8; 16]| LbBackend {
        node_vtep: HOSTB_UL,
        overlay_ip: ip6,
        vni: VNI,
        is_v6: 1,
        _pad: [0; 3],
    };
    n.maps.maglev.insert(
        MaglevKey {
            table_id: 8,
            slot: 0,
        },
        mk(BE1_IP6),
    );
    n.maps.maglev.insert(
        MaglevKey {
            table_id: 8,
            slot: 1,
        },
        mk(BE2_IP6),
    );

    let mut seen_taps = std::collections::HashSet::new();
    for last in [1u8, 2, 3, 4] {
        let mut src6 = [0x20u8, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        src6[15] = last;
        let inner = eth_ipv6_tcp(src6, vip6, 443);
        let out = n.uplink_v6(&inner, VNI, &local_for(HOSTB_UL, 9));
        if let Action::Redirect(tap) = out.action {
            seen_taps.insert(tap);
        }
    }
    assert!(
        seen_taps.contains(&BE1_TAP) && seen_taps.contains(&BE2_TAP),
        "both same-node v6 backends must be reachable (got {seen_taps:?})"
    );
}
