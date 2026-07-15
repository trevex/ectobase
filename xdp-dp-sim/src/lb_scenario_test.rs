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
use xdp_dp_common::{LbKey, LbValue, MaglevKey};
use xdp_dp_common::{Local, UnderlayValue};
use xdp_dp_core::encap::EncapParams;

use crate::compilednic::{apply, CompiledNic};
use crate::fabric::{Fabric, Outcome, Prog};
use crate::{MemMaps, SimNode};

// ---- addressing ----
const VNI: u32 = 100;
const HOSTB_UL: [u8; 16] = ul(0xbb);
const RELAY_UL: [u8; 16] = ul(0xcc);
const EDGE_UL: [u8; 16] = ul(0xaa);
const HOSTA_UL: [u8; 16] = ul(0xdd);

const HOSTB_TAP: u32 = 42;
const RELAY_TAP: u32 = 43;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];

const WAN_VIP: [u8; 4] = [203, 0, 113, 50]; // N/S public VIP (edge, vni=0)
const WAN_SRC: [u8; 4] = [203, 0, 113, 9];
const OVERLAY_VIP: [u8; 4] = [10, 0, 100, 1]; // E/W overlay VIP (vni=100)
const GUEST_A: [u8; 4] = [10, 0, 0, 20]; // an internal E/W client (in 10.0.0.0/8)

const fn ul(last: u8) -> [u8; 16] {
    [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last]
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

/// Encapsulate a full inner Eth+IPv4 frame IP-in-IPv6 toward `dst_ul` from `src_ul` (the fabric
/// wire format), mirroring a guest_tx / relay-origin encap.
fn encap_to(inner: &[u8], src_ul: [u8; 16], dst_ul: [u8; 16]) -> Vec<u8> {
    let node = SimNode::new();
    node.edge_encap(
        inner,
        EncapParams {
            gateway_mac: [1; 6],
            uplink_mac: [2; 6],
            uplink_ifindex: 7,
            src_underlay: src_ul,
            nexthop_ipv6: dst_ul,
            inner_len: 0,
            inner_proto: 4,
        },
    )
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

/// Build a backend node (hostB): UNDERLAY self-entry + optional overlay-LB self-registration.
fn backend_node(with_overlay_lb: bool) -> SimNode {
    let mut n = SimNode::with_local(local_for(HOSTB_UL, 9));
    n.maps.underlay.insert(
        HOSTB_UL,
        UnderlayValue {
            vni: VNI,
            tap_ifindex: HOSTB_TAP,
            guest_mac: GUEST_MAC,
            _pad: [0; 2],
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
        n.maps.maglev.insert(
            MaglevKey {
                table_id: 2,
                slot: 0,
            },
            HOSTB_UL,
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
    e.maps.maglev.insert(
        MaglevKey {
            table_id: 1,
            slot: 0,
        },
        HOSTB_UL,
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
    relay.maps.underlay.insert(
        RELAY_UL,
        UnderlayValue {
            vni: VNI,
            tap_ifindex: RELAY_TAP,
            guest_mac: [0; 6],
            _pad: [0; 2],
        },
    );
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
    relay.maps.maglev.insert(
        MaglevKey {
            table_id: 2,
            slot: 0,
        },
        HOSTB_UL,
    );
    fab.add_node("relay", relay);

    let mut b = backend_node(true); // hostB re-selects itself (DSR)
    apply_fw(&mut b.maps, HOSTB_TAP, allow_internal_443());
    fab.add_node("hostB", b);

    fab.route(RELAY_UL, "relay");
    fab.route(HOSTB_UL, "hostB");

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let encapped = encap_to(&inner, HOSTA_UL, RELAY_UL);
    let t = fab.deliver("relay", Prog::UplinkRx, &encapped);
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
    let encapped = encap_to(&inner, HOSTA_UL, HOSTB_UL);
    let t = fab.deliver("hostB", Prog::UplinkRx, &encapped);
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
    relay.maps.underlay.insert(
        RELAY_UL,
        UnderlayValue {
            vni: VNI,
            tap_ifindex: RELAY_TAP,
            guest_mac: [0; 6],
            _pad: [0; 2],
        },
    );
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
    relay.maps.maglev.insert(
        MaglevKey {
            table_id: 2,
            slot: 0,
        },
        HOSTB_UL,
    );
    fab.add_node("relay", relay);
    let mut b = backend_node(true);
    apply_fw(&mut b.maps, HOSTB_TAP, allow_all());
    fab.add_node("hostB", b);
    fab.route(RELAY_UL, "relay");
    fab.route(HOSTB_UL, "hostB");

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let encapped = encap_to(&inner, HOSTA_UL, RELAY_UL);
    let t = fab.deliver("relay", Prog::UplinkRx, &encapped);
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
    fab.add_node("hostB", b);
    fab.route(HOSTB_UL, "hostB");

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let encapped = encap_to(&inner, HOSTA_UL, HOSTB_UL);
    let t = fab.deliver("hostB", Prog::UplinkRx, &encapped);
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
    fab.add_node("hostB", b);
    fab.route(HOSTB_UL, "hostB");

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let encapped = encap_to(&inner, HOSTA_UL, HOSTB_UL);
    let t = fab.deliver("hostB", Prog::UplinkRx, &encapped);
    assert_eq!(
        t.outcome,
        Outcome::Dropped { node: "hostB" },
        "LB delivery must be dropped when no NetworkPolicy admits the source"
    );
}
