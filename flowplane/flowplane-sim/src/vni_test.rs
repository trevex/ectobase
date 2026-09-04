//! Conformance tests for VNI isolation on the guest-egress routing path.
//!
//! These tests drive the REAL `flowplane_core::egress::route4` (via the full `SimNode::guest_tx`
//! compose) over in-memory `MemMaps` / `VecPkt`.  Nothing is reimplemented — the assertions guard
//! byte-identical production behaviour: a route programmed under VNI-B is invisible to a lookup
//! under VNI-A (the `route4_get` implementation in `MemMaps` filters by `r.vni == vni`).
//!
//! # Topology
//! - Destination D (`10.1.1.1`) is routed only under VNI-B (200).
//! - Guest A lives in VNI-A (100); Guest B lives in VNI-B (200).
//!
//! # Cases
//! - **Isolation (VNI-A → D):** route lookup MISSES → `guest_tx` returns `Action::Pass`.
//! - **Resolution (VNI-B → D):** route lookup HITS → `guest_tx` returns `Action::Redirect` (encap).
//!
//! The two outcomes MUST differ — that contrast is the actual isolation assertion.

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, Local, PortMeta, RouteValue, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
};
use flowplane_core::pkt::Action;

use crate::SimNode;

// ─── fixed test topology ──────────────────────────────────────────────────────

/// VNI that owns the route to DEST_IP.
const VNI_B: u32 = 200;
/// VNI that does NOT own the route to DEST_IP — isolation is enforced at this VNI.
const VNI_A: u32 = 100;

/// The destination address programmed only under VNI_B.
const DEST_IP: [u8; 4] = [10, 1, 1, 1];

/// Underlay nexthop for the route in VNI_B (any non-local IPv6 — drives the Encap branch).
const NEXTHOP: [u8; 16] = [
    0x20, 0x01, 0xdb, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];

/// Synthetic egress-firewall ifindex for the two guests.
const SRC_IFINDEX_A: u32 = 10;
const SRC_IFINDEX_B: u32 = 11;

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Build a minimal guest Ethernet frame `[Eth(14)][IPv4][UDP]` from `src_ip` to `DEST_IP`.
fn guest_udp_frame(src_ip: [u8; 4]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
        .ipv4(src_ip, DEST_IP, 64)
        .udp(12345, 53);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

/// Install a wildcard egress ALLOW rule on `ifindex` so the firewall is not the test variable.
fn allow_egress(node: &mut SimNode, ifindex: u32) {
    node.maps.fw_meta.insert(
        ifindex,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps.fw_rules.insert(
        (ifindex, 0),
        FwRule {
            src_ip: [0; 4],
            src_mask: [0; 4],
            dst_ip: [0; 4],
            dst_mask: [0; 4],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 0,
            dst_port_max: 65535,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 0, // 0 = any protocol (mirrors fw_rule_matches: proto 0 matches all)
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_EGRESS,
            enabled: 1,
        },
    );
}

/// Build a `PortMeta` for a guest in `vni` with a generic underlay identity.
fn port_meta(vni: u32, guest_ip: [u8; 4]) -> PortMeta {
    PortMeta {
        vni,
        guest_ipv4: guest_ip,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: [0xaa; 6],
        l3: 0,
        _pad: [0; 1],
        underlay_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

/// Configure `node.local` so the `deliver` path can take the Encap branch.
fn configure_local(node: &mut SimNode) {
    node.maps.local = Some(Local {
        uplink_ifindex: 7,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
    });
    // No underlay entry for NEXTHOP → deliver falls through to Deliver::Encap (uplink path).
}

// ─── (a) VNI isolation: route miss in the wrong VNI ──────────────────────────

/// A guest in VNI-A sends to DEST_IP, which is routed only under VNI-B.
/// The `route4` lookup for VNI-A MISSES (no route) → `guest_tx` returns `Action::Pass`.
/// This is the isolation property: VNI-B's routing table is opaque to VNI-A.
#[test]
fn vni_isolation_route_miss_for_wrong_vni_returns_pass() {
    let guest_a_ip: [u8; 4] = [10, 0, 1, 10];

    let mut node = SimNode::new();
    configure_local(&mut node);
    allow_egress(&mut node, SRC_IFINDEX_A);

    // Program DEST_IP ONLY under VNI_B — VNI_A has no route to DEST_IP.
    node.maps.add_route4(
        VNI_B,
        DEST_IP,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: NEXTHOP,
            is_external: 0,
            _pad: [0; 3],
        },
    );

    node.src_ifindex = SRC_IFINDEX_A;
    let frame = guest_udp_frame(guest_a_ip);
    let meta = port_meta(VNI_A, guest_a_ip);
    let out = node.guest_tx(&frame, &meta);

    // Route lookup for VNI_A returns None → guest_tx returns Action::Pass (step 3 in sim.rs).
    assert!(
        matches!(out.action, Action::Pass),
        "VNI-A guest sending to DEST_IP must get Action::Pass (route miss) — VNI isolation broken; got {:?}",
        out.action
    );
}

// ─── (b) Same VNI resolves: route hit in the correct VNI ─────────────────────

/// A guest in VNI-B sends to DEST_IP, which is routed under VNI-B.
/// The `route4` lookup for VNI-B HITS → `guest_tx` takes the Encap path →
/// `Action::Redirect(uplink_ifindex)`.
#[test]
fn vni_same_vni_route_hit_delivers_via_encap() {
    let guest_b_ip: [u8; 4] = [10, 0, 2, 20];

    let mut node = SimNode::new();
    configure_local(&mut node);
    allow_egress(&mut node, SRC_IFINDEX_B);

    // Program DEST_IP under VNI_B.
    node.maps.add_route4(
        VNI_B,
        DEST_IP,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: NEXTHOP,
            is_external: 0,
            _pad: [0; 3],
        },
    );

    node.src_ifindex = SRC_IFINDEX_B;
    let frame = guest_udp_frame(guest_b_ip);
    let meta = port_meta(VNI_B, guest_b_ip);
    let out = node.guest_tx(&frame, &meta);

    // Route lookup for VNI_B returns the entry → deliver takes Encap path → Redirect to uplink.
    const UPLINK_IFINDEX: u32 = 7; // matches configure_local
    assert!(
        matches!(out.action, Action::Redirect(UPLINK_IFINDEX)),
        "VNI-B guest sending to DEST_IP must get Action::Redirect({UPLINK_IFINDEX}) (encap); got {:?}",
        out.action
    );
}

// ─── (c) The contrast: same destination, different VNI, different outcome ─────

/// Core isolation assertion: the SAME destination address `DEST_IP` yields DIFFERENT actions
/// from `guest_tx` depending solely on the sender's VNI.  This is a single test that asserts
/// both outcomes together and confirms they are not equal — making it impossible for a
/// tautological equality to accidentally pass.
#[test]
fn vni_isolation_same_dst_different_vni_yields_different_actions() {
    let guest_a_ip: [u8; 4] = [10, 0, 1, 10];
    let guest_b_ip: [u8; 4] = [10, 0, 2, 20];

    let mut node = SimNode::new();
    configure_local(&mut node);
    allow_egress(&mut node, SRC_IFINDEX_A);
    allow_egress(&mut node, SRC_IFINDEX_B);

    // DEST_IP routed ONLY under VNI_B.
    node.maps.add_route4(
        VNI_B,
        DEST_IP,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: NEXTHOP,
            is_external: 0,
            _pad: [0; 3],
        },
    );

    // ── VNI-A: expect Pass (miss) ────────────────────────────────────────────
    node.src_ifindex = SRC_IFINDEX_A;
    let out_a = node.guest_tx(&guest_udp_frame(guest_a_ip), &port_meta(VNI_A, guest_a_ip));
    assert!(
        matches!(out_a.action, Action::Pass),
        "VNI-A → DEST_IP must be Action::Pass (route miss); got {:?}",
        out_a.action
    );

    // ── VNI-B: expect Redirect (encap hit) ──────────────────────────────────
    node.src_ifindex = SRC_IFINDEX_B;
    let out_b = node.guest_tx(&guest_udp_frame(guest_b_ip), &port_meta(VNI_B, guest_b_ip));
    const UPLINK_IFINDEX: u32 = 7;
    assert!(
        matches!(out_b.action, Action::Redirect(UPLINK_IFINDEX)),
        "VNI-B → DEST_IP must be Action::Redirect({UPLINK_IFINDEX}) (encap); got {:?}",
        out_b.action
    );

    // The two actions MUST differ — this is the isolation property encoded as a single assertion.
    // Action does not impl PartialEq so we encode the inequality structurally: one is Pass and the
    // other is Redirect — they can never be the same variant.
    assert!(
        !matches!(out_a.action, Action::Redirect(_)),
        "VNI-A action must NOT be Redirect — isolation is broken if VNI-A can reach VNI-B routes"
    );
    assert!(
        !matches!(out_b.action, Action::Pass),
        "VNI-B action must NOT be Pass — route was programmed and must be reachable"
    );
}
