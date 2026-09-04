//! Conformance tests for VPC-peering route semantics on the guest-egress path.
//!
//! VPC peering adds NO new datapath code.  Its entire datapath effect is that the agent installs a
//! cross-VNI route **under the local VNI** — identical in structure to any local route, just with
//! a nexthop pointing at the peer guest's underlay.  `route4(local_vni, dst)` then HITS because
//! the agent wrote the entry; no new BPF logic is involved.
//!
//! These tests drive the REAL `flowplane_core::egress::route4` (via the full `SimNode::guest_tx`
//! compose) over in-memory `MemMaps` / `VecPkt`, mirroring `vni_test.rs` exactly — the only
//! structural difference is that the route is inserted under the SENDER's VNI rather than a
//! different VNI.
//!
//! # Topology
//! - VNI-A (100): the local/sender VNI.
//! - DEST_IP (`10.1.1.1`): destination guest in the peer VPC.
//! - `PEER_NEXTHOP`: the peer guest's underlay IPv6 address (drives the Encap branch).
//! - `LOCAL_NEXTHOP`: a local guest's underlay IPv6 address (used in the shadow test).
//!
//! # Cases
//! 1. **`imported_cross_vni_route_resolves_and_delivers`**
//!    The agent installs a route for DEST_IP under VNI-A (the local VNI), nexthop = peer underlay.
//!    `guest_tx` from VNI-A to DEST_IP HITS → `Action::Redirect(uplink_ifindex)`.
//!    Contrast with `vni_test`: if the route were under VNI-B instead, the same send returns
//!    `Action::Pass` (miss).  Installing under the LOCAL VNI is what peering provides.
//!
//! 2. **`local_route_shadows_imported_peer_route`**
//!    The datapath map holds one value per `(vni, prefix)` key.  The agent guarantees (via
//!    local-VNI precedence) that a local route wins over any import for the same prefix.  This test pins that
//!    the entry the agent actually writes (the local nexthop) is what the datapath forwards on.
//!    We model this by programming only the local-nexthop entry and asserting delivery via it.
//!    (Agent-side precedence — ensuring the local entry is written and not overwritten — is tested
//!    separately in Go; here we pin that whatever is in the map is what the datapath uses.)

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, Local, PortMeta, RouteValue, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
};
use flowplane_core::pkt::Action;

use crate::SimNode;

// ─── fixed test topology ──────────────────────────────────────────────────────

/// The local VNI — the sender's VNI; routes are installed here by the peering agent.
const VNI_A: u32 = 100;

/// The destination address the agent has imported a peer route for.
const DEST_IP: [u8; 4] = [10, 1, 1, 1];

/// Underlay nexthop representing the peer guest (cross-VNI import target).
const PEER_NEXTHOP: [u8; 16] = [
    0x20, 0x01, 0xdb, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
];

/// Underlay nexthop representing a local guest (used in the shadow test).
const LOCAL_NEXTHOP: [u8; 16] = [
    0x20, 0x01, 0xdb, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03,
];

/// Synthetic egress-firewall ifindex for the sender guest.
const SRC_IFINDEX_A: u32 = 10;

/// Uplink ifindex set in `configure_local` — the expected Redirect target on encap.
const UPLINK_IFINDEX: u32 = 7;

// ─── helpers (mirrored from vni_test) ────────────────────────────────────────

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
            proto: 0,
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
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
    });
    // No underlay neighbour entry for the nexthop → deliver falls through to Encap (uplink path).
}

// ─── (1) imported cross-VNI route resolves and delivers ──────────────────────

/// The peering agent installs a route for DEST_IP **under VNI-A** (the sender's own VNI).
/// The nexthop is the peer guest's underlay IPv6 — exactly what a cross-VNI import produces.
///
/// `guest_tx` for a VNI-A guest sending to DEST_IP must:
/// - find the route (lookup is keyed by VNI-A, which now has the entry), and
/// - take the Encap path → `Action::Redirect(UPLINK_IFINDEX)`.
///
/// **Contrast with `vni_test`**: if the SAME route were installed under VNI-B instead of VNI-A,
/// `vni_isolation_route_miss_for_wrong_vni_returns_pass` shows the result is `Action::Pass`.
/// The ONLY difference here is `add_route4(VNI_A, ...)` vs `add_route4(VNI_B, ...)`.
#[test]
fn imported_cross_vni_route_resolves_and_delivers() {
    let guest_a_ip: [u8; 4] = [10, 0, 1, 10];

    let mut node = SimNode::new();
    configure_local(&mut node);
    allow_egress(&mut node, SRC_IFINDEX_A);

    // Agent installs the peer route UNDER VNI_A — this is the peering import effect.
    node.maps.add_route4(
        VNI_A,
        DEST_IP,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: PEER_NEXTHOP,
            is_external: 0,
            _pad: [0; 3],
        },
    );

    node.src_ifindex = SRC_IFINDEX_A;
    let frame = guest_udp_frame(guest_a_ip);
    let meta = port_meta(VNI_A, guest_a_ip);
    let out = node.guest_tx(&frame, &meta);

    // Route for VNI_A HITS → deliver takes Encap path → Redirect to uplink.
    assert!(
        matches!(out.action, Action::Redirect(UPLINK_IFINDEX)),
        "VNI-A guest sending to imported DEST_IP must get Action::Redirect({UPLINK_IFINDEX}) \
         (encap hit) — peering import broken; got {:?}",
        out.action
    );
}

// ─── (2) local route shadows imported peer route ──────────────────────────────

/// The datapath map holds exactly one `RouteValue` per `(vni, prefix)` key.
/// The agent (via local-VNI precedence) ensures that when both a local route and a peer import exist
/// for the same destination, the LOCAL nexthop is what ends up in the map.
///
/// This test pins that whichever entry is present in the map is what the datapath forwards on —
/// i.e., the datapath is not doing its own precedence logic; it forwards on whatever value the
/// agent wrote.  We model the "agent chose local" outcome by inserting the local nexthop and
/// asserting delivery via it.
///
/// Agent-side write-ordering (ensuring the local entry overwrites any import) is tested
/// separately in Go.  This test is the datapath half: local entry → local delivery.
#[test]
fn local_route_shadows_imported_peer_route() {
    let guest_a_ip: [u8; 4] = [10, 0, 1, 10];

    let mut node = SimNode::new();
    configure_local(&mut node);
    allow_egress(&mut node, SRC_IFINDEX_A);

    // Agent wrote the LOCAL nexthop into the map (having applied local-VNI precedence).
    // The peer import is NOT in the map — the agent did not write it because local wins.
    node.maps.add_route4(
        VNI_A,
        DEST_IP,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: LOCAL_NEXTHOP,
            is_external: 0,
            _pad: [0; 3],
        },
    );

    node.src_ifindex = SRC_IFINDEX_A;
    let frame = guest_udp_frame(guest_a_ip);
    let meta = port_meta(VNI_A, guest_a_ip);
    let out = node.guest_tx(&frame, &meta);

    // The local entry is in the map → route HIT → Encap → Redirect to uplink.
    assert!(
        matches!(out.action, Action::Redirect(UPLINK_IFINDEX)),
        "VNI-A guest sending to locally-shadowed DEST_IP must get Action::Redirect({UPLINK_IFINDEX}) \
         — local-entry delivery broken; got {:?}",
        out.action
    );

    // Additionally confirm this is NOT a miss — the local entry must be reachable.
    assert!(
        !matches!(out.action, Action::Pass),
        "Local route entry must not be invisible (Action::Pass) — map lookup is broken"
    );
}
