//! Conformance tests for the NATIVE IPv6→IPv6 guest-egress datapath (`tc_guest_egress_v6` →
//! `forward_decision_v6`).
//!
//! These drive the REAL shared core stages `flowplane_core::egress::{egress_fw_ct6, route_decision6}`
//! via the full `SimNode::guest_tx_v6` compose (`flowplane_core::datapath::process_guest_tx_v6`) that
//! the eBPF `forward_decision_v6` DELEGATES to — the SAME code runs in the eBPF tc datapath, with the
//! native SimNode serving as the reference oracle. Nothing is reimplemented.
//!
//! A native v6 guest frame `[Eth 0x86DD][IPv6 guest_v6 → ext_v6][TCP]` whose dst is NOT in the NAT64
//! prefix, with an egress-allow firewall rule + an external v6 `route6`, is:
//!   - deny-by-default egress-firewalled (a fresh flow with no egress rule is DROPPED);
//!   - firewall-tracked in `conntrack6` (forward + pre-seeded reverse entries);
//!   - route6-looked-up → emits the `TunnelEncap{vni, remote}` decision toward the route nexthop
//!     (NOT outer bytes — see `flowplane_core::encap`), leaving the inner frame byte-unchanged.

use etherparse::PacketBuilder;
use flowplane_common::{
    CtKey6, FwMeta, FwRule6, Local, PortMeta, RouteValue, FW_ACTION_ACCEPT, FW_ACTION_DROP,
    FW_DIR_EGRESS,
};
use flowplane_core::conntrack::{ct_key6, invert_key6};
use flowplane_core::encap::{TunnelEncap, ETH_LEN};
use flowplane_core::maps::Maps;
use flowplane_core::pkt::Action;

use crate::{MemMaps, SimNode};

// ─── fixed test topology ──────────────────────────────────────────────────────
const VNI: u32 = 400;
const SRC_IFINDEX: u32 = 11;
const UPLINK_IFINDEX: u32 = 7;
const GUEST_V6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
];
/// External v6 dst — NOT in `64:ff9b::/96`, so this is native v6→v6 (no NAT64).
const EXT_V6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
];
const SELF_UNDERLAY: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const NEXTHOP_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];
const UPLINK_MAC: [u8; 6] = [0x02; 6];
const GATEWAY_MAC: [u8; 6] = [0x03; 6];
const GUEST_MAC: [u8; 6] = [0x22; 6];
const SPORT: u16 = 50000;
const DPORT: u16 = 443;

fn local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: UPLINK_MAC,
        gateway_mac: GATEWAY_MAC,
        underlay_ipv6: SELF_UNDERLAY,
    }
}

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: [10, 0, 0, 42],
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: GUEST_MAC,
        l3: 0,
        _pad: [0; 1],
        underlay_ipv6: SELF_UNDERLAY,
        gateway_ipv6: [0; 16],
        guest_ipv6: GUEST_V6,
    }
}

/// External v6 route (is_external=1, nexthop = NEXTHOP_UNDERLAY) with no UNDERLAY[nexthop] entry →
/// the encap branch.
fn route_value() -> RouteValue {
    RouteValue {
        nexthop_vni: VNI,
        nexthop_ipv6: NEXTHOP_UNDERLAY,
        is_external: 1,
        _pad: [0; 3],
    }
}

fn egress_allow_rule() -> FwRule6 {
    FwRule6 {
        src_ip: [0; 16],
        src_mask: [0; 16],
        dst_ip: [0; 16],
        dst_mask: [0; 16],
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
    }
}

/// A SimNode with LOCAL, an external v6 route, and an egress-allow v6 firewall rule on SRC_IFINDEX.
fn node() -> SimNode {
    let mut node = SimNode::with_local(local());
    node.maps.local = Some(local());
    node.src_ifindex = SRC_IFINDEX;
    node.maps.add_route6(VNI, EXT_V6, route_value());
    node.maps.fw_meta6.insert(
        SRC_IFINDEX,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps
        .fw_rules6
        .insert((SRC_IFINDEX, 0), egress_allow_rule());
    node
}

/// `[Eth 0x86DD][IPv6 GUEST_V6 → EXT_V6][TCP]` guest frame.
fn tcp_frame() -> Vec<u8> {
    let b = PacketBuilder::ethernet2(GUEST_MAC, [0x11; 6])
        .ipv6(GUEST_V6, EXT_V6, 64)
        .tcp(SPORT, DPORT, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

/// Fresh v6 5-tuple key for the pre-egress guest frame (VNI-keyed).
fn fwd_key() -> CtKey6 {
    CtKey6 {
        vni: VNI,
        src_ip: GUEST_V6,
        dst_ip: EXT_V6,
        src_port: SPORT,
        dst_port: DPORT,
        proto: 6,
        _pad: [0; 3],
    }
}

#[test]
fn native_v6_egress_encaps_ipv6_in_ipv6_and_tracks_conntrack6() {
    let mut node = node();
    let out = node.guest_tx_v6(&tcp_frame(), &port_meta());

    // 1. Encap arm → redirect out the uplink; the tunnel decision carries the route's vni + nexthop
    //    underlay; the frame is byte-for-byte unchanged (no outer bytes written).
    assert_eq!(
        out.action,
        Action::Redirect(UPLINK_IFINDEX),
        "native v6 egress encaps out the uplink"
    );
    assert_eq!(
        out.tunnel,
        Some(TunnelEncap {
            vni: VNI,
            remote: NEXTHOP_UNDERLAY,
        }),
        "tunnel decision carries the route's vni + nexthop underlay"
    );
    assert_eq!(
        out.pkt,
        tcp_frame(),
        "inner IPv6 frame is byte-for-byte unchanged (no outer bytes written, no SNAT on v6)"
    );

    // 4. conntrack6 firewall-track landed: forward + pre-seeded reverse entries.
    let fwd = fwd_key();
    assert!(
        node.maps.conntrack6_get(&fwd).is_some(),
        "forward conntrack6 entry landed (firewall-track)"
    );
    assert!(
        node.maps.conntrack6_get(&invert_key6(&fwd)).is_some(),
        "reverse conntrack6 entry pre-seeded (established return recognised)"
    );
}

/// Deny-by-default: with NO egress firewall meta/rule, a fresh native v6 flow is DROPPED and nothing
/// is encapped or tracked.
#[test]
fn native_v6_egress_deny_by_default_drops_fresh_flow() {
    let mut node = SimNode::with_local(local());
    node.maps.local = Some(local());
    node.src_ifindex = SRC_IFINDEX;
    node.maps.add_route6(VNI, EXT_V6, route_value());
    // No fw_meta6 / fw_rules6 → fw_eval_dir6 returns DROP on the fresh flow.

    let frame = tcp_frame();
    let before = node.maps.conntrack6.len();
    let out = node.guest_tx_v6(&frame, &port_meta());
    assert_eq!(
        fw_eval_smoke(&node.maps),
        FW_ACTION_DROP,
        "sanity: deny-by-default with no meta"
    );
    assert_eq!(
        out.action,
        Action::Drop,
        "deny-by-default drops the fresh flow"
    );
    assert_eq!(out.pkt, frame, "dropped frame is unchanged (no encap)");
    assert_eq!(
        node.maps.conntrack6.len(),
        before,
        "no conntrack6 entry for a denied fresh flow"
    );
}

/// A native v6 flow with no matching route6 falls through with `Pass`, leaving the frame unchanged.
#[test]
fn native_v6_egress_no_route_passes() {
    let mut node = node();
    // Route a DIFFERENT dst; the frame's EXT_V6 has no route6 → Pass.
    node.maps = MemMaps::default();
    node.maps.local = Some(local());
    node.maps.fw_meta6.insert(
        SRC_IFINDEX,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps
        .fw_rules6
        .insert((SRC_IFINDEX, 0), egress_allow_rule());

    let frame = tcp_frame();
    let out = node.guest_tx_v6(&frame, &port_meta());
    assert_eq!(out.action, Action::Pass, "no route6 → Pass");
    assert_eq!(out.pkt, frame, "frame unchanged on pass-through");
}

/// Helper: evaluate the egress firewall for the fixed guest frame (deny-by-default smoke check).
fn fw_eval_smoke(m: &MemMaps) -> u8 {
    let pkt = crate::VecPkt::from_bytes(&tcp_frame());
    flowplane_core::firewall::fw_eval_dir6(&pkt, m, ETH_LEN, SRC_IFINDEX, FW_DIR_EGRESS)
}

/// The forward conntrack6 key derivation matches what the datapath tracks (guards against a
/// key-shape drift between the test and the real `ct_key6`).
#[test]
fn conntrack6_key_matches_datapath() {
    let pkt = crate::VecPkt::from_bytes(&tcp_frame());
    let k = ct_key6(&pkt, ETH_LEN, VNI).unwrap();
    assert_eq!(k, fwd_key());
}
