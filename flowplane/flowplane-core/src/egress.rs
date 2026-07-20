//! Guest-egress routing decision, ported over the `Maps` trait so the same route→deliver logic runs
//! in eBPF and natively. Faithful port of the route-lookup + local-fast-path + encap tail of the
//! eBPF `egress::forward_decision_v4` / `forward_decision_v6`.
//!
//! Scope (option A, mirroring `uplink.rs`): this covers ONLY the map-driven ROUTE lookup and the
//! resulting deliver decision (local tap vs. encap vs. pass). The conntrack/firewall/VIP/NAT/meter
//! steps that the eBPF wrapper interleaves around it stay in the wrapper — those are separate
//! `Pkt`/`Maps` slices. The eBPF `forward_decision_v4` now: looks up the route via
//! [`route4`], runs its inline nat/ct/meter, then asks [`deliver`] for the local/encap decision.

use flowplane_common::{Local, PortMeta, RouteValue};

use crate::encap::EncapParams;
use crate::maps::Maps;

/// IPIP outer next-header (IPv4-in-IPv6). Mirrors the eBPF `parse::IPPROTO_IPIP`.
pub const IPPROTO_IPIP: u8 = 4;
/// IPv6-in-IPv6 outer next-header. Mirrors the eBPF `parse::IPPROTO_IPV6`.
pub const IPPROTO_IPV6: u8 = 41;

/// What the caller's glue should do after the route+deliver decision. Mirrors the eBPF
/// `egress::EgressVerdict` (kept in the eBPF crate because it is the glue's own type); the core
/// exposes this parallel enum so the sim can consume the decision without pulling in eBPF glue.
pub enum Deliver {
    Pass,
    Local {
        tap_ifindex: u32,
        guest_mac: [u8; 6],
    },
    Encap(EncapParams),
}

/// Look up the exact-match (`/32`) IPv4 route for `dst` in the guest's VNI. `None` => the eBPF
/// wrapper returns `Pass`. Faithful to the eBPF `ROUTES.get(Key::new(64, ..))`.
#[inline(always)]
pub fn route4<M: Maps>(maps: &M, vni: u32, dst: &[u8; 4]) -> Option<RouteValue> {
    maps.route4_get(vni, dst)
}

/// Look up the exact-match (`/128`) IPv6 route for `dst`. Faithful to the eBPF
/// `ROUTES6.get(Key::new(160, ..))`.
#[inline(always)]
pub fn route6<M: Maps>(maps: &M, vni: u32, dst: &[u8; 16]) -> Option<RouteValue> {
    maps.route6_get(vni, dst)
}

/// Given a matched `route`, decide local-tap delivery vs. encap vs. pass. `inner_proto` is the outer
/// next-header for the encap case (IPIP for v4-inner, IPPROTO_IPV6 for v6-inner). Faithful port of
/// the eBPF local-fast-path + encap tail:
///   - if `UNDERLAY[route.nexthop_ipv6]` resolves to a LOCAL interface (`tap_ifindex != 0`), deliver
///     to that tap (`Deliver::Local`); the caller runs the destination ingress firewall for v4;
///   - else if `LOCAL[0]` is set, `Deliver::Encap(..)` toward `route.nexthop_ipv6`;
///   - else `Deliver::Pass`.
///
/// The destination ingress-firewall gate on the v4 local path stays in the eBPF wrapper (it needs
/// `was_new` + the packet), exactly as the wrapper still owns conntrack/vip/meter.
#[inline(always)]
pub fn deliver<M: Maps>(maps: &M, route: &RouteValue, meta: &PortMeta, inner_proto: u8) -> Deliver {
    if let Some(u) = maps.underlay_get(&route.nexthop_ipv6) {
        if u.tap_ifindex != 0 {
            return Deliver::Local {
                tap_ifindex: u.tap_ifindex,
                guest_mac: u.guest_mac,
            };
        }
    }
    let local: Local = match maps.local() {
        Some(l) => l,
        None => return Deliver::Pass,
    };
    Deliver::Encap(EncapParams {
        gateway_mac: local.gateway_mac,
        uplink_mac: local.uplink_mac,
        uplink_ifindex: local.uplink_ifindex,
        src_underlay: meta.underlay_ipv6,
        nexthop_ipv6: route.nexthop_ipv6,
        inner_proto,
        flow_label: 0,
    })
}
