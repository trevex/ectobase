//! Guest-egress routing decision, ported over the `Maps` trait so the same route→deliver logic runs
//! in eBPF and natively. Faithful port of the route-lookup + local-fast-path + encap tail of the
//! eBPF `egress::forward_decision_v4` / `forward_decision_v6`.
//!
//! Scope (option A, mirroring `uplink.rs`): this covers ONLY the map-driven ROUTE lookup and the
//! resulting deliver decision (local tap vs. encap vs. pass). The conntrack/firewall/VIP/NAT/meter
//! steps that the eBPF wrapper interleaves around it stay in the wrapper — those are separate
//! `Pkt`/`Maps` slices. The eBPF `forward_decision_v4` now: looks up the route via
//! [`route4`], runs its inline nat/ct/meter, then asks [`deliver`] for the local/encap decision.

use flowplane_common::{Local, PortMeta, RouteValue, FW_ACTION_DROP, FW_DIR_EGRESS};

use crate::conntrack::{ct_create_default6, ct_key6, ct_refresh6};
use crate::encap::{EncapParams, ETH_LEN};
use crate::firewall::fw_eval_dir6;
use crate::maps::Maps;
use crate::pkt::Pkt;

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
///
/// `flow_label` is the 20-bit outer IPv6 flow label (RFC 6438 fabric ECMP); the caller computes it
/// from the inner flow via [`crate::parse::inner_flow_label`] so the eBPF and native paths carry an
/// identical value.
#[inline(always)]
pub fn deliver<M: Maps>(
    maps: &M,
    route: &RouteValue,
    meta: &PortMeta,
    inner_proto: u8,
    flow_label: u32,
) -> Deliver {
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
        flow_label,
    })
}

/// Result of the shared inner-v6 egress firewall/conntrack stage ([`egress_fw_ct6`]): either DROP
/// (deny-by-default on a fresh flow), or PASS carrying whether this was a NEW flow (a conntrack
/// MISS). `was_new` is consumed downstream so the local fast path can enforce the DESTINATION's
/// ingress firewall on new flows only — mirroring the v4 [`crate::datapath::process_guest_tx`] Local
/// arm; established flows (CT hit, incl. the pre-seeded reverse entry for a same-node reply) skip
/// both egress and dest-ingress firewalls.
///
/// This is the SHARED core the eBPF `egress::egress_fw_ct_v6` wrapper delegates to (seam-not-
/// duplicate), and the SAME code the native SimNode + DPDK worker run via
/// [`crate::datapath::process_guest_tx_v6`].
pub enum EgressFwCt6 {
    Drop,
    Pass { was_new: bool },
}

/// STAGE 1 (shared core) — stateful egress firewall + firewall-only IPv6 conntrack for a native
/// v6→v6 guest egress flow. Faithful mirror of the eBPF `egress::egress_fw_ct_v6`: build the v6
/// 5-tuple key ([`ct_key6`]); on a CT HIT refresh (`ct_refresh6`, map-only, byte-neutral); on a MISS
/// enforce the SOURCE egress firewall ([`fw_eval_dir6`], deny-by-default → DROP), then create the
/// default (firewall-track) v6 conntrack entry (`ct_create_default6`) and report `was_new = true`.
/// `ip_off` is the inner IPv6 header offset (`ETH_LEN` for a guest frame). Kept as a SEPARATE pub fn
/// so the eBPF wrapper can hold it in its own `#[inline(never)]` BPF stack frame (CtKey6 ~48B) —
/// freed before the route stage's `Key<RouteLpmData6>` frame runs (512B combined stack limit).
#[inline(always)]
pub fn egress_fw_ct6<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &mut M,
    ip_off: usize,
    ifindex: u32,
    vni: u32,
    now: u64,
) -> EgressFwCt6 {
    if let Some(key) = ct_key6(pkt, ip_off, vni) {
        match maps.conntrack6_get(&key) {
            Some(mut e) => ct_refresh6(pkt, maps, ip_off, &key, &mut e, now),
            None => {
                if fw_eval_dir6(pkt, &*maps, ip_off, ifindex, FW_DIR_EGRESS) == FW_ACTION_DROP {
                    return EgressFwCt6::Drop;
                }
                ct_create_default6(pkt, maps, ip_off, vni, now);
                return EgressFwCt6::Pass { was_new: true };
            }
        }
    }
    EgressFwCt6::Pass { was_new: false }
}

/// STAGE 2 (shared core) — route6 lookup + deliver decision for a native v6→v6 guest egress flow.
/// Faithful mirror of the eBPF `egress::route_decision_v6`: read the inner IPv6 dst (@ `ip_off + 24`)
/// → [`route6`] (Pass on miss) → [`deliver`] (local fast path / encap / pass) with `inner_proto =
/// IPPROTO_IPV6` (41 — IPv6-in-IPv6, NOT IPIP/4). `flow_label` is the RFC-6438 outer flow label the
/// caller computes from the inner 5-tuple ([`crate::parse::inner_flow_label`], `is_v6 = true`) so the
/// eBPF and native encapped bytes are identical. Kept as a SEPARATE pub fn so the eBPF wrapper holds
/// the route-lookup frame in its own `#[inline(never)]` frame, sequential to stage 1's.
#[inline(always)]
pub fn route_decision6<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &M,
    meta: &PortMeta,
    flow_label: u32,
) -> Deliver {
    let dst = match pkt.read_array::<16>(ip_off_dst6()) {
        Some(d) => d,
        None => return Deliver::Pass,
    };
    let route = match route6(maps, meta.vni, &dst) {
        Some(r) => r,
        None => return Deliver::Pass,
    };
    deliver(maps, &route, meta, IPPROTO_IPV6, flow_label)
}

/// Inner IPv6 dst offset within a guest Ethernet frame: `ETH_LEN + 24` (IPv6 dst is at +24 in the
/// fixed 40-byte v6 header). A small const-fn so the offset is single-sourced.
#[inline(always)]
const fn ip_off_dst6() -> usize {
    ETH_LEN + 24
}
