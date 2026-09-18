//! Guest-egress routing decision, ported over the `Maps` trait so the same route→deliver logic runs
//! in eBPF and natively. Faithful port of the route-lookup + local-fast-path + encap tail of the
//! eBPF `egress::forward_decision_v4` / `forward_decision_v6`.
//!
//! Scope (option A, mirroring `uplink.rs`): this covers ONLY the map-driven ROUTE lookup and the
//! resulting deliver decision (local tap vs. encap vs. pass). The conntrack/firewall/LB address/NAT/meter
//! steps that the eBPF wrapper interleaves around it stay in the wrapper — those are separate
//! `Pkt`/`Maps` slices. The eBPF `forward_decision_v4` now: looks up the route via
//! [`route4`], runs its inline nat/ct/meter, then asks [`deliver`] for the local/encap decision.

use flowplane_common::{Local, PortMeta, RouteValue, FW_ACTION_DROP, FW_DIR_EGRESS};

use crate::conntrack::{ct_create_default6, ct_key6, ct_refresh6};
use crate::encap::{tunnel_encap, TunnelEncap, ETH_LEN};
use crate::firewall::fw_eval_dir6;
use crate::maps::Maps;
use crate::pkt::Pkt;

/// What the caller's glue should do after the route+deliver decision. Mirrors the eBPF
/// `egress::EgressVerdict` (kept in the eBPF crate because it is the glue's own type); the core
/// exposes this parallel enum so the sim can consume the decision without pulling in eBPF glue.
pub enum Deliver {
    Pass,
    Local {
        tap_ifindex: u32,
        guest_mac: [u8; 6],
    },
    /// Overlay-egress: stamp `tunnel` (the Geneve tunnel key) and redirect out `uplink_ifindex`.
    /// `uplink_ifindex` rides alongside the tunnel key purely for the caller's `bpf_redirect` /
    /// `Action::Redirect` — it is node-local (from `Local`), not part of the wire decision itself.
    Encap {
        tunnel: TunnelEncap,
        uplink_ifindex: u32,
    },
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

/// Given the packet's `(vni, overlay dst)` and its matched `route`, decide local-tap delivery vs.
/// encap vs. pass. Local delivery is now demuxed by the overlay destination address via the
/// `INTERFACES` / `INTERFACES6` maps (the node-VTEP scheme) rather than by a per-interface /128
/// `UNDERLAY[route.nexthop_ipv6]` self-route:
///   - if `INTERFACES[(vni, dst)]` (v4) / `INTERFACES6[(vni, dst)]` (v6) resolves to a LOCAL
///     interface (`is_local != 0`), deliver to that tap (`Deliver::Local`); the caller runs the
///     destination ingress firewall for v4;
///   - else if `LOCAL[0]` is set, `Deliver::Encap` with the [`tunnel_encap`] decision toward
///     `route.nexthop_ipv6`;
///   - else `Deliver::Pass`.
///
/// `dst` is the 16-byte overlay destination; `is_v6` selects the map (v4 callers pass the 4-byte
/// dst left-justified in the 16-byte buffer). `route` is still needed for the encap-on-miss arm
/// (the tunnel key rides `route.nexthop_ipv6`). The destination ingress-firewall gate on the v4
/// local path stays in the eBPF wrapper (it needs `was_new` + the packet), exactly as the wrapper
/// still owns conntrack/lb_ip/meter.
///
/// Note: the old `inner_proto` (outer next-header) and `flow_label` (RFC 6438 outer flow-label
/// entropy) parameters are gone — both were only meaningful to the byte-written outer header this
/// fn used to build. Under Geneve `collect_md` the kernel builds the outer header itself; ECMP
/// entropy becomes the kernel's Geneve UDP-source-port hash, not something this decision carries.
#[inline(always)]
pub fn deliver<M: Maps>(
    maps: &M,
    vni: u32,
    dst: &[u8; 16],
    is_v6: bool,
    route: &RouteValue,
) -> Deliver {
    let iface = if is_v6 {
        maps.ifaces6_get(vni, dst)
    } else {
        let mut dst4 = [0u8; 4];
        dst4.copy_from_slice(&dst[..4]);
        maps.ifaces_get(vni, &dst4)
    };
    if let Some(iv) = iface {
        if iv.is_local != 0 {
            return Deliver::Local {
                tap_ifindex: iv.tap_ifindex,
                guest_mac: iv.guest_mac,
            };
        }
    }
    let local: Local = match maps.local() {
        Some(l) => l,
        None => return Deliver::Pass,
    };
    Deliver::Encap {
        tunnel: tunnel_encap(route),
        uplink_ifindex: local.uplink_ifindex,
    }
}

/// Result of the shared inner-v6 egress firewall/conntrack stage ([`egress_fw_ct6`]): either DROP
/// (deny-by-default on a fresh flow), or PASS carrying whether this was a NEW flow (a conntrack
/// MISS). `was_new` is consumed downstream so the local fast path can enforce the DESTINATION's
/// ingress firewall on new flows only — mirroring the v4 [`crate::datapath::process_guest_tx`] Local
/// arm; established flows (CT hit, incl. the pre-seeded reverse entry for a same-node reply) skip
/// both egress and dest-ingress firewalls.
///
/// The native SimNode runs [`egress_fw_ct6`] via [`crate::datapath::process_guest_tx_v6`]; the eBPF
/// `egress::forward_decision_v6` runs the SAME three parts ([`egress_ct6`], [`fw_eval_dir6`],
/// [`ct_create_default6`]) as sequential out-of-line subprograms, in the same order.
pub enum EgressFwCt6 {
    Drop,
    Pass { was_new: bool },
}

/// What the conntrack half of STAGE 1 found for an inner-v6 egress frame ([`egress_ct6`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EgressCt6 {
    /// A tracked flow; its entry was refreshed. The firewall is skipped.
    Established,
    /// No entry: the egress firewall decides, and an allowed flow is then tracked.
    Miss,
    /// The frame is too short to key. Keying gates the firewall, so this must DROP: passing it
    /// would let a guest skip deny-by-default by truncating its own frame.
    Unkeyable,
}

/// STAGE 1a (shared core) — the conntrack lookup of [`egress_fw_ct6`]: build the v6 5-tuple key
/// ([`ct_key6`]) and, on a HIT, refresh the entry (`ct_refresh6`, map-only, byte-neutral). Split out
/// so the eBPF dispatcher can run the CT lookup, the firewall scan and the CT create as SEQUENTIAL
/// `#[inline(never)]` frames: nested, the CtKey6/CtEntry locals and the 16-slot `FwRule6` scan
/// exceed what the 512B combined stack leaves after `tc_guest_egress_v6`'s own frame.
#[inline(always)]
pub fn egress_ct6<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &mut M,
    ip_off: usize,
    vni: u32,
    now: u64,
) -> EgressCt6 {
    let Some(key) = ct_key6(pkt, ip_off, vni) else {
        return EgressCt6::Unkeyable;
    };
    match maps.conntrack6_get(&key) {
        Some(mut e) => {
            ct_refresh6(pkt, maps, ip_off, &key, &mut e, now);
            EgressCt6::Established
        }
        None => EgressCt6::Miss,
    }
}

/// STAGE 1 (shared core) — stateful egress firewall + firewall-only IPv6 conntrack for a native
/// v6→v6 guest egress flow: [`egress_ct6`]; on a MISS enforce the SOURCE egress firewall
/// ([`fw_eval_dir6`], deny-by-default → DROP), then create the default (firewall-track) v6
/// conntrack entry (`ct_create_default6`) and report `was_new = true`. An unkeyable frame DROPs.
/// `ip_off` is the inner IPv6 header offset (`ETH_LEN` for a guest frame).
#[inline(always)]
pub fn egress_fw_ct6<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &mut M,
    ip_off: usize,
    ifindex: u32,
    vni: u32,
    now: u64,
) -> EgressFwCt6 {
    match egress_ct6(pkt, maps, ip_off, vni, now) {
        EgressCt6::Established => EgressFwCt6::Pass { was_new: false },
        EgressCt6::Unkeyable => EgressFwCt6::Drop,
        EgressCt6::Miss => {
            if fw_eval_dir6(pkt, &*maps, ip_off, ifindex, FW_DIR_EGRESS) == FW_ACTION_DROP {
                return EgressFwCt6::Drop;
            }
            ct_create_default6(pkt, maps, ip_off, vni, now);
            EgressFwCt6::Pass { was_new: true }
        }
    }
}

/// STAGE 2 (shared core) — route6 lookup + deliver decision for a native v6→v6 guest egress flow.
/// Faithful mirror of the eBPF `egress::route_decision_v6`: read the inner IPv6 dst (@ `ip_off + 24`)
/// → [`route6`] (Pass on miss) → [`deliver`] (local fast path / encap / pass). Kept as a SEPARATE pub
/// fn so the eBPF wrapper holds the route-lookup frame in its own `#[inline(never)]` frame,
/// sequential to stage 1's.
#[inline(always)]
pub fn route_decision6<P: Pkt, M: Maps>(pkt: &P, maps: &M, meta: &PortMeta) -> Deliver {
    let dst = match pkt.read_array::<16>(ip_off_dst6()) {
        Some(d) => d,
        None => return Deliver::Pass,
    };
    let route = match route6(maps, meta.vni, &dst) {
        Some(r) => r,
        None => return Deliver::Pass,
    };
    deliver(maps, meta.vni, &dst, true, &route)
}

/// Inner IPv6 dst offset within a guest Ethernet frame: `ETH_LEN + 24` (IPv6 dst is at +24 in the
/// fixed 40-byte v6 header). A small const-fn so the offset is single-sourced.
#[inline(always)]
const fn ip_off_dst6() -> usize {
    ETH_LEN + 24
}
