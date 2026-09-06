//! Substrate-agnostic datapath orchestrators shared by the eBPF program and the native `SimNode`
//! harness. These compose the REAL per-step core fns (`lb_select_forward`,
//! `reforward`, `fw_eval_dir`, `ct_create_default`, `decap_and_rewrite`, metering) in the exact order
//! and gates of the eBPF program tails, over any `Pkt` + `Maps` implementation. The SAME code thus
//! runs under the sim and under the `BPF_PROG_TEST_RUN` anchor.

use flowplane_common::{
    Local, PortMeta, CT_F_NAT64, CT_REWRITE_DST, FW_ACTION_DROP, FW_DIR_EGRESS, FW_DIR_INGRESS,
    GENEVE_OVERHEAD, UNDERLAY_LOCAL_DELIVER,
};

use crate::arp_nd::{arp_reply, nd_reply};
use crate::conntrack::{
    ct_apply, ct_create_default, ct_create_default6, ct_key, ct_key6, ct_refresh, ct_refresh6,
};
use crate::dhcp;
use crate::egress::{deliver, egress_fw_ct6, route4, route_decision6, Deliver, EgressFwCt6};
use crate::encap::{reforward, tunnel_encap, TunnelEncap, ETH_LEN};
use crate::firewall::{fw_eval_dir, fw_eval_dir6};
use crate::lb::{lb_select_forward, lb_select_forward_icmp_error, lb_select_forward_v6};
use crate::maps::Maps;
use crate::nat::{snat_egress, SnatOutcome};
use crate::nat64::{
    nat64_egress_parse, nat64_egress_write, nat64_ingress_parse, nat64_ingress_write,
};
use crate::parse::{l4_ports, IPPROTO_TCP, IPPROTO_UDP};
use crate::pkt::{Action, Pkt};
use crate::uplink::{decap_and_rewrite, edge_local_deliver, ETH_P_IP, ETH_P_IPV6, GW_MAC};
use flowplane_common::csum::csum_replace4;

/// Inputs for [`process_uplink`]. Under Geneve `collect_md` the kernel decaps before this runs and
/// `get_tunnel_key` recovers only the VNI + sender remote — NOT "which local identity to deliver
/// to" (that was previously encoded in the outer dst address under the per-interface /128 VTEP
/// scheme). So there is no pre-resolved `UnderlayValue`/outer-dst here anymore: `vni` (from
/// `get_tunnel_key().tunnel_id`) + the inner packet + maps are the ONLY inputs the delivery-target
/// reconstruction (see [`resolve_uplink_target`]) has to work with. `local` supplies the outer
/// MACs/ifindex for an LB remote `reforward` / neighbor-NAT relay / WAN-edge local-deliver rewrite;
/// `now` is the monotonic clock (ns) the ingress-lane meter stamps `last_ns` from (models
/// `bpf_ktime_get_ns()`). There is no `guest_ipv6` field here: the CT_F_NAT64 reverse-return path
/// (see [`process_uplink_rx`]) needs the delivery tap resolved FIRST (it is per-tap `PORT_META`
/// metadata), which only happens inside the dispatch itself — so it is read from `Maps` there,
/// not threaded in as an input the caller can't yet know.
pub struct UplinkIn<'a> {
    pub vni: u32,
    pub local: &'a Local,
    pub now: u64,
}

/// The outcome of reconstructing WHERE to deliver a decapped inner frame from `(vni, inner dst)` plus
/// maps alone — this covers mechanism ONE (normal guest self-route) and mechanism FOUR (WAN-edge
/// sentinel / genuine miss) of the four-mechanism ingress delivery-target reconstruction (see the P2
/// Task-4 design doc). Mechanism TWO (NAT-return) and mechanism THREE (LB remote-backend /
/// neighbor-NAT relay) are resolved by their own callers instead — a plain `ROUTES`/`ROUTES6` lookup
/// on the CURRENT packet bytes isn't the right tool for those (mechanism TWO keys off the reverse
/// conntrack entry's restored guest IP, not the packet; mechanism THREE keys off `NEIGHBOR_NAT`, not
/// `ROUTES`) — but mechanism TWO's callers reuse THIS resolver once they have the restored guest IP,
/// since that address is exactly what the guest's own self-route is keyed on. Protocol-agnostic (the
/// `tap_ifindex`/`guest_mac` a v4 self-route and a v6 self-route resolve to look identical) — shared
/// by both [`resolve_uplink_target`] (v4) and [`resolve_uplink_target6`] (v6, P2 Task 4c).
enum UplinkTarget {
    /// A local guest interface, resolved by demuxing the overlay dst against the node-VTEP
    /// `INTERFACES[(vni, guest_ipv4)]` / `INTERFACES6[(vni, guest_ipv6)]` map (`is_local != 0`),
    /// written per interface by `program_interface` (`flowplane-control/src/interface.rs`).
    Local {
        tap_ifindex: u32,
        guest_mac: [u8; 6],
        /// Target device has a netns peer (veth/netkit) → deliver with `bpf_redirect_peer`.
        peer_capable: bool,
    },
    /// `INTERFACES` missed AND this node is configured as the WAN edge: `UNDERLAY[LOCAL.underlay_ipv6]`
    /// carries the `UNDERLAY_LOCAL_DELIVER` sentinel (programmed once by `Control::attach_edge`,
    /// keyed under the edge's OWN `Local.underlay_ipv6` — verified against `control/mod.rs`). Decap
    /// already ran (kernel/Fabric); only the inner-Ethernet rewrite + kernel hand-off remains
    /// ([`edge_local_deliver`]).
    EdgeLocalDeliver,
    /// `INTERFACES` missed and this node is NOT the WAN edge: nothing on this node can legitimately
    /// claim the packet. SECURITY DEFAULT: drop, never pass — passing would leak decapped overlay
    /// bytes into this node's own kernel netns (a genuine miss must never look like a WAN egress).
    Drop,
}

/// Resolve mechanisms #1 + #4 for an inner IPv4 `dst`: demux `INTERFACES[(vni, dst)]` (local
/// delivery on `is_local`), falling back to the WAN-edge sentinel check (else genuine-miss `Drop`)
/// on an `INTERFACES` miss. Shared by the normal (non-LB, non-NAT) uplink base path
/// ([`process_uplink`]) AND the NAT-return / NAT64-return delivery-target resolution
/// ([`process_uplink_nat_return`], [`process_uplink_rx`]'s NAT64 dispatch): after `ct_apply` (or the
/// reverse CT entry directly) restores the guest's real overlay IPv4, that restored address is
/// EXACTLY the address the guest's own self-route is keyed on — the same lookup mechanism #1
/// already does, so there is no separate map for mechanism #2.
///
/// `#[inline(never)]`: it is packet-FREE (takes `dst` by value; only map lookups), so out-of-lining
/// it is verifier-safe and reclaims frame budget in its callers. P2 added a packet-reading
/// (must-stay-inlined) ICMP-error relay + VIP-DNAT arm to `process_uplink`, pushing its inlined
/// frame over the eBPF verifier's combined-2-call stack budget; moving this (larger, pkt-free) helper
/// out-of-line brings `uplink_rx` back under budget without a pkt-pointer-tracking regression.
#[inline(never)]
fn resolve_uplink_target<M: Maps>(
    maps: &M,
    vni: u32,
    dst: &[u8; 4],
    local: &Local,
) -> UplinkTarget {
    if let Some(iv) = maps.ifaces_get(vni, dst) {
        if iv.is_local != 0 {
            return UplinkTarget::Local {
                tap_ifindex: iv.tap_ifindex,
                guest_mac: iv.guest_mac,
                peer_capable: iv.peer_capable != 0,
            };
        }
    }
    if let Some(u) = maps.underlay_get(&local.underlay_ipv6) {
        if u.tap_ifindex == UNDERLAY_LOCAL_DELIVER {
            return UplinkTarget::EdgeLocalDeliver;
        }
    }
    UplinkTarget::Drop
}

/// Resolve mechanisms #1 + #4 for an inner IPv6 `dst`: demux `INTERFACES6[(vni, dst)]` (local
/// delivery on `is_local`), falling back to the WAN-edge sentinel check (else genuine-miss `Drop`) on
/// an `INTERFACES6` miss. v6 mirror of [`resolve_uplink_target`] (P2 Task 4c) — v6 has no NAT/NAT64-return
/// mechanism TWO caller (those are v4-only; see [`process_uplink_v6`]'s doc comment), so this is used
/// by [`process_uplink_v6`] alone. The `local.underlay_ipv6`/`UNDERLAY_LOCAL_DELIVER` sentinel check
/// is the SAME node-identity lookup the v4 resolver uses — the WAN-edge role isn't protocol-specific.
///
/// SECURITY DEFAULT (closes the pre-existing v6 gap — P2 Task 4c): an `INTERFACES6` miss that is also
/// not the edge sentinel returns `UplinkTarget::Drop`, never a pass-through. HEAD's hand-inlined
/// `v6_uplink_rx` fell through to `TC_ACT_OK` on a `ROUTES6` miss (fail-OPEN — a decapped overlay v6
/// frame with no legitimate local claimant was handed to this node's own kernel netns); this resolver
/// gives v6 the exact fail-closed default v4 already has.
#[inline(always)]
fn resolve_uplink_target6<M: Maps>(
    maps: &M,
    vni: u32,
    dst: &[u8; 16],
    local: &Local,
) -> UplinkTarget {
    if let Some(iv) = maps.ifaces6_get(vni, dst) {
        if iv.is_local != 0 {
            return UplinkTarget::Local {
                tap_ifindex: iv.tap_ifindex,
                guest_mac: iv.guest_mac,
                peer_capable: iv.peer_capable != 0,
            };
        }
    }
    if let Some(u) = maps.underlay_get(&local.underlay_ipv6) {
        if u.tap_ifindex == UNDERLAY_LOCAL_DELIVER {
            return UplinkTarget::EdgeLocalDeliver;
        }
    }
    UplinkTarget::Drop
}

/// Host uplink_rx for the LB + base path, operating in place on `pkt`. Mirrors `try_uplink_rx`:
///   1. `lb_select_forward` → local backend (deliver to its tap) | remote (reforward, no decap)
///      | None → mechanism #3 (neighbor-NAT relay) → mechanisms #1/#4 (`resolve_uplink_target`);
///   2. ingress firewall on the inner 5-tuple against the deliver tap (new-flow gate);
///   3. conntrack create-on-miss, **skipped for LB** (DSR, no ct — `ingress.rs:266`);
///   4. decap + inner-Ethernet rewrite;
///   5. ingress-lane policing (keyed by dest tap).
///
/// Result of [`process_uplink`] / [`process_uplink_rx`]: the delivery `Action`, plus the tunnel-key
/// decision the relay/reforward arms emit. Only the LB remote-backend re-forward + neighbor-NAT
/// relay arms set `tunnel: Some(..)` — every other branch here is a decap/deliver/drop path, so
/// `tunnel` is `None`.
pub struct UplinkOut {
    pub action: Action,
    pub tunnel: Option<TunnelEncap>,
}

/// Ingress firewall check on NEW inbound flows against the deliver tap (mirrors `process_uplink`
/// step 2). Returns `true` iff the packet must be dropped.
///
/// `#[inline(never)]`, own subprogram: `firewall::fw_eval_dir` itself must stay `#[inline(always)]`
/// (shared with the egress path — see its doc comment), so this ingress-only WRAPPER around the
/// ct_key-miss-gated call is where the P2 Task 4b out-of-lining actually happens, splitting it from
/// [`uplink_track_flow`] (step 3) and the rest of [`process_uplink`] so their locals don't combine
/// on `uplink_rx`'s BPF stack (they run sequentially, never nested, so this is safe).
#[inline(never)]
fn uplink_ingress_firewall_drop<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &M,
    inner_off: usize,
    vni: u32,
    tap: u32,
) -> bool {
    match ct_key(pkt, inner_off, vni) {
        Some(key) => {
            maps.conntrack_get(&key).is_none()
                && fw_eval_dir(pkt, maps, inner_off, tap, FW_DIR_INGRESS) == FW_ACTION_DROP
        }
        None => false,
    }
}

/// Conntrack create-on-miss / refresh-on-hit (mirrors `process_uplink` step 3, non-LB only). Map-only
/// (never mutates `pkt`), so byte-parity-neutral. `#[inline(never)]`: see
/// [`uplink_ingress_firewall_drop`]'s doc comment for why this ingress-only wrapper is the safe
/// out-of-lining lever (`conntrack::ct_create_default`/`ct_refresh` themselves stay
/// `#[inline(always)]` — also shared with the egress path).
#[inline(never)]
fn uplink_track_flow<P: Pkt, M: Maps>(pkt: &P, maps: &mut M, inner_off: usize, vni: u32, now: u64) {
    if let Some(key) = ct_key(pkt, inner_off, vni) {
        match maps.conntrack_get(&key) {
            None => ct_create_default(pkt, maps, inner_off, vni, now),
            Some(mut e) => ct_refresh(pkt, maps, inner_off, &key, &mut e, now),
        }
    }
}

/// Source the guest's overlay IPv6 for the CT_F_NAT64 ingress-return dispatch (mirrors
/// `process_uplink_rx`'s CT_F_NAT64 branch — see its call site). `[0; 16]` if `PORT_META` has no
/// entry for `tap_ifindex` (IPv4-only guest; `nat64_ingress_parse` rejects it, falling through to
/// `Action::Pass`). `#[inline(never)]`: same BPF-stack-relief reasoning as
/// [`uplink_ingress_firewall_drop`]/[`uplink_track_flow`] — inlining the ~70-byte `PortMeta` copy
/// directly into `process_uplink_rx`'s already-large dispatch pushed the verifier's combined-call-
/// stack over budget.
#[inline(never)]
fn resolve_nat64_guest_ipv6<M: Maps>(maps: &M, tap_ifindex: u32) -> [u8; 16] {
    maps.port_meta_get(tap_ifindex)
        .map(|m| m.guest_ipv6)
        .unwrap_or([0; 16])
}

/// Source the delivery tap's `l3` bit (`PortMeta.l3 != 0`) for [`decap_and_rewrite`]: `true` picks the
/// all-zero inner dst MAC an L3 netkit pod accepts, `false` keeps the L2 `guest_mac`. Mirrors
/// [`resolve_nat64_guest_ipv6`]'s per-tap `PORT_META` lookup (and its `#[inline(never)]` BPF-stack-
/// relief reasoning — the ~70-byte `PortMeta` copy stays out of the caller's already-large dispatch).
/// `false` when `PORT_META` has no entry for `tap_ifindex` (defaults to the L2 path, byte-unchanged).
#[inline(never)]
fn resolve_delivery_l3<M: Maps>(maps: &M, tap_ifindex: u32) -> bool {
    maps.port_meta_get(tap_ifindex)
        .map(|m| m.l3 != 0)
        .unwrap_or(false)
}

/// F2: rewrite an inbound frame's inner IPv4 DESTINATION `old` -> `new` (1:1 floating-IP DNAT),
/// fixing the IPv4 header checksum and the TCP/UDP L4 checksum incrementally. ICMP needs no L4
/// fixup (the ICMPv4 checksum does not cover addresses). Mirrors `nat.rs`'s SNAT read-modify-write
/// window pattern for eBPF-verifier friendliness (one dominating bound per access).
///
/// `#[inline(never)]`: keeps this out of `process_uplink`'s already-tight combined call stack (same
/// BPF-stack-relief discipline as `uplink_ingress_firewall_drop`).
#[inline(never)]
fn vip_dnat_rewrite<P: Pkt>(pkt: &mut P, ip_off: usize, old: &[u8; 4], new: &[u8; 4]) {
    // dst IP at ip_off + 16.
    if !pkt.write_array(ip_off + 16, new) {
        return;
    }
    // IP header checksum at ip_off + 10.
    if let Some(ipc) = pkt.read_u16_be(ip_off + 10) {
        let c = csum_replace4(ipc, old, new);
        pkt.write_array(ip_off + 10, &c.to_be_bytes());
    }
    let ihl = match pkt.read_u8(ip_off) {
        Some(b) => (b & 0x0f) as usize * 4,
        None => return,
    };
    let proto = match pkt.read_u8(ip_off + 9) {
        Some(p) => p,
        None => return,
    };
    let l4 = ip_off + ihl;
    if proto == IPPROTO_TCP {
        // TCP checksum at l4[16..18]. Window = 18 (single dominating bound).
        if let Some(mut h) = pkt.read_array::<18>(l4) {
            let c0 = u16::from_be_bytes([h[16], h[17]]);
            let c1 = csum_replace4(c0, old, new);
            h[16..18].copy_from_slice(&c1.to_be_bytes());
            pkt.write_array(l4, &h);
        }
    } else if proto == IPPROTO_UDP {
        // UDP checksum at l4[6..8]; a zero UDP checksum stays zero. Window = 8.
        if let Some(mut h) = pkt.read_array::<8>(l4) {
            let c0 = u16::from_be_bytes([h[6], h[7]]);
            if c0 != 0 {
                let c1 = csum_replace4(c0, old, new);
                h[6..8].copy_from_slice(&c1.to_be_bytes());
            }
            pkt.write_array(l4, &h);
        }
    }
    // ICMP (proto 1): no L4 checksum fixup — the ICMPv4 checksum does not cover the IP addresses.
}

/// Returns the final delivery `Action` (+ tunnel decision on a relay/reforward arm), having mutated
/// `pkt` in place.
///
/// No explicit inline attribute (P2 Task 4b): its own body is now small (steps 2/3/5 are out-of-line
/// subprograms — see [`uplink_ingress_firewall_drop`]/[`uplink_track_flow`]/`meter::ingress_pass`),
/// so letting it merge back into its single real-eBPF call site (`ingress.rs::try_uplink_rx` via
/// `process_uplink_rx`) keeps `uplink_rx`'s combined-call chain SHALLOWER (2 deep to each out-of-line
/// stage, not 3) — `#[inline(never)]` here was tried first and passed `uplink_rx` alone, but the
/// extra chain depth pushed `main -> process_uplink -> uplink_ingress_firewall_drop` over budget.
pub fn process_uplink<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in_: &UplinkIn) -> UplinkOut {
    // Post-decap (P2 Task 5): the kernel `collect_md` geneve device already stripped the outer
    // Eth/IPv6/UDP/Geneve header before this program runs — `pkt` IS the inner frame, so the inner
    // 5-tuple/route lookups read at `ETH_LEN`, not `ETH_LEN + IPV6_LEN` (that old offset modeled the
    // inner sitting BEHIND a still-present outer header, which no longer exists on this path).
    let inner_off = ETH_LEN;

    // 1. LB dispatch. The ICMP-error relay wins first: an ICMP error destined to a VIP must follow
    //    its EMBEDDED flow's backend, not the (mis-hashed) outer ICMP tuple. Everything else — incl.
    //    a normal ICMP echo to a VIP — falls through to the plain select (echo load-balances to a
    //    backend; it is NOT answered by the dataplane).
    let lb_ul = lb_select_forward_icmp_error(&*pkt, &*maps, inner_off, in_.vni)
        .or_else(|| lb_select_forward(&*pkt, &*maps, inner_off, in_.vni));
    let (tap, guest_mac, is_lb, peer_capable) = match lb_ul {
        Some(be) => {
            if be.node_vtep == in_.local.underlay_ipv6 {
                let overlay4 = [
                    be.overlay_ip[0],
                    be.overlay_ip[1],
                    be.overlay_ip[2],
                    be.overlay_ip[3],
                ];
                match maps.ifaces_get(be.vni, &overlay4) {
                    Some(iv) if iv.is_local != 0 => {
                        (iv.tap_ifindex, iv.guest_mac, true, iv.peer_capable != 0)
                    }
                    _ => {
                        return UplinkOut {
                            action: Action::Drop,
                            tunnel: None,
                        };
                    }
                }
            } else {
                // Remote backend: re-forward — same vni, no decap, packet bytes untouched. The
                // kernel geneve device re-stamps the tunnel key toward `be.node_vtep` via
                // `bpf_skb_set_tunnel_key`.
                let tunnel = reforward(be.vni, &be.node_vtep);
                return UplinkOut {
                    action: Action::Redirect(in_.local.uplink_ifindex),
                    tunnel: Some(tunnel),
                };
            }
        }
        None => {
            let dst = match pkt.read_array::<4>(inner_off + 16) {
                Some(d) => d,
                None => {
                    return UplinkOut {
                        action: Action::Drop,
                        tunnel: None,
                    }
                }
            };
            // F2: 1:1 floating-IP ingress DNAT. `VIPS[(vni,V)] = G` means dst V must be rewritten to
            // the backing guest G and delivered locally (VIPS is only programmed on the node that owns
            // G — the `--vip` CLI maps a node's OWN guest — so a non-local G is a misconfig -> Drop, and
            // there is no reforward arm). A floating IP is never a nat_ip, so a VIP hit SKIPS the
            // neighbor-NAT relay. Rebuild of the pre-P2 eBPF `vip::dnat_ingress`. NOTE: compute a single
            // `deliver_dst` and fall through to ONE `resolve_uplink_target` below — duplicating that
            // (inlined) match in a separate VIP branch blew the eBPF verifier's combined-call stack
            // budget ("combined stack size of 2 calls is 528"), regressing `uplink_rx` load.
            let deliver_dst = if let Some(g) = maps.vip_get(in_.vni, &dst) {
                vip_dnat_rewrite(pkt, inner_off, &dst, &g);
                g
            } else {
                // Mechanism #3: neighbor-NAT relay — the inner dst may be a nat_ip owned by ANOTHER
                // node (an owned nat_ip instead demuxes via the CT-based `nat_guest` path one level up,
                // in `process_uplink_rx`). Mirrors ingress.rs's "Neighbor NAT" block.
                if let Some((_proto, _sport, dport)) = l4_ports(&*pkt, inner_off) {
                    if let Some(owner_ul) = maps.neighbor_nat_lookup(in_.vni, dst, dport) {
                        let tunnel = reforward(in_.vni, &owner_ul);
                        return UplinkOut {
                            action: Action::Redirect(in_.local.uplink_ifindex),
                            tunnel: Some(tunnel),
                        };
                    }
                }
                dst
            };
            // Mechanisms #1 (normal/DNAT'd guest delivery) + #4 (WAN-edge sentinel / genuine miss).
            match resolve_uplink_target(&*maps, in_.vni, &deliver_dst, in_.local) {
                UplinkTarget::Local {
                    tap_ifindex,
                    guest_mac,
                    peer_capable,
                } => (tap_ifindex, guest_mac, false, peer_capable),
                UplinkTarget::EdgeLocalDeliver => {
                    return UplinkOut {
                        action: edge_local_deliver(pkt, in_.local.uplink_mac, ETH_P_IP),
                        tunnel: None,
                    }
                }
                UplinkTarget::Drop => {
                    return UplinkOut {
                        action: Action::Drop,
                        tunnel: None,
                    }
                }
            }
        }
    };

    // 2. Ingress firewall on NEW inbound flows against the deliver tap.
    if uplink_ingress_firewall_drop(&*pkt, maps, inner_off, in_.vni, tap) {
        return UplinkOut {
            action: Action::Drop,
            tunnel: None,
        };
    }

    // 3. Conntrack: create on miss, refresh (last_seen + TCP state) on hit — but ONLY for non-LB
    //    (LB is DSR — no ct, ingress.rs:266). Refresh mirrors the eBPF `ct_touch`; it is map-only
    //    (never mutates the packet), so it is byte-parity-neutral.
    if !is_lb {
        uplink_track_flow(&*pkt, maps, inner_off, in_.vni, in_.now);
    }

    // 4. Decap outer Eth+IPv6 and rewrite the inner Ethernet for the guest. The delivery tap's `l3`
    //    bit selects the inner dst MAC (zero MAC for an L3 netkit pod; guest_mac for an L2 tap).
    let l3 = resolve_delivery_l3(&*maps, tap);
    let action = match decap_and_rewrite(pkt, tap, guest_mac, ETH_P_IP, l3, peer_capable) {
        Ok(a) => a,
        Err(_) => Action::Drop,
    };
    if action == Action::Drop {
        return UplinkOut {
            action,
            tunnel: None,
        };
    }

    // 5. Ingress-lane policing (keyed by dest tap) — mirrors ingress.rs uplink_rx. Post-decap inner
    // length is the frame delivered to the guest. No cap => pass.
    let in_len = pkt.len() as u64;
    if !crate::meter::ingress_pass(maps, tap, in_len, in_.now) {
        return UplinkOut {
            action: Action::Drop,
            tunnel: None,
        };
    }

    UplinkOut {
        action,
        tunnel: None,
    }
}

/// Ingress firewall check on NEW inbound flows against the deliver tap — v6 mirror of
/// [`uplink_ingress_firewall_drop`] (mirrors [`process_uplink_v6`] step 2), over `CONNTRACK6`/
/// `fw_eval_dir6` instead of the v4 maps. `#[inline(never)]` for the SAME BPF-stack-relief reason:
/// its `CtKey6` frame must be freed before [`uplink_track_flow6`]'s runs, and before the rest of
/// [`process_uplink_v6`]'s locals accumulate on the tail-called `xdp_uplink_v6` stack (P2 Task 4c —
/// this is the same 512B budget the pre-4c hand-inlined `v6_uplink_rx` was already tail-called for).
#[inline(never)]
fn uplink_ingress_firewall_drop6<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &M,
    inner_off: usize,
    vni: u32,
    tap: u32,
) -> bool {
    match ct_key6(pkt, inner_off, vni) {
        Some(key) => {
            maps.conntrack6_get(&key).is_none()
                && fw_eval_dir6(pkt, maps, inner_off, tap, FW_DIR_INGRESS) == FW_ACTION_DROP
        }
        None => false,
    }
}

/// Conntrack create-on-miss / refresh-on-hit — v6 mirror of [`uplink_track_flow`] (mirrors
/// [`process_uplink_v6`] step 3, non-LB only), over `CONNTRACK6`. Map-only (never mutates `pkt`), so
/// byte-parity-neutral. `#[inline(never)]`: same BPF-stack-relief reasoning as
/// [`uplink_ingress_firewall_drop6`].
#[inline(never)]
fn uplink_track_flow6<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &mut M,
    inner_off: usize,
    vni: u32,
    now: u64,
) {
    if let Some(key) = ct_key6(pkt, inner_off, vni) {
        match maps.conntrack6_get(&key) {
            None => ct_create_default6(pkt, maps, inner_off, vni, now),
            Some(mut e) => ct_refresh6(pkt, maps, inner_off, &key, &mut e, now),
        }
    }
}

/// Host `v6_uplink_rx` for the v6 LB + base ingress path, operating in place on `pkt`. v6 mirror of
/// [`process_uplink`] (P2 Task 4c — this is the shared core orchestrator `v6.rs::v6_uplink_rx`
/// previously had NO counterpart for, hand-inlining its own copy with no sim coverage and a
/// fail-OPEN `ROUTES6`-miss default; see the P2 Task-4c design note). Mirrors the (now-former)
/// hand-inlined `v6_uplink_rx`, adapted to the shared-core shape:
///   1. `lb_select_forward_v6` → local backend (deliver to its tap) | remote (reforward, no decap) |
///      None → mechanisms #1/#4 (`resolve_uplink_target6`) — v6 has NO mechanism #3 (neighbor-NAT
///      relay is a v4-only NAT_IPS/NEIGHBOR_NAT concept; there is no v6 NAT) and NO mechanism #2
///      caller (v6 has no NAT-return/NAT64-return dispatch — those translate a v4 inner, so they can
///      only ever be reached via the v4 [`process_uplink_rx`]). A `ROUTES6` miss that is also not the
///      WAN-edge sentinel is a genuine miss: **`Drop`, fail-closed** — this is the security fix (HEAD
///      fell through to `TC_ACT_OK`/`Pass` here, leaking decapped overlay bytes into the local
///      kernel netns on any miss);
///   2. ingress firewall on the inner v6 5-tuple against the deliver tap (new-flow gate);
///   3. conntrack6 create-on-miss / refresh-on-hit, **skipped for LB** (DSR, no ct — mirrors
///      [`process_uplink`] step 3 exactly: LB is stateless-firewalled, every packet re-checked,
///      since no LB flow ever gets a `CONNTRACK6` entry to hit);
///   4. decap + inner-Ethernet rewrite ([`decap_and_rewrite`] with `ETH_P_IPV6` — the rewrite itself
///      is protocol-agnostic, only the stamped ethertype differs from the v4 arm).
///
/// SCOPE (confirmed against the pre-4c `v6.rs`): no ingress-lane metering step — `v6_uplink_rx` never
/// had one (verified back to the pre-tcx `c2cdc55` v6 program; this is a pre-existing, out-of-scope
/// gap, not something this task's fail-open fix touches). No ICMPv6-echo-to-VIP intercept — by design
/// the dataplane does NOT answer ping locally (only ARP/ND/RA/DHCP are); ICMP echo to a VIP is
/// forwarded to a backend by the LB select. (v4's ICMP-error LB relay was rebuilt as F3, v4-only.)
///
/// Returns the delivery `Action`, plus the tunnel-key decision the relay/reforward arm emits (`None`
/// on every other branch) — reuses [`UplinkOut`] (protocol-agnostic).
pub fn process_uplink_v6<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in_: &UplinkIn) -> UplinkOut {
    // Post-decap (P2 Task 5, same as v4): `pkt` IS the inner v6 frame at `ETH_LEN`.
    let inner_off = ETH_LEN;

    // 1. v6 LB dispatch (mirror the pre-4c hand-inlined `v6_uplink_rx`'s LB block).
    let lb_ul = lb_select_forward_v6(&*pkt, &*maps, inner_off, in_.vni);
    let (tap, guest_mac, is_lb, peer_capable) = match lb_ul {
        Some(be) => {
            if be.node_vtep == in_.local.underlay_ipv6 {
                match maps.ifaces6_get(be.vni, &be.overlay_ip) {
                    Some(iv) if iv.is_local != 0 => {
                        (iv.tap_ifindex, iv.guest_mac, true, iv.peer_capable != 0)
                    }
                    _ => {
                        return UplinkOut {
                            action: Action::Drop,
                            tunnel: None,
                        };
                    }
                }
            } else {
                // Remote backend: re-forward — same vni, no decap, packet bytes untouched. The
                // kernel geneve device re-stamps the tunnel key toward `be.node_vtep`.
                let tunnel = reforward(be.vni, &be.node_vtep);
                return UplinkOut {
                    action: Action::Redirect(in_.local.uplink_ifindex),
                    tunnel: Some(tunnel),
                };
            }
        }
        None => {
            let dst = match pkt.read_array::<16>(inner_off + 24) {
                Some(d) => d,
                None => {
                    return UplinkOut {
                        action: Action::Drop,
                        tunnel: None,
                    }
                }
            };
            // Mechanisms #1 (normal guest delivery) + #4 (WAN-edge sentinel / genuine miss). No
            // mechanism #3 here — see this fn's doc comment.
            match resolve_uplink_target6(&*maps, in_.vni, &dst, in_.local) {
                UplinkTarget::Local {
                    tap_ifindex,
                    guest_mac,
                    peer_capable,
                } => (tap_ifindex, guest_mac, false, peer_capable),
                UplinkTarget::EdgeLocalDeliver => {
                    return UplinkOut {
                        action: edge_local_deliver(pkt, in_.local.uplink_mac, ETH_P_IPV6),
                        tunnel: None,
                    }
                }
                UplinkTarget::Drop => {
                    return UplinkOut {
                        action: Action::Drop,
                        tunnel: None,
                    }
                }
            }
        }
    };

    // 2. Ingress firewall on NEW inbound flows against the deliver tap.
    if uplink_ingress_firewall_drop6(&*pkt, maps, inner_off, in_.vni, tap) {
        return UplinkOut {
            action: Action::Drop,
            tunnel: None,
        };
    }

    // 3. Conntrack6: create on miss, refresh (last_seen + TCP state) on hit — but ONLY for non-LB.
    if !is_lb {
        uplink_track_flow6(&*pkt, maps, inner_off, in_.vni, in_.now);
    }

    // 4. Decap already ran (kernel); rewrite the inner Ethernet for the guest (ethertype = IPv6). The
    //    delivery tap's `l3` bit selects the inner dst MAC (zero MAC on L3 netkit; guest_mac on L2).
    let l3 = resolve_delivery_l3(&*maps, tap);
    let action = match decap_and_rewrite(pkt, tap, guest_mac, ETH_P_IPV6, l3, peer_capable) {
        Ok(a) => a,
        Err(_) => Action::Drop,
    };

    UplinkOut {
        action,
        tunnel: None,
    }
}

/// Inputs for [`process_guest_tx`]. `meta` is the sending port's `PortMeta` (vni + guest/gateway
/// identity + underlay); `src_ifindex` is the source (guest tap) ifindex the egress firewall +
/// meter are keyed on (the eBPF path uses the frame's ingress_ifindex); `now` is the monotonic
/// clock (ns) the egress meter stamps `last_ns`/EDT cursor from (models `bpf_ktime_get_ns()`).
pub struct GuestTxIn<'a> {
    pub meta: &'a PortMeta,
    pub src_ifindex: u32,
    pub now: u64,
}

/// Result of [`process_guest_tx`] / [`process_guest_tx_v6`]: the delivery `Action`, plus the EDT
/// departure timestamp (ns) recorded when the Encap arm hit the `edt_egress` shaping path, plus the
/// tunnel-key decision the Encap arm emits (`None` on Local/Pass). `edt_tstamp` is `None` when the
/// interface has no egress cap (`total_bps == 0`) / no METER entry, and on the Local/Pass verdicts
/// (which leave it untouched — the eBPF `tc_guest_tx` only stamps on the Encap arm). Wire bytes are
/// unchanged by EDT (FQ pacing is kernel-side) AND by the Encap arm itself (see [`TunnelEncap`]).
pub struct GuestTxOut {
    pub action: Action,
    pub edt_tstamp: Option<u64>,
    pub tunnel: Option<TunnelEncap>,
}

/// Guest egress (`guest_tx`) for the IPv4 forwarding path, operating in place on `pkt`. `pkt` is a
/// full guest Ethernet frame `[InnerEth(14)][IPv4][L4]`. Composes the REAL core fns in the exact
/// order + gates of the eBPF `egress::forward_decision_v4` for the byte-parity-relevant steps:
///   1. conntrack: on a NEW flow (miss) enforce the SOURCE egress firewall (deny-by-default);
///      an established flow's CT_REWRITE_SRC translation (ct_apply) is NOT modelled here (separate
///      slice) — the anchor + tests exercise fresh flows. The last_seen/TCP-state refresh on a hit
///      (ct_refresh, mirroring the eBPF ct_touch) IS applied in step 5 (map-only, byte-neutral);
///   2. VIP snat/dnat: NOT modelled (separate slice; anchor installs no VIP maps → no-op);
///   3. route lookup (`route4`) → Pass on miss;
///   4. network NAT SNAT (`snat_egress`) when the route is external;
///   5. conntrack: create-on-miss (`ct_create_default`) / refresh-on-hit (`ct_refresh`, last_seen +
///      TCP state — the eBPF `ct_touch`); both map-only, byte-neutral;
///   6. rate metering: public-lane policing (`public_pass`, external only, step 6a). Mirrors
///      `egress.rs`. No METER entry => unlimited (pass). `now` comes from `in_.now`;
///   7. deliver decision (`deliver`): Local tap (inner-Eth rewrite) | Encap (`TunnelEncap` decision,
///      no byte write) | Pass. In the Encap arm ONLY, EDT egress shaping (`edt_egress`, records
///      `edt_tstamp`, no drop, step 6b) is called using `pkt.len() + GENEVE_OVERHEAD` — mirrors
///      `tc.rs` `edt_stamp`. `pkt.len()` alone is the INNER frame length (no outer bytes are written
///      anymore — see `TunnelEncap`); `GENEVE_OVERHEAD` adds back the kernel's outer
///      Eth/IPv6/UDP/Geneve bytes so shaping reflects real wire bytes. Local/Pass leave `edt_tstamp`
///      as `None` (EDT shaping applies only on the encap/uplink egress path).
///
/// Returns the delivery `Action` + the EDT timestamp, having mutated `pkt` in place.
///
/// NOTE (scope): only the fresh-flow / non-VIP path is composed here for the OUTPUT PACKET — that
/// slice is byte-identical to the eBPF program and thus anchorable. Metering does not mutate packet
/// bytes (it only reads/writes the METER map and returns a verdict), so with no METER entry the
/// emitted bytes are unaffected; the interleaved un-ported step (ct_apply, vip) and the
/// ct_refresh hit-path are map/refresh-only on this fixture and do not change the emitted bytes.
pub fn process_guest_tx<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in_: &GuestTxIn) -> GuestTxOut {
    // Reset the stamp so a Local/Pass verdict leaves edt_tstamp = None (unshaped), matching the
    // eBPF `tc_guest_tx` which only calls `edt_stamp` on the Encap arm.
    let mut edt_tstamp: Option<u64> = None;
    let ip_off = ETH_LEN;

    // 1. Conntrack miss → source egress firewall (deny-by-default). Fresh flow only.
    let mut was_new = false;
    if let Some(key) = ct_key(&*pkt, ip_off, in_.meta.vni) {
        if maps.conntrack_get(&key).is_none() {
            was_new = true;
            // Egress firewall keyed on the SOURCE interface. The sim keys FW_META/FW_RULES on a
            // synthetic ifindex == meta.vni's port; the fixture installs it under `src_ifindex`.
            if fw_eval_dir(&*pkt, &*maps, ip_off, in_.src_ifindex, FW_DIR_EGRESS) == FW_ACTION_DROP
            {
                return GuestTxOut {
                    action: Action::Drop,
                    edt_tstamp,
                    tunnel: None,
                };
            }
        }
    }

    // 2. VIP snat/dnat: not modelled (no VIP maps → no-op in the eBPF path too).

    // 3. Route lookup on the inner IPv4 dst.
    let dst = match pkt.read_array::<4>(ip_off + 16) {
        Some(d) => d,
        None => {
            return GuestTxOut {
                action: Action::Pass,
                edt_tstamp,
                tunnel: None,
            }
        }
    };
    let route = match route4(&*maps, in_.meta.vni, &dst) {
        Some(r) => r,
        None => {
            return GuestTxOut {
                action: Action::Pass,
                edt_tstamp,
                tunnel: None,
            }
        }
    };

    // 4. Network NAT SNAT when the route is external. Pass the REAL `now` (not 0): `snat_egress`
    // stamps the peer-independent reverse conntrack entry's `last_seen` from it, and the return path's
    // idle-timeout GC (`shared_ct_sweep_expired` → `ct_is_expired = now - last_seen > timeout`) would
    // otherwise treat a `last_seen == 0` entry as expired the instant a real monotonic clock sweeps it
    // — silently evicting every SNAT reverse entry and breaking NAT-return. Mirrors the eBPF path,
    // which already passes `conntrack::now()` here (egress.rs); tests using `now: 0` are unaffected
    // (they stamp 0 and never sweep with a real clock).
    let is_ext = route.is_external != 0;
    if snat_egress(pkt, maps, ip_off, in_.meta.vni, is_ext, in_.now) == SnatOutcome::Exhausted {
        return GuestTxOut {
            action: Action::Drop,
            edt_tstamp,
            tunnel: None,
        };
    }

    // 5. Track every flow: create-on-miss, refresh (last_seen + TCP state) on hit. Refresh mirrors
    //    the eBPF `ct_touch`; it is map-only (never mutates the packet), so it is byte-parity-neutral.
    //    Keyed on the POST-SNAT 5-tuple, exactly as the create path (and the reverse NAT entry).
    if let Some(key) = ct_key(&*pkt, ip_off, in_.meta.vni) {
        match maps.conntrack_get(&key) {
            None => ct_create_default(&*pkt, maps, ip_off, in_.meta.vni, in_.now),
            Some(mut e) => ct_refresh(&*pkt, maps, ip_off, &key, &mut e, in_.now),
        }
    }

    // 6. Egress metering — mirrors the eBPF split in egress.rs + tc.rs:
    //    a) Public-lane policing (drop-on-exhaust, external only) — mirrors egress.rs `public_pass`.
    //    b) EDT egress shaping — mirrors tc.rs `edt_stamp`, called ONLY in the Encap arm (step 7).
    //       Same-node LOCAL delivery is unshaped (eBPF `tc_guest_tx` only stamps on the Encap
    //       arm, after `adjust_room`). `edt_tstamp` stays `None` for Local / Pass.
    let frame_len = pkt.len() as u64;
    // a) Public-lane policing (external egress only) — mirrors egress.rs. `public_pass` only
    // actually measures `len` when `is_ext` (else it short-circuits to pass), and an external route
    // leaves via the Encap arm below (no outer bytes written there — see `TunnelEncap`), so the
    // GENEVE_OVERHEAD compensation belongs here: `frame_len` is the INNER length only; add the
    // kernel's outer Eth/IPv6/UDP/Geneve bytes back in so the policer measures real wire bytes.
    if !crate::meter::public_pass(
        maps,
        in_.src_ifindex,
        frame_len + GENEVE_OVERHEAD as u64,
        is_ext,
        in_.now,
    ) {
        return GuestTxOut {
            action: Action::Drop,
            edt_tstamp,
            tunnel: None,
        };
    }

    // 7. Deliver decision: Local tap (inner-Eth rewrite) | Encap (`TunnelEncap` decision) | Pass.
    //    Local delivery is demuxed by the overlay dst (vni, inner IPv4) via INTERFACES.
    let mut dst16 = [0u8; 16];
    dst16[..4].copy_from_slice(&dst);
    match deliver(&*maps, in_.meta.vni, &dst16, false, &route) {
        Deliver::Local {
            tap_ifindex,
            guest_mac,
        } => {
            // Destination ingress firewall on NEW flows (same-node delivery).
            if was_new
                && fw_eval_dir(&*pkt, &*maps, ip_off, tap_ifindex, FW_DIR_INGRESS) == FW_ACTION_DROP
            {
                return GuestTxOut {
                    action: Action::Drop,
                    edt_tstamp,
                    tunnel: None,
                };
            }
            // Rewrite the inner Ethernet for the local guest: dst=guest MAC, src=GW_MAC,
            // ethertype stays IPv4. Same-node delivery is unshaped — edt_tstamp left as-is.
            pkt.write_bytes(0, &guest_mac);
            pkt.write_bytes(6, &GW_MAC);
            GuestTxOut {
                action: Action::Redirect(tap_ifindex),
                edt_tstamp,
                tunnel: None,
            }
        }
        Deliver::Encap {
            tunnel,
            uplink_ifindex,
        } => {
            // No byte write (see `TunnelEncap`): EDT egress shaping stamps off the (unchanged)
            // inner frame length PLUS `GENEVE_OVERHEAD` — the kernel's `collect_md` geneve device
            // adds the outer Eth/IPv6/UDP/Geneve bytes on transmit, so shaping needs to reflect the
            // real wire size, not just what this program can see. Mirrors tc.rs `edt_stamp`.
            edt_tstamp = crate::meter::edt_egress(
                maps,
                in_.src_ifindex,
                pkt.len() as u64 + GENEVE_OVERHEAD as u64,
                in_.now,
            );
            GuestTxOut {
                action: Action::Redirect(uplink_ifindex),
                edt_tstamp,
                tunnel: Some(tunnel),
            }
        }
        Deliver::Pass => GuestTxOut {
            action: Action::Pass,
            edt_tstamp,
            tunnel: None,
        },
    }
}

/// Guest egress (`guest_tx`) for the NATIVE IPv6→IPv6 forwarding path, operating in place on `pkt`.
/// `pkt` is a full guest Ethernet frame `[InnerEth(14)][IPv6(40)][L4]` whose dst is NOT in the NAT64
/// prefix (the caller runs [`process_guest_tx_nat64`] first for `64:ff9b::/96` dsts). Composes the
/// two SHARED core stages the eBPF `egress::forward_decision_v6` delegates to, in its exact order +
/// gates:
///   1. egress firewall + firewall-only v6 conntrack ([`egress_fw_ct6`]): deny-by-default on a fresh
///      flow (CT miss → `fw_eval_dir6` DROP), else track (`ct_create_default6`) / refresh
///      (`ct_refresh6`); carries `was_new` (CT miss) up to the local fast path;
///   2. route6 + deliver ([`route_decision6`]): `route6` → Pass on miss, else `deliver` →
///      Local / Encap / Pass. The flow label is folded from the (immutable, no-SNAT) inner v6
///      5-tuple, matching the eBPF `egress_flow_label(.., is_v6 = true)`;
///   3. on `Deliver::Local` to a SAME-NODE guest, enforce the DESTINATION's ingress firewall on NEW
///      flows only (`fw_eval_dir6` INGRESS, deny-by-default) — mirrors the v4 [`process_guest_tx`]
///      Local arm (the cross-node `uplink_rx` ingress path is bypassed for same-node delivery).
///
/// Verdict mapping (mirrors [`process_guest_tx`]):
///   - `Deliver::Encap { tunnel, uplink_ifindex }` → no byte write (see [`TunnelEncap`]) — EDT
///     egress shaping (`edt_egress`, records `edt_tstamp`) stamps off `pkt.len() + GENEVE_OVERHEAD`
///     (the unchanged inner frame length, plus the kernel's outer Eth/IPv6/UDP/Geneve bytes so
///     shaping reflects real wire bytes) → `Redirect(uplink_ifindex)`. This is now representation-
///     identical to the v4 encap arm; the old v4/v6 outer next-header difference (IPIP vs
///     IPPROTO_IPV6) no longer exists on the wire here — the packet's own ethertype already says
///     which it is;
///   - `Deliver::Local { tap_ifindex, guest_mac }` → inner-Eth rewrite (dst = guest_mac, src =
///     GW_MAC, ethertype stays IPv6) → `Redirect(tap_ifindex)`, unshaped (`edt_tstamp = None`);
///   - `Deliver::Pass` → `Action::Pass`.
///
/// SCOPE: native v6→v6 ONLY. There is NO NAT64 here (v6→v4 lives in [`process_guest_tx_nat64`]) and
/// no VIP/network-NAT (v6 firewall + conntrack6 only, matching the eBPF v6 path). Returns the
/// delivery `Action` + the EDT timestamp, having mutated `pkt` in place.
pub fn process_guest_tx_v6<P: Pkt, M: Maps>(
    pkt: &mut P,
    maps: &mut M,
    in_: &GuestTxIn,
) -> GuestTxOut {
    let mut edt_tstamp: Option<u64> = None;
    let ip_off = ETH_LEN;

    // Stage 1: egress firewall + firewall-only v6 conntrack (deny-by-default on a fresh flow).
    let was_new = match egress_fw_ct6(&*pkt, maps, ip_off, in_.src_ifindex, in_.meta.vni, in_.now) {
        EgressFwCt6::Drop => {
            return GuestTxOut {
                action: Action::Drop,
                edt_tstamp,
                tunnel: None,
            }
        }
        EgressFwCt6::Pass { was_new } => was_new,
    };

    // Stage 2: route6 + deliver.
    match route_decision6(&*pkt, &*maps, in_.meta) {
        Deliver::Local {
            tap_ifindex,
            guest_mac,
        } => {
            // Stage 3: destination ingress firewall on NEW flows (same-node delivery). Deny-by-default.
            // v6 evaluator (fw_eval_dir6 / FW_META6) — mirrors the eBPF dest_ingress_fw_v6.
            if was_new
                && crate::firewall::fw_eval_dir6(&*pkt, &*maps, ip_off, tap_ifindex, FW_DIR_INGRESS)
                    == FW_ACTION_DROP
            {
                return GuestTxOut {
                    action: Action::Drop,
                    edt_tstamp,
                    tunnel: None,
                };
            }
            // Rewrite the inner Ethernet for the local guest: dst=guest MAC, src=GW_MAC; the
            // ethertype stays IPv6 (0x86DD) — the frame was already v6, so it is left untouched
            // (mirrors the eBPF tc_guest_egress_v6 Local arm, which rewrites the two MACs).
            pkt.write_bytes(0, &guest_mac);
            pkt.write_bytes(6, &GW_MAC);
            GuestTxOut {
                action: Action::Redirect(tap_ifindex),
                edt_tstamp,
                tunnel: None,
            }
        }
        Deliver::Encap {
            tunnel,
            uplink_ifindex,
        } => {
            // No byte write (see `TunnelEncap`); GENEVE_OVERHEAD compensates for the kernel's outer
            // bytes not being visible to this program (mirrors the v4 arm).
            edt_tstamp = crate::meter::edt_egress(
                maps,
                in_.src_ifindex,
                pkt.len() as u64 + GENEVE_OVERHEAD as u64,
                in_.now,
            );
            GuestTxOut {
                action: Action::Redirect(uplink_ifindex),
                edt_tstamp,
                tunnel: Some(tunnel),
            }
        }
        Deliver::Pass => GuestTxOut {
            action: Action::Pass,
            edt_tstamp,
            tunnel: None,
        },
    }
}

/// Inputs for [`process_uplink_nat_return`]. `local` supplies the WAN-edge-sentinel fallback input
/// to [`resolve_uplink_target`] (mechanism #4) — in practice a NAT-return always resolves via
/// mechanism #2 (the reverse CT entry's `xlate_ip` is on THIS node, since conntrack is never
/// synced across nodes), so `local` only matters for the (never-expected) miss case.
pub struct UplinkNatReturnIn<'a> {
    pub vni: u32,
    pub local: &'a Local,
}

/// Host NAT reverse-DNAT return path, in place on `pkt`. Mirrors the eBPF `try_uplink_rx` NAT branch:
/// build the inner 5-tuple key (demuxed peer-independently when the inner dst is a registered nat_ip);
/// reverse-DNAT apply when the matched CT entry carries `CT_REWRITE_DST`; resolve the delivery
/// target (mechanism #2 — see [`resolve_uplink_target`]) from the RESTORED guest IPv4 the reverse
/// entry's `xlate_ip` carries; decap + inner-Eth rewrite.
/// `#[inline(never)]`: ingress-only, same BPF-stack-relief reasoning as [`process_uplink`].
#[inline(never)]
pub fn process_uplink_nat_return<P: Pkt, M: Maps>(
    pkt: &mut P,
    maps: &mut M,
    in_: &UplinkNatReturnIn,
) -> Action {
    // Post-decap (P2 Task 5): see `process_uplink`'s doc comment on the same offset change.
    let inner_off = ETH_LEN;
    let mut xlate_ip: Option<[u8; 4]> = None;

    // 1. Build the inner 5-tuple key; NAT returns are demuxed peer-independently.
    if let Some(mut key) = ct_key(&*pkt, inner_off, in_.vni) {
        if maps.is_nat_ip(in_.vni, &key.dst_ip) {
            key.src_ip = [0; 4];
            key.src_port = 0;
        }
        // 2. Reverse-DNAT apply when the matched entry carries CT_REWRITE_DST.
        if let Some(e) = maps.conntrack_get(&key) {
            if e.flags & CT_REWRITE_DST != 0 {
                ct_apply(pkt, inner_off, &e);
                xlate_ip = Some(e.xlate_ip);
            }
        }
    }

    // 3. Resolve delivery (mechanism #2) + rewrite the inner Ethernet for the guest (decap already
    // ran via `ct_apply`'s address restore — the frame itself still needs the outer Eth+IPv6 strip).
    let dst = match xlate_ip {
        Some(ip) => ip,
        // No CT_REWRITE_DST hit: this function's entire purpose is the established-NAT-return path
        // (its callers only invoke it after confirming a hit), so a miss here means there is no
        // legitimate delivery target to reconstruct. Fail closed.
        None => return Action::Drop,
    };
    match resolve_uplink_target(&*maps, in_.vni, &dst, in_.local) {
        UplinkTarget::Local {
            tap_ifindex,
            guest_mac,
            peer_capable,
        } => {
            // Same delivery-tap `l3` selection as `process_uplink` — an L3 netkit pod can receive
            // NAT returns too, and would drop a unicast guest_mac dst as PACKET_OTHERHOST.
            let l3 = resolve_delivery_l3(&*maps, tap_ifindex);
            match decap_and_rewrite(pkt, tap_ifindex, guest_mac, ETH_P_IP, l3, peer_capable) {
                Ok(a) => a,
                Err(_) => Action::Drop,
            }
        }
        UplinkTarget::EdgeLocalDeliver | UplinkTarget::Drop => Action::Drop,
    }
}

/// Unified host `uplink_rx` entry: makes the base-vs-NAT-return dispatch the eBPF `try_uplink_rx`
/// makes inline (`nat_guest` gate, `ingress.rs:163-209`), in SHARED code, so the native SimNode
/// decides identically instead of re-implementing it. A frame that LB does not claim,
/// whose inner dst is a registered nat_ip with a matching peer-independent `CT_REWRITE_DST` reverse
/// entry, is an established NAT return → [`process_uplink_nat_return`] (reverse-DNAT + deliver, NO
/// ingress firewall: it is the reply to a guest-initiated, already-egress-firewalled flow — see the
/// `nat_guest.is_none()` guard at `ingress.rs:256`). Everything else takes the LB + base path
/// ([`process_uplink`]).
///
/// NAT64 returns (`CT_F_NAT64`) need v4->v6 expansion, not the plain reverse-DNAT: a matching
/// `CT_F_NAT64 | CT_REWRITE_DST` reverse entry dispatches to [`process_uplink_nat64_ingress`]
/// (restores the guest IPv4 dst, then expands back to the guest's overlay IPv6 — sourced from
/// `PORT_META[tap_ifindex].guest_ipv6` once the delivery tap is resolved; see the CT_F_NAT64 branch
/// below).
pub fn process_uplink_rx<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in_: &UplinkIn) -> UplinkOut {
    // Post-decap (P2 Task 5): see `process_uplink`'s doc comment on the same offset change.
    let inner_off = ETH_LEN;

    // NAT-return dispatch — gated on `lb_ul.is_none()` exactly as `try_uplink_rx` (an LB VIP is never
    // itself a nat_ip, but keep the gate to mirror the eBPF ordering precisely).
    if lb_select_forward(&*pkt, &*maps, inner_off, in_.vni).is_none() {
        if let Some(mut key) = ct_key(&*pkt, inner_off, in_.vni) {
            // Peer-independent demux: a registered nat_ip inner dst keys the
            // `(vni,0,nat_ip,0,nat_port)` reverse entry the egress SNAT allocator stored.
            if maps.is_nat_ip(in_.vni, &key.dst_ip) {
                key.src_ip = [0; 4];
                key.src_port = 0;
            }
            if let Some(e) = maps.conntrack_get(&key) {
                if e.flags & CT_REWRITE_DST != 0 {
                    if e.flags & CT_F_NAT64 != 0 {
                        // Refresh the reverse entry (last_seen + TCP state, map-only/byte-neutral) so
                        // an active NAT64 flow is not idle-GC'd mid-session. process_uplink_nat64_ingress
                        // takes no Maps and cannot do it; this mirrors the eBPF ingress `ct_touch` on
                        // the CT_REWRITE_DST reverse entry (which the core path was previously missing).
                        let mut r = e;
                        ct_refresh(&*pkt, maps, inner_off, &key, &mut r, in_.now);
                        // Mechanism #2 (NAT64-return): the reverse entry's `xlate_ip` IS the guest's
                        // real overlay IPv4 (`nat64_egress_parse` pins it from `meta_guest_ipv4`) —
                        // the SAME address the guest's own ROUTES self-route is keyed on, so resolve
                        // delivery exactly as mechanism #1. `process_uplink_nat64_ingress` itself
                        // takes no `Maps` (by design — see its doc comment), so the resolve happens
                        // here, before dispatch. Decap-only — no tunnel decision.
                        let action =
                            match resolve_uplink_target(&*maps, in_.vni, &r.xlate_ip, in_.local) {
                                UplinkTarget::Local {
                                    tap_ifindex,
                                    guest_mac,
                                    // NAT64-return delivery keeps plain bpf_redirect (a niche path;
                                    // process_uplink_nat64_ingress builds its own action). peer-redirect
                                    // is applied to the main uplink + guest-egress local arms.
                                    peer_capable: _,
                                } => {
                                    // The guest's overlay IPv6 is per-tap metadata (`PORT_META`), not
                                    // derivable from `(vni, inner dst)` alone — it can only be read
                                    // NOW, after `tap_ifindex` is resolved (fixes the disclosed gap:
                                    // the eBPF glue used to pass a `[0;16]` placeholder here because
                                    // it cannot know the tap before this dispatch runs, which made
                                    // `nat64_ingress_parse` reject every real NAT64 return and fall
                                    // through to `Action::Pass` — see `ingress.rs`'s former comment).
                                    // Out-of-lined (`#[inline(never)]`): inlining the ~70-byte
                                    // `PortMeta` copy directly into this already-large dispatch
                                    // pushed the verifier's combined-call-stack over budget
                                    // ("combined stack size of 2 calls is 528. Too large") — the
                                    // same BPF-stack-relief pattern as
                                    // [`uplink_ingress_firewall_drop`]/[`uplink_track_flow`].
                                    let guest_ipv6 = resolve_nat64_guest_ipv6(&*maps, tap_ifindex);
                                    process_uplink_nat64_ingress(
                                        pkt,
                                        &UplinkNat64IngressIn {
                                            tap_ifindex,
                                            guest_mac,
                                            guest_ipv6,
                                            rev: &r,
                                        },
                                    )
                                }
                                UplinkTarget::EdgeLocalDeliver | UplinkTarget::Drop => Action::Drop,
                            };
                        return UplinkOut {
                            action,
                            tunnel: None,
                        };
                    }
                    // Mechanism #2 (NAT-return) — resolved internally by `process_uplink_nat_return`
                    // from the reverse entry's restored guest IP. Decap-only — no tunnel decision.
                    let action = process_uplink_nat_return(
                        pkt,
                        maps,
                        &UplinkNatReturnIn {
                            vni: in_.vni,
                            local: in_.local,
                        },
                    );
                    return UplinkOut {
                        action,
                        tunnel: None,
                    };
                }
            }
        }
    }

    process_uplink(pkt, maps, in_)
}

/// Inputs for [`process_uplink_nat64_ingress`]. `rev` is the reverse `CT_F_NAT64` conntrack entry the
/// caller already resolved (restores the guest IPv4 dst + orig L4 port); this fn takes no `Maps`.
pub struct UplinkNat64IngressIn<'a> {
    pub tap_ifindex: u32,
    pub guest_mac: [u8; 6],
    pub guest_ipv6: [u8; 16],
    pub rev: &'a flowplane_common::CtEntry,
}

/// Host NAT64 ingress reply path, in place on `pkt`. Mirrors the eBPF ingress `nat64_ingress`:
/// reverse `ct_apply` → `nat64_ingress_parse` (Pass on miss) → `grow_head(20)` → `nat64_ingress_write`.
///
/// P2 Task 5: post-decap `pkt` arrives as `[InnerEth(14)][InnerIPv4(20)][L4]` (34+L4 bytes) — the
/// kernel already stripped the outer Eth/IPv6/UDP/Geneve header. NAT64 v4→v6 EXPANDS the inner
/// header (IPv4 20 → IPv6 40), so this is a **+20 GROW** to `[Eth(14)][IPv6(40)][L4]` (54+L4 bytes)
/// — the mirror image of `nat64_egress`'s v6→v4 shrink, reversed. (The pre-Task-5 code shrank 20
/// bytes here, which modeled the OLD pre-decap 74→54 collapse; that shape no longer exists.)
///
/// `#[inline(never)]`: ingress-only, same BPF-stack-relief reasoning as [`process_uplink`].
#[inline(never)]
pub fn process_uplink_nat64_ingress<P: Pkt>(pkt: &mut P, in_: &UplinkNat64IngressIn) -> Action {
    let inner_off = ETH_LEN;
    let orig_sport = in_.rev.xlate_port;

    // 1. Reverse conntrack apply: restore the guest IPv4 dst + orig L4 port (+ checksums).
    ct_apply(pkt, inner_off, in_.rev);

    // 2. Parse (IHL/proto/TTL/addrs/checksum + reconstructed 64:ff9b:: IPv6 src).
    let xlate =
        match nat64_ingress_parse(&*pkt, inner_off, in_.guest_ipv6, in_.guest_mac, orig_sport) {
            Some(x) => x,
            None => return Action::Pass,
        };

    // 3. Resize: grow 20 bytes at the front (models adjust_room(+20, BPF_ADJ_ROOM_MAC) /
    // bpf_xdp_adjust_head(-20)) — v4(20)→v6(40) inner header expansion.
    if !pkt.grow_head(20) {
        return Action::Drop;
    }

    // 4. Write: guest Ethernet + inner IPv6 header + L4 translation.
    if !nat64_ingress_write(pkt, ETH_LEN, GW_MAC, &xlate) {
        return Action::Drop;
    }

    Action::Redirect(in_.tap_ifindex)
}

/// Inputs for [`process_guest_tx_nat64`]. `local` supplies the outer MACs/ifindex for the encap;
/// `meta` supplies the vni + guest IPv4 (NAT key) + underlay src.
pub struct GuestTxNat64In<'a> {
    pub meta: &'a flowplane_common::PortMeta,
    pub local: &'a flowplane_common::Local,
}

/// Result of [`process_guest_tx_nat64`]: the delivery `Action`, plus the tunnel-key decision on the
/// (only) encap outcome. `None` on Pass/Drop.
pub struct GuestTxNat64Out {
    pub action: Action,
    pub tunnel: Option<TunnelEncap>,
}

/// Guest NAT64 egress path, in place on `pkt`. Mirrors the eBPF `nat64_egress`: parse (config +
/// port-alloc + CT_F_NAT64 pins) → `shrink_head(20)` (v6→v4) → `nat64_egress_write` → route4 (Pass on
/// miss) → the [`tunnel_encap`] decision toward the nexthop (no byte write — see [`TunnelEncap`]).
pub fn process_guest_tx_nat64<P: Pkt, M: Maps>(
    pkt: &mut P,
    maps: &mut M,
    in_: &GuestTxNat64In,
) -> GuestTxNat64Out {
    let ip6_off = ETH_LEN;

    // 1. Parse (dst-prefix check + NAT config + port alloc + CT_F_NAT64 conntrack inserts).
    let xlate = match nat64_egress_parse(&*pkt, maps, ip6_off, in_.meta.vni, in_.meta.guest_ipv4, 0)
    {
        Some(x) => x,
        None => {
            return GuestTxNat64Out {
                action: Action::Pass,
                tunnel: None,
            }
        }
    };

    // 2. Resize: shrink inner IPv6(40)→IPv4(20) via a 20-byte front drop (models adjust_head(+20)).
    if !pkt.shrink_head(20) {
        return GuestTxNat64Out {
            action: Action::Drop,
            tunnel: None,
        };
    }

    // 3. Write: restore the Ethernet header + build the IPv4 header + translate the L4.
    if !nat64_egress_write(pkt, ETH_LEN, true, &xlate) {
        return GuestTxNat64Out {
            action: Action::Drop,
            tunnel: None,
        };
    }

    // 4. Route lookup on the embedded IPv4 dst.
    let route = match route4(&*maps, in_.meta.vni, &xlate.ipv4_dst) {
        Some(r) => r,
        None => {
            return GuestTxNat64Out {
                action: Action::Pass,
                tunnel: None,
            }
        }
    };

    // 5. Tunnel-key decision toward the route nexthop — no byte write.
    GuestTxNat64Out {
        action: Action::Redirect(in_.local.uplink_ifindex),
        tunnel: Some(tunnel_encap(&route)),
    }
}

/// Inputs for [`process_wan_rx`]. `local` supplies the outer MACs/ifindex + this node's underlay src.
pub struct WanRxIn<'a> {
    pub local: &'a flowplane_common::Local,
}

/// Result of [`process_wan_rx`]: the delivery `Action`, plus the tunnel-key decision on a VIP hit
/// (`None` on Pass).
pub struct WanRxOut {
    pub action: Action,
    pub tunnel: Option<TunnelEncap>,
}

/// Edge WAN-VIP ingress, in place on `pkt`. Mirrors `ingress.rs::try_wan_rx`: dispatch on ethertype
/// (offset 12) — 0x86DD → v6 core select; else v4 core select, falling back to mechanism #3
/// (neighbor-NAT relay, v4-only — `NEIGHBOR_NAT` has no v6 WAN-return path) on an LB miss. On a
/// VIP hit or a neighbor-NAT relay hit, emit the tunnel-key decision (no byte write — see
/// [`TunnelEncap`]) → `Redirect(uplink_ifindex)`; else `Pass`. The WAN LB service space is `vni = 0`
/// (mirrors the `lb_select_forward*(.., 0)` lookup below). The relay hit uses the REAL owner VNI
/// from [`Maps::neighbor_nat_lookup_any`] — the eBPF `try_wan_rx` (ingress.rs:452) discards it
/// (`let (owner_ul, _vni) = ..`), a bug this reconstruction fixes: without the owner's VNI, the
/// relayed packet's tunnel key would carry the WRONG VNI and the owner's peer-independent reverse
/// conntrack key `(vni,0,nat_ip,0,nat_port)` would never match.
pub fn process_wan_rx<P: Pkt, M: Maps>(pkt: &mut P, maps: &M, in_: &WanRxIn) -> WanRxOut {
    let ethertype = match pkt.read_array::<2>(12) {
        Some(b) => u16::from_be_bytes(b),
        None => 0, // frame < 14 bytes → v4 branch (matches plain.get(..).unwrap_or(0))
    };
    let selected = match ethertype {
        0x86DD => lb_select_forward_v6(&*pkt, maps, ETH_LEN, 0),
        _ => lb_select_forward(&*pkt, maps, ETH_LEN, 0),
    };
    if let Some(backend) = selected {
        return WanRxOut {
            action: Action::Redirect(in_.local.uplink_ifindex),
            tunnel: Some(TunnelEncap {
                vni: 0,
                remote: backend.node_vtep,
                dsr_vip: None,
            }),
        };
    }
    // Mechanism #3 (WAN-edge sub-case): a plain WAN-arriving IPv4 packet destined to a nat_ip block
    // owned by some node, relayed toward the owner WITH the owner's real VNI.
    if ethertype != 0x86DD {
        if let Some(dst) = pkt.read_array::<4>(ETH_LEN + 16) {
            if let Some((_proto, _sport, dport)) = l4_ports(&*pkt, ETH_LEN) {
                if let Some((owner_ul, owner_vni)) = maps.neighbor_nat_lookup_any(dst, dport) {
                    return WanRxOut {
                        action: Action::Redirect(in_.local.uplink_ifindex),
                        tunnel: Some(TunnelEncap {
                            vni: owner_vni,
                            remote: owner_ul,
                            dsr_vip: None,
                        }),
                    };
                }
            }
        }
    }
    WanRxOut {
        action: Action::Pass,
        tunnel: None,
    }
}

/// Inputs for [`process_guest_arp_nd`]. Gateway is advertised at the shared router MAC `GW_MAC`.
pub struct GuestArpNdIn {
    pub gateway_ipv4: [u8; 4],
    pub gateway_ipv6: [u8; 16],
    pub ingress_ifindex: u32,
}

/// Guest-facing ARP/ND gateway responder, in place on `pkt`. Mirrors the eBPF `try_guest_tx` head:
/// ARP request for the gateway → ARP reply, else ICMPv6 NS for the gateway → NA, both from `GW_MAC`;
/// on a hit `Redirect(ingress_ifindex)`, else `Pass`.
pub fn process_guest_arp_nd<P: Pkt>(pkt: &mut P, in_: &GuestArpNdIn) -> Action {
    if arp_reply(pkt, in_.gateway_ipv4, GW_MAC) || nd_reply(pkt, in_.gateway_ipv6, GW_MAC) {
        Action::Redirect(in_.ingress_ifindex)
    } else {
        Action::Pass
    }
}

/// Inputs for [`process_guest_dhcp4`]. The assigned/gateway IPv4 + reply MTU/DNS/host come from
/// `meta` + the node's `DHCP_CONFIG`/`DHCP_META[ingress_ifindex]`.
pub struct GuestDhcp4In {
    pub guest_ipv4: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub ingress_ifindex: u32,
}

/// Guest DHCPv4 responder, in place on `pkt`. Mirrors the eBPF `guest_dhcp` glue: parse the
/// DISCOVER/REQUEST (Pass on non-DHCP), resize to the constant `dhcp::REPLY_LEN` (`adjust_tail`), then
/// write the fixed OFFER/ACK; `Redirect(ingress_ifindex)` on success else `Pass`.
pub fn process_guest_dhcp4<P: Pkt, M: Maps>(pkt: &mut P, maps: &M, in_: &GuestDhcp4In) -> Action {
    let req = match dhcp::parse(&*pkt) {
        Some(r) => r,
        None => return Action::Pass,
    };
    pkt.set_tail(dhcp::REPLY_LEN);
    let ok = dhcp::write(
        pkt,
        &req,
        in_.guest_ipv4,
        in_.gateway_ipv4,
        GW_MAC,
        maps,
        in_.ingress_ifindex,
    );
    if ok {
        Action::Redirect(in_.ingress_ifindex)
    } else {
        Action::Pass
    }
}
