//! Ingress uplink_rx orchestrators: the LB + base delivery path ([`process_uplink`] /
//! [`process_uplink_v6`]), the NAT reverse-DNAT return ([`process_uplink_nat_return`]), and the
//! unified dispatch ([`process_uplink_rx`]) that decides base-vs-NAT/NAT64-return exactly as the eBPF
//! `try_uplink_rx`. Split out of the datapath god-file per review P1.2; behavior-preserving.

use flowplane_common::{
    Local, CT_F_NAT64, CT_REWRITE_DST, FW_ACTION_DROP, FW_DIR_INGRESS, UNDERLAY_LOCAL_DELIVER,
};

use crate::conntrack::{
    ct_apply, ct_create_default, ct_create_default6, ct_key, ct_key6, ct_refresh, ct_refresh6,
};
use crate::decap::{decap_and_rewrite, edge_local_deliver, ETH_P_IP, ETH_P_IPV6};
use crate::encap::{reforward, TunnelEncap, ETH_LEN};
use crate::firewall::{fw_eval_dir, fw_eval_dir6};
use crate::lb::{
    lb_select_forward, lb_select_forward_icmp_error, lb_select_forward_icmp_error_v6,
    lb_select_forward_v6,
};
use crate::maps::Maps;
use crate::nat::nat_return_rewrite6;
use crate::parse::{l4_ports, l4_ports_v6};
use crate::pkt::{Action, Pkt};

use super::nat64::{process_uplink_nat64_ingress, UplinkNat64IngressIn};
use super::vip_dnat_rewrite;

/// Inputs for [`process_uplink`]. Under Geneve `collect_md` the kernel decaps before this runs and
/// `get_tunnel_key` recovers only the VNI + sender remote — NOT "which local identity to deliver
/// to". So `vni` (from `get_tunnel_key().tunnel_id`) + the inner packet + maps are the ONLY inputs
/// the delivery-target reconstruction (see [`resolve_uplink_target`]) has to work with. `local`
/// supplies the outer MACs/ifindex for an LB remote `reforward` / neighbor-NAT relay / WAN-edge
/// local-deliver rewrite; `now` is the monotonic clock (ns) the ingress-lane meter stamps `last_ns`
/// from (models `bpf_ktime_get_ns()`). There is no `guest_ipv6` field: the CT_F_NAT64 reverse-return
/// path (see [`process_uplink_rx`]) needs the delivery tap resolved FIRST (it is per-tap `PORT_META`
/// metadata), which only happens inside the dispatch itself — so it is read from `Maps` there,
/// not threaded in as an input the caller can't yet know.
pub struct UplinkIn<'a> {
    pub vni: u32,
    pub local: &'a Local,
    pub now: u64,
}

/// The outcome of reconstructing WHERE to deliver a decapped inner frame from `(vni, inner dst)` plus
/// maps alone — this covers mechanism ONE (normal guest self-route) and mechanism FOUR (WAN-edge
/// sentinel / genuine miss) of the four-mechanism ingress delivery-target reconstruction.
/// Mechanism TWO (NAT-return) and mechanism THREE (LB remote-backend /
/// neighbor-NAT relay) are resolved by their own callers instead — a plain `ROUTES`/`ROUTES6` lookup
/// on the CURRENT packet bytes isn't the right tool for those (mechanism TWO keys off the reverse
/// conntrack entry's restored guest IP, not the packet; mechanism THREE keys off `NEIGHBOR_NAT`, not
/// `ROUTES`) — but mechanism TWO's callers reuse THIS resolver once they have the restored guest IP,
/// since that address is exactly what the guest's own self-route is keyed on. Protocol-agnostic (the
/// `tap_ifindex`/`guest_mac` a v4 self-route and a v6 self-route resolve to look identical) — shared
/// by both [`resolve_uplink_target`] (v4) and [`resolve_uplink_target6`] (v6).
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
/// it is verifier-safe and reclaims frame budget in its callers. `process_uplink`'s inlined frame —
/// with its packet-reading (must-stay-inlined) ICMP-error relay + VIP-DNAT arm — would otherwise
/// exceed the eBPF verifier's combined-2-call stack budget; keeping this larger, pkt-free helper
/// out-of-line holds `uplink_rx` under budget without a pkt-pointer-tracking regression.
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
/// an `INTERFACES6` miss. v6 mirror of [`resolve_uplink_target`] — v6 has no NAT/NAT64-return
/// mechanism TWO caller (those are v4-only; see [`process_uplink_v6`]'s doc comment), so this is used
/// by [`process_uplink_v6`] alone. The `local.underlay_ipv6`/`UNDERLAY_LOCAL_DELIVER` sentinel check
/// is the SAME node-identity lookup the v4 resolver uses — the WAN-edge role isn't protocol-specific.
///
/// SECURITY DEFAULT: an `INTERFACES6` miss that is also not the edge sentinel returns
/// `UplinkTarget::Drop`, never a pass-through — a decapped overlay v6 frame with no legitimate local
/// claimant must never be handed to this node's own kernel netns. This is the same fail-closed
/// default the v4 resolver has.
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
/// ct_key-miss-gated call is the out-of-lining lever, splitting it from
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

/// Returns the final delivery `Action` (+ tunnel decision on a relay/reforward arm), having mutated
/// `pkt` in place.
///
/// Deliberately NOT `#[inline(never)]`: its body is small (steps 2/3/5 are out-of-line subprograms —
/// see [`uplink_ingress_firewall_drop`]/[`uplink_track_flow`]/`meter::ingress_pass`), so merging it
/// into its single real-eBPF call site (`ingress.rs::try_uplink_rx` via `process_uplink_rx`) keeps
/// `uplink_rx`'s combined-call chain 2 levels deep to each out-of-line stage instead of 3, under the
/// eBPF verifier's stack budget.
pub fn process_uplink<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in_: &UplinkIn) -> UplinkOut {
    // Post-decap: the kernel `collect_md` geneve device already stripped the outer Eth/IPv6/UDP/Geneve
    // header before this program runs — `pkt` IS the inner frame, so the inner 5-tuple/route lookups
    // read at `ETH_LEN`, not `ETH_LEN + IPV6_LEN`.
    let inner_off = ETH_LEN;

    // 1. LB dispatch. The ICMP-error relay wins first: an ICMP error destined to a VIP must follow
    //    its EMBEDDED flow's backend, not the (mis-hashed) outer ICMP tuple. Everything else — incl.
    //    a normal ICMP echo to a VIP — falls through to the plain select (echo load-balances to a
    //    backend; it is NOT answered by the dataplane).
    // The ICMP-error relay result is captured separately so step 2 below can EXEMPT it from the ingress
    // firewall (PMTUD fix): the relayed error carries an OUTER ICMP tuple (src = erroring router, proto
    // = ICMP), which a typical backend policy ("allow TCP/443 from any") never matches, so the shared
    // default-deny would blackhole PMTUD / dest-unreachable feedback. LB is DSR/stateless-firewalled
    // (no conntrack RELATED state to consult), so the relay arm is exempted wholesale — mirroring how a
    // stateful firewall admits an ICMP error embedding a tracked flow. The relay only ever fires for an
    // error whose EMBEDDED src is a real LB VIP with a live backend, so the surface is an ICMP error
    // delivered to the backend that owns that flow, which its own IP stack still validates.
    let icmp_relay = lb_select_forward_icmp_error(&*pkt, &*maps, inner_off, in_.vni);
    let is_icmp_relay = icmp_relay.is_some();
    let lb_ul = icmp_relay.or_else(|| lb_select_forward(&*pkt, &*maps, inner_off, in_.vni));
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
                    // The DSR reverse-VIP note (`conntrack::dsr_note`) is recorded by the separate
                    // `uplink_dsr_note` tcx pre-program (see `flowplane-ebpf/src/ingress.rs`), not
                    // here — keeping its `ct_key` build off this call graph holds `uplink_rx`'s
                    // combined stack under the verifier's 512-byte budget. That program notes the VIP
                    // unconditionally whenever the DSR option is present, without re-confirming
                    // local-backend delivery the way this branch does.
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
            // 1:1 floating-IP ingress DNAT. `VIPS[(vni,V)] = G` means dst V must be rewritten to the
            // backing guest G and delivered locally (VIPS is only programmed on the node that owns G —
            // the `--vip` CLI maps a node's OWN guest — so a non-local G is a misconfig -> Drop, and
            // there is no reforward arm). A floating IP is never a nat_ip, so a VIP hit SKIPS the
            // neighbor-NAT relay. Compute a single `deliver_dst` and fall through to ONE
            // `resolve_uplink_target` below — duplicating that (inlined) match in a separate VIP branch
            // blows the eBPF verifier's combined-call stack budget ("combined stack size of 2 calls is
            // 528"), regressing `uplink_rx` load.
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

    // 2. Ingress firewall on NEW inbound flows against the deliver tap. EXEMPT the ICMP-error relay
    //    (PMTUD fix — see the `is_icmp_relay` capture above): the relayed error's outer ICMP tuple would
    //    never match the backend's L4 policy, so evaluating it here blackholes PMTUD feedback.
    if !is_icmp_relay && uplink_ingress_firewall_drop(&*pkt, maps, inner_off, in_.vni, tap) {
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
/// [`process_uplink_v6`]'s locals accumulate on the tail-called `xdp_uplink_v6` stack (the 512B
/// verifier budget the v6 program is tail-called into a fresh stack for).
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
/// [`process_uplink`], sharing the core orchestrator shape so the sim and the eBPF program run the
/// same code:
///   1. `lb_select_forward_v6` → local backend (deliver to its tap) | remote (reforward, no decap) |
///      None → mechanisms #1/#4 (`resolve_uplink_target6`) — v6 has NO mechanism #3 (neighbor-NAT
///      relay is a v4-only NAT_IPS/NEIGHBOR_NAT concept; there is no v6 NAT) and NO mechanism #2
///      caller (v6 has no NAT-return/NAT64-return dispatch — those translate a v4 inner, so they can
///      only ever be reached via the v4 [`process_uplink_rx`]). A `ROUTES6` miss that is also not the
///      WAN-edge sentinel is a genuine miss: **`Drop`, fail-closed** — a decapped overlay v6 frame
///      with no legitimate local claimant must never leak into the local kernel netns;
///   2. ingress firewall on the inner v6 5-tuple against the deliver tap (new-flow gate);
///   3. conntrack6 create-on-miss / refresh-on-hit, **skipped for LB** (DSR, no ct — mirrors
///      [`process_uplink`] step 3 exactly: LB is stateless-firewalled, every packet re-checked,
///      since no LB flow ever gets a `CONNTRACK6` entry to hit);
///   4. decap + inner-Ethernet rewrite ([`decap_and_rewrite`] with `ETH_P_IPV6` — the rewrite itself
///      is protocol-agnostic, only the stamped ethertype differs from the v4 arm).
///
/// SCOPE: no ingress-lane metering step — the v6 ingress path has none (a known gap). No
/// ICMPv6-echo-to-VIP intercept — by design the dataplane does NOT answer ping locally (only
/// ARP/ND/RA/DHCP are); ICMP echo to a VIP is forwarded to a backend by the LB select. The
/// ICMP-error LB relay is v4-only.
///
/// Returns the delivery `Action`, plus the tunnel-key decision the relay/reforward arm emits (`None`
/// on every other branch) — reuses [`UplinkOut`] (protocol-agnostic).
pub fn process_uplink_v6<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in_: &UplinkIn) -> UplinkOut {
    // Post-decap (same as v4): `pkt` IS the inner v6 frame at `ETH_LEN`.
    let inner_off = ETH_LEN;

    // 0. NAT66-return reverse-DNAT (v6 sibling of `process_uplink_rx`'s NAT branch). If the inner dst
    //    is a LOCALLY-owned nat_ip6 with a matching peer-independent `CT_REWRITE_DST` reverse entry,
    //    rewrite dst->guest (+ L4 dport) IN PLACE — in its OWN small #[inline(never)] frame (stack
    //    budget: the resolve/decap tail below is shared with normal delivery, so we do NOT duplicate
    //    it here) — then FALL THROUGH to the shared delivery, skipping the ingress firewall (it is a
    //    reply to an already-egress-firewalled guest flow). A REMOTE-owned nat_ip6 has no local
    //    reverse entry → not rewritten here → the neighbor-NAT relay (mechanism #3) below re-forwards.
    let is_nat_return = nat_return_dnat6(pkt, maps, in_.vni);

    // 1. v6 LB dispatch. The ICMPv6-error
    //    relay wins first (v6 sibling of `process_uplink`'s v4 or_else at the top of this file): an
    //    ICMPv6 error destined to a VIP must follow its EMBEDDED flow's backend, not the (mis-hashed)
    //    outer ICMPv6 tuple. Everything else — incl. a normal ICMPv6 echo to a VIP — falls through to
    //    the plain v6 select (echo load-balances to a backend; it is NOT answered by the dataplane).
    // ICMPv6-error relay captured separately so step 2 can EXEMPT it from the ingress firewall (PMTUD
    // fix — v6 sibling of `process_uplink`'s `is_icmp_relay`): the relayed error's outer ICMPv6 tuple
    // (nexthdr = 58) never matches a backend's TCP/UDP policy, so the shared default-deny would
    // blackhole the ICMPv6 Packet-Too-Big PMTUD feedback. Same DSR/stateless-firewall rationale as v4.
    let icmp_relay = lb_select_forward_icmp_error_v6(&*pkt, &*maps, inner_off, in_.vni);
    let is_icmp_relay = icmp_relay.is_some();
    let lb_ul = icmp_relay.or_else(|| lb_select_forward_v6(&*pkt, &*maps, inner_off, in_.vni));
    let (tap, guest_mac, is_lb, peer_capable) = match lb_ul {
        Some(be) => {
            if be.node_vtep == in_.local.underlay_ipv6 {
                match maps.ifaces6_get(be.vni, &be.overlay_ip) {
                    // See the v4 `process_uplink`'s matching comment — the DSR reverse-VIP note
                    // (`conntrack::dsr_note6`) is recorded by the separate `uplink_dsr_note` tcx
                    // pre-program (verifier stack budget), not here.
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
            // Mechanism #3 (NAT66 neighbor-NAT relay): the inner dst may be a nat_ip6 owned by
            // ANOTHER node (an OWNED nat_ip6 instead demuxes via the CT-based return path at the top
            // of this fn). Mirror of v4 `process_uplink`'s neighbor-NAT relay.
            if let Some((_proto, _sport, dport)) = l4_ports_v6(&*pkt, inner_off) {
                if let Some(owner_ul) = maps.neighbor_nat_lookup6(in_.vni, dst, dport) {
                    let tunnel = reforward(in_.vni, &owner_ul);
                    return UplinkOut {
                        action: Action::Redirect(in_.local.uplink_ifindex),
                        tunnel: Some(tunnel),
                    };
                }
            }
            // Mechanisms #1 (normal guest delivery) + #4 (WAN-edge sentinel / genuine miss).
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

    // 2. Ingress firewall on NEW inbound flows against the deliver tap. SKIPPED for a NAT66 return
    //    (it is the reply to an already-egress-firewalled guest flow — mirrors the v4 nat-return path,
    //    which bypasses the ingress firewall) AND for the ICMPv6-error relay (PMTUD fix — see the
    //    `is_icmp_relay` capture above; the relayed error's outer ICMPv6 tuple never matches L4 policy).
    if !is_nat_return
        && !is_icmp_relay
        && uplink_ingress_firewall_drop6(&*pkt, maps, inner_off, in_.vni, tap)
    {
        return UplinkOut {
            action: Action::Drop,
            tunnel: None,
        };
    }

    // 3. Conntrack6: create on miss, refresh (last_seen + TCP state) on hit — but ONLY for non-LB and
    //    non-NAT-return (a return is tracked by the guest's egress-side conntrack6, not re-tracked).
    if !is_lb && !is_nat_return {
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
    // Post-decap: see `process_uplink`'s doc comment on the same offset change.
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

/// NAT66 reverse-DNAT (v6 sibling of the v4 nat-return's `ct_apply` step). If the inner dst is a
/// LOCALLY-owned nat_ip6 with a peer-independent `CT_REWRITE_DST` reverse entry in `NAT_CT6`, rewrite
/// the inner dst v6 + L4 dport back to the guest ([`nat_return_rewrite6`]) IN PLACE and return `true`.
/// Otherwise leaves the packet untouched and returns `false` (not a local NAT66 return — a normal
/// flow or a remote-owned nat_ip6 handled by the neighbor-NAT relay). Its OWN `#[inline(never)]` BPF
/// frame (holds the `CtKey6`/`CtEntry6` locals) so `process_uplink_v6`'s shared resolve/decap tail is
/// NOT duplicated onto the return path — that duplication would blow the 512B combined-stack limit.
/// pkt-touching but self-contained (no delivery), so no `R2 pkt_end` wall.
#[inline(never)]
fn nat_return_dnat6<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, vni: u32) -> bool {
    let inner_off = ETH_LEN;
    let mut key = match ct_key6(&*pkt, inner_off, vni) {
        Some(k) => k,
        None => return false,
    };
    // Only a registered nat_ip6 dst is a NAT66-return candidate; demux peer-independently.
    if !maps.is_nat_ip6(vni, &key.dst_ip) {
        return false;
    }
    key.src_ip = [0; 16];
    key.src_port = 0;
    if let Some(e) = maps.nat_ct6_get(&key) {
        if e.flags & CT_REWRITE_DST != 0 {
            nat_return_rewrite6(pkt, inner_off, &e);
            return true;
        }
    }
    false
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
    // Post-decap: see `process_uplink`'s doc comment on the same offset change.
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
                        // the CT_REWRITE_DST reverse entry.
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
                                    // NOW, after `tap_ifindex` is resolved. `nat64_ingress_parse`
                                    // needs the real overlay IPv6 to accept a NAT64 return, so it must
                                    // be sourced here rather than passed in before the tap is known.
                                    // Out-of-lined (`#[inline(never)]`): inlining the ~70-byte
                                    // `PortMeta` copy directly into this already-large dispatch
                                    // pushes the verifier's combined-call-stack over budget
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
