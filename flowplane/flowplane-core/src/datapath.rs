//! Substrate-agnostic datapath orchestrators shared by the eBPF program and the native `SimNode`
//! harness. These compose the REAL per-step core fns (`lb_select_forward`,
//! `reforward`, `fw_eval_dir`, `ct_create_default`, `decap_and_rewrite`, metering) in the exact order
//! and gates of the eBPF program tails, over any `Pkt` + `Maps` implementation. The SAME code thus
//! runs under the sim and under the `BPF_PROG_TEST_RUN` anchor.

use flowplane_common::{
    Local, PortMeta, UnderlayValue, CT_F_NAT64, CT_REWRITE_DST, FW_ACTION_DROP, FW_DIR_EGRESS,
    FW_DIR_INGRESS,
};

use crate::arp_nd::{arp_reply, nd_reply};
use crate::conntrack::{ct_apply, ct_create_default, ct_key, ct_refresh};
use crate::dhcp;
use crate::egress::{
    deliver, egress_fw_ct6, route4, route_decision6, Deliver, EgressFwCt6, IPPROTO_IPIP,
};
use crate::encap::{reforward, write_outer_v6, EncapParams, ETH_LEN, IPV6_LEN};
use crate::firewall::fw_eval_dir;
use crate::lb::{lb_select_forward, lb_select_forward_v6};
use crate::maps::Maps;
use crate::nat::{snat_egress, SnatOutcome};
use crate::nat64::{
    nat64_egress_parse, nat64_egress_write, nat64_ingress_parse, nat64_ingress_write,
};
use crate::pkt::{Action, Pkt};
use crate::uplink::{decap_and_rewrite, GW_MAC};

/// Inputs for [`process_uplink`]. `u` is `UNDERLAY[outer_dst]` (this node's resolved vni + base tap);
/// `outer_dst` is the encapped frame's current outer IPv6 dst; `local` supplies the outer
/// MACs/ifindex for an LB remote `reforward`; `now` is the monotonic clock (ns) the ingress-lane
/// meter stamps `last_ns` from (models `bpf_ktime_get_ns()`).
pub struct UplinkIn<'a> {
    pub vni: u32,
    pub u: UnderlayValue,
    pub outer_dst: [u8; 16],
    pub local: &'a Local,
    pub now: u64,
    /// The guest's own overlay IPv6 (its `PortMeta.guest_ipv6`); used ONLY on the `CT_F_NAT64`
    /// reverse-return path to reconstruct the reply's inner IPv6 dst ([`process_uplink_nat64_ingress`]).
    pub guest_ipv6: [u8; 16],
}

/// Host uplink_rx for the LB + base path, operating in place on `pkt`. Mirrors `try_uplink_rx`:
///   1. `lb_select_forward` → local backend (deliver to its tap) | remote (reforward, no decap)
///      | None (base tap);
///   2. ingress firewall on the inner 5-tuple against the deliver tap (new-flow gate);
///   3. conntrack create-on-miss, **skipped for LB** (DSR, no ct — `ingress.rs:266`);
///   4. decap + inner-Ethernet rewrite;
///   5. ingress-lane policing (keyed by dest tap).
///
/// Returns the final delivery `Action`, having mutated `pkt` in place.
pub fn process_uplink<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in_: &UplinkIn) -> Action {
    let inner_off = ETH_LEN + IPV6_LEN;

    // 1. LB dispatch (mirror ingress.rs:135-157).
    let lb_ul = lb_select_forward(&*pkt, &*maps, inner_off, in_.vni);
    let (tap, guest_mac, is_lb) = match lb_ul {
        Some(bul) => match maps.underlay_get(&bul) {
            Some(bu) => (bu.tap_ifindex, bu.guest_mac, true), // LB backend local
            None => {
                // Remote backend: reforward the encapped frame, no decap.
                return reforward(pkt, in_.local, &in_.outer_dst, &bul);
            }
        },
        None => (in_.u.tap_ifindex, in_.u.guest_mac, false), // non-LB base
    };

    // 2. Ingress firewall on NEW inbound flows against the deliver tap.
    if let Some(key) = ct_key(&*pkt, inner_off, in_.vni) {
        if maps.conntrack_get(&key).is_none()
            && fw_eval_dir(&*pkt, &*maps, inner_off, tap, FW_DIR_INGRESS) == FW_ACTION_DROP
        {
            return Action::Drop;
        }
    }

    // 3. Conntrack: create on miss, refresh (last_seen + TCP state) on hit — but ONLY for non-LB
    //    (LB is DSR — no ct, ingress.rs:266). Refresh mirrors the eBPF `ct_touch`; it is map-only
    //    (never mutates the packet), so it is byte-parity-neutral.
    if !is_lb {
        if let Some(key) = ct_key(&*pkt, inner_off, in_.vni) {
            match maps.conntrack_get(&key) {
                None => ct_create_default(&*pkt, maps, inner_off, in_.vni, in_.now),
                Some(mut e) => ct_refresh(&*pkt, maps, inner_off, &key, &mut e, in_.now),
            }
        }
    }

    // 4. Decap outer Eth+IPv6 and rewrite the inner Ethernet for the guest.
    let action = match decap_and_rewrite(pkt, tap, guest_mac) {
        Ok(a) => a,
        Err(_) => Action::Drop,
    };
    if action == Action::Drop {
        return action;
    }

    // 5. Ingress-lane policing (keyed by dest tap) — mirrors ingress.rs uplink_rx. Post-decap inner
    // length is the frame delivered to the guest. No cap => pass.
    let in_len = pkt.len() as u64;
    if !crate::meter::ingress_pass(maps, tap, in_len, in_.now) {
        return Action::Drop;
    }

    action
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

/// Result of [`process_guest_tx`]: the delivery `Action`, plus the EDT departure timestamp (ns)
/// recorded when the Encap arm hit the `edt_egress` shaping path. `None` when the interface has no
/// egress cap (`total_bps == 0`) / no METER entry, and on the Local/Pass verdicts (which leave it
/// untouched — the eBPF `tc_guest_tx` only stamps on the Encap arm). Wire bytes are unchanged by
/// EDT (FQ pacing is kernel-side).
pub struct GuestTxOut {
    pub action: Action,
    pub edt_tstamp: Option<u64>,
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
///   7. deliver decision (`deliver`): Local tap (inner-Eth rewrite) | Encap | Pass.
///      In the Encap arm ONLY, after `grow_head(IPV6_LEN)`/`write_outer_v6`, EDT egress shaping
///      (`edt_egress`, records `edt_tstamp`, no drop, step 6b) is called using the POST-encap
///      `pkt.len()` — mirrors `tc.rs` `edt_stamp` after `adjust_room`. Local/Pass leave `edt_tstamp`
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
            }
        }
    };
    let route = match route4(&*maps, in_.meta.vni, &dst) {
        Some(r) => r,
        None => {
            return GuestTxOut {
                action: Action::Pass,
                edt_tstamp,
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
    //    b) EDT egress shaping — mirrors tc.rs `edt_stamp`, called ONLY in the Encap arm (step 7)
    //       AFTER `grow_head(IPV6_LEN)` / `write_outer_v6`, using the POST-encap `pkt.len()`.
    //       Same-node LOCAL delivery is unshaped (eBPF `tc_guest_tx` only stamps on the Encap
    //       arm, after `adjust_room`). `edt_tstamp` stays `None` for Local / Pass.
    let frame_len = pkt.len() as u64;
    // a) Public-lane policing (external egress only) — mirrors egress.rs.
    if !crate::meter::public_pass(maps, in_.src_ifindex, frame_len, is_ext, in_.now) {
        return GuestTxOut {
            action: Action::Drop,
            edt_tstamp,
        };
    }

    // 7. Deliver decision. Flow label from the (post-NAT) inner 5-tuple — same core helper the
    // eBPF forward_decision_v4 runs, so the encapped bytes stay identical.
    let flow_label = crate::parse::inner_flow_label(&*pkt, ip_off, false);
    match deliver(&*maps, &route, in_.meta, IPPROTO_IPIP, flow_label) {
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
                };
            }
            // Rewrite the inner Ethernet for the local guest: dst=guest MAC, src=GW_MAC,
            // ethertype stays IPv4. Same-node delivery is unshaped — edt_tstamp left as-is.
            pkt.write_bytes(0, &guest_mac);
            pkt.write_bytes(6, &GW_MAC);
            GuestTxOut {
                action: Action::Redirect(tap_ifindex),
                edt_tstamp,
            }
        }
        Deliver::Encap(e) => {
            // Prepend 40 bytes (bpf_skb_adjust_room(+IPV6_LEN, MAC)) then write the outer
            // Eth+IPv6, consuming the new 40 bytes + the 14-byte inner Ethernet, leaving the
            // bare inner IPv4 — mirrors tc.rs `adjust_room` + `write_outer_v6`.
            if !pkt.grow_head(IPV6_LEN) || !write_outer_v6(pkt, &e) {
                return GuestTxOut {
                    action: Action::Drop,
                    edt_tstamp,
                };
            }
            // b) EDT egress shaping: stamp AFTER the frame has been grown to its wire length,
            // using pkt.len() which is now the full post-encap length (inner + 40-byte outer
            // IPv6 header) — mirrors tc.rs `ctx.len()` after `adjust_room`. Wire bytes are
            // unchanged (FQ pacing is kernel-side); edt_tstamp lets tests assert pacing.
            edt_tstamp = crate::meter::edt_egress(maps, in_.src_ifindex, pkt.len() as u64, in_.now);
            GuestTxOut {
                action: Action::Redirect(e.uplink_ifindex),
                edt_tstamp,
            }
        }
        Deliver::Pass => GuestTxOut {
            action: Action::Pass,
            edt_tstamp,
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
/// Verdict mapping (mirrors [`process_guest_tx`], with the v6 differences called out):
///   - `Deliver::Encap(e)` → `grow_head(IPV6_LEN)` + `write_outer_v6` with **`inner_proto =
///     IPPROTO_IPV6` (41 — IPv6-in-IPv6), NOT `IPPROTO_IPIP` (4)** as the v4 path uses — this is the
///     ONLY byte difference from the v4 encap arm — then EDT egress shaping (`edt_egress`, records
///     `edt_tstamp`) using the POST-encap `pkt.len()` → `Redirect(e.uplink_ifindex)`;
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
            }
        }
        EgressFwCt6::Pass { was_new } => was_new,
    };

    // Stage 2: route6 + deliver. Flow label from the (SNAT-free) inner v6 5-tuple — the SAME core
    // helper the eBPF forward_decision_v6 runs (is_v6 = true), so the encapped bytes stay identical.
    let flow_label = crate::parse::inner_flow_label(&*pkt, ip_off, true);
    match route_decision6(&*pkt, &*maps, in_.meta, flow_label) {
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
            }
        }
        Deliver::Encap(e) => {
            // Prepend 40 bytes then write the outer Eth+IPv6 (inner_proto = IPPROTO_IPV6/41 — the
            // v6-in-v6 difference from the v4 IPIP/4 path — `route_decision6` set `e.inner_proto =
            // IPPROTO_IPV6`), consuming the new 40 bytes + the 14-byte inner Ethernet, leaving the
            // bare inner IPv6 — mirrors tc.rs adjust_room + write_outer_v6.
            if !pkt.grow_head(IPV6_LEN) || !write_outer_v6(pkt, &e) {
                return GuestTxOut {
                    action: Action::Drop,
                    edt_tstamp,
                };
            }
            edt_tstamp = crate::meter::edt_egress(maps, in_.src_ifindex, pkt.len() as u64, in_.now);
            GuestTxOut {
                action: Action::Redirect(e.uplink_ifindex),
                edt_tstamp,
            }
        }
        Deliver::Pass => GuestTxOut {
            action: Action::Pass,
            edt_tstamp,
        },
    }
}

/// Inputs for [`process_uplink_nat_return`]. `u`'s base tap becomes the delivery ifindex.
pub struct UplinkNatReturnIn {
    pub vni: u32,
    pub tap_ifindex: u32,
    pub guest_mac: [u8; 6],
}

/// Host NAT reverse-DNAT return path, in place on `pkt`. Mirrors the eBPF `try_uplink_rx` NAT branch:
/// build the inner 5-tuple key (demuxed peer-independently when the inner dst is a registered nat_ip);
/// reverse-DNAT apply when the matched CT entry carries `CT_REWRITE_DST`; decap + inner-Eth rewrite.
pub fn process_uplink_nat_return<P: Pkt, M: Maps>(
    pkt: &mut P,
    maps: &mut M,
    in_: &UplinkNatReturnIn,
) -> Action {
    let inner_off = ETH_LEN + IPV6_LEN;

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
            }
        }
    }

    // 3. Decap outer Eth+IPv6 and rewrite the inner Ethernet for the guest.
    match decap_and_rewrite(pkt, in_.tap_ifindex, in_.guest_mac) {
        Ok(a) => a,
        Err(_) => Action::Drop,
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
/// (restores the guest IPv4 dst, then expands back to the guest's overlay IPv6 via `in_.guest_ipv6`).
pub fn process_uplink_rx<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in_: &UplinkIn) -> Action {
    let inner_off = ETH_LEN + IPV6_LEN;

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
                        // NAT64 return: v4->v6 expansion, not plain reverse-DNAT.
                        return process_uplink_nat64_ingress(
                            pkt,
                            &UplinkNat64IngressIn {
                                tap_ifindex: in_.u.tap_ifindex,
                                guest_mac: in_.u.guest_mac,
                                guest_ipv6: in_.guest_ipv6,
                                rev: &r,
                            },
                        );
                    }
                    return process_uplink_nat_return(
                        pkt,
                        maps,
                        &UplinkNatReturnIn {
                            vni: in_.vni,
                            tap_ifindex: in_.u.tap_ifindex,
                            guest_mac: in_.u.guest_mac,
                        },
                    );
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
/// reverse `ct_apply` → `nat64_ingress_parse` (Pass on miss) → `shrink_head(20)` → `nat64_ingress_write`.
pub fn process_uplink_nat64_ingress<P: Pkt>(pkt: &mut P, in_: &UplinkNat64IngressIn) -> Action {
    let inner_off = ETH_LEN + IPV6_LEN;
    let orig_sport = in_.rev.xlate_port;

    // 1. Reverse conntrack apply: restore the guest IPv4 dst + orig L4 port (+ checksums).
    ct_apply(pkt, inner_off, in_.rev);

    // 2. Parse (IHL/proto/TTL/addrs/checksum + reconstructed 64:ff9b:: IPv6 src).
    let xlate =
        match nat64_ingress_parse(&*pkt, inner_off, in_.guest_ipv6, in_.guest_mac, orig_sport) {
            Some(x) => x,
            None => return Action::Pass,
        };

    // 3. Resize: shrink 20 bytes off the front (models adjust_head(+20)).
    if !pkt.shrink_head(20) {
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

/// Guest NAT64 egress path, in place on `pkt`. Mirrors the eBPF `nat64_egress`: parse (config +
/// port-alloc + CT_F_NAT64 pins) → `shrink_head(20)` (v6→v4) → `nat64_egress_write` → route4 (Pass on
/// miss) → `grow_head(IPV6_LEN)`+`write_outer_v6` encap toward the nexthop.
pub fn process_guest_tx_nat64<P: Pkt, M: Maps>(
    pkt: &mut P,
    maps: &mut M,
    in_: &GuestTxNat64In,
) -> Action {
    let ip6_off = ETH_LEN;

    // 1. Parse (dst-prefix check + NAT config + port alloc + CT_F_NAT64 conntrack inserts).
    let xlate = match nat64_egress_parse(&*pkt, maps, ip6_off, in_.meta.vni, in_.meta.guest_ipv4, 0)
    {
        Some(x) => x,
        None => return Action::Pass,
    };

    // 2. Resize: shrink inner IPv6(40)→IPv4(20) via a 20-byte front drop (models adjust_head(+20)).
    if !pkt.shrink_head(20) {
        return Action::Drop;
    }

    // 3. Write: restore the Ethernet header + build the IPv4 header + translate the L4.
    if !nat64_egress_write(pkt, ETH_LEN, true, &xlate) {
        return Action::Drop;
    }

    // 4. Route lookup on the embedded IPv4 dst.
    let route = match route4(&*maps, in_.meta.vni, &xlate.ipv4_dst) {
        Some(r) => r,
        None => return Action::Pass,
    };

    // 5. Encap IP-in-IPv6 toward the route nexthop (IPIP inner-proto).
    let e = EncapParams {
        gateway_mac: in_.local.gateway_mac,
        uplink_mac: in_.local.uplink_mac,
        uplink_ifindex: in_.local.uplink_ifindex,
        src_underlay: in_.meta.underlay_ipv6,
        nexthop_ipv6: route.nexthop_ipv6,
        inner_proto: IPPROTO_IPIP,
        flow_label: 0,
    };
    if !pkt.grow_head(IPV6_LEN) || !write_outer_v6(pkt, &e) {
        return Action::Drop;
    }
    Action::Redirect(in_.local.uplink_ifindex)
}

/// Inputs for [`process_wan_rx`]. `local` supplies the outer MACs/ifindex + this node's underlay src.
pub struct WanRxIn<'a> {
    pub local: &'a flowplane_common::Local,
}

/// Edge WAN-VIP ingress, in place on `pkt`. Mirrors `ingress.rs::try_wan_rx` VIP branch: dispatch on
/// ethertype (offset 12) — 0x86DD → v6 core select (`inner_proto = 41`), else v4 core select
/// (`inner_proto = 4`); on a VIP hit, encap the inner packet IP-in-IPv6 toward the Maglev-selected
/// backend (`grow_head(IPV6_LEN)` + `write_outer_v6`) → `Redirect(uplink_ifindex)`; else `Pass`.
pub fn process_wan_rx<P: Pkt, M: Maps>(pkt: &mut P, maps: &M, in_: &WanRxIn) -> Action {
    let ethertype = match pkt.read_array::<2>(12) {
        Some(b) => u16::from_be_bytes(b),
        None => 0, // frame < 14 bytes → v4 branch (matches plain.get(..).unwrap_or(0))
    };
    let selected = match ethertype {
        0x86DD => lb_select_forward_v6(&*pkt, maps, ETH_LEN, 0).map(|b| (b, 41u8)),
        _ => lb_select_forward(&*pkt, maps, ETH_LEN, 0).map(|b| (b, 4u8)),
    };
    match selected {
        Some((backend, inner_proto)) => {
            let e = EncapParams {
                gateway_mac: in_.local.gateway_mac,
                uplink_mac: in_.local.uplink_mac,
                uplink_ifindex: in_.local.uplink_ifindex,
                src_underlay: in_.local.underlay_ipv6,
                nexthop_ipv6: backend,
                inner_proto,
                flow_label: 0,
            };
            if !pkt.grow_head(IPV6_LEN) || !write_outer_v6(pkt, &e) {
                return Action::Drop;
            }
            Action::Redirect(in_.local.uplink_ifindex)
        }
        None => Action::Pass,
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
