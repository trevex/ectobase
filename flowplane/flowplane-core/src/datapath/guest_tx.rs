//! Guest egress orchestrators: the IPv4 forwarding path ([`process_guest_tx`]), the native IPv6→IPv6
//! path ([`process_guest_tx_v6`]), and the NAT64 v6→v4 egress path ([`process_guest_tx_nat64`]).
//! Split out of the datapath god-file per review P1.2; behavior-preserving.

use flowplane_common::{
    CtEntry, PortMeta, CT_REWRITE_SRC, FW_ACTION_DROP, FW_DIR_EGRESS, FW_DIR_INGRESS,
    GENEVE_OVERHEAD,
};

use crate::conntrack::{ct_apply, ct_create_default, ct_key, ct_key6, ct_refresh, rewrite_v6_addr};
use crate::decap::GW_MAC;
use crate::egress::{deliver, egress_fw_ct6, route4, route_decision6, Deliver, EgressFwCt6};
use crate::encap::{tunnel_encap, TunnelEncap, ETH_LEN};
use crate::firewall::fw_eval_dir;
use crate::maps::Maps;
use crate::nat::{snat_egress, snat_egress6, SnatOutcome};
use crate::nat64::{nat64_egress_parse, nat64_egress_write};
use crate::pkt::{Action, Pkt};

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

    // DSR reverse-SNAT. If this is the guest's REPLY to a DSR-load-balanced flow, the backend's
    // ingress `uplink_dsr_note` tcx pre-program already noted the VIP the edge dispatched, keyed
    // on this exact reply 5-tuple (`invert_key(ct_key(forwarded))` == `ct_key(reply)`). Rewrite src
    // (this guest's own overlay IP) -> that VIP so the reply is client-visible as coming from the VIP,
    // then let it fall through the ordinary route/deliver tail (it typically routes out via the
    // external/public route toward any anycast edge — no local INTERFACES entry for the real client).
    // Reuses `ct_apply`'s CT_REWRITE_SRC path (byte-identical IP+L4 checksum fold to any other src
    // rewrite) via a transient, map-free `CtEntry` — no new rewrite helper needed. A DSR flow has no
    // `NAT` config of its own, so `snat_egress` below would no-op for it anyway; `is_dsr` skips the
    // call explicitly since a DSR reply is not NAT-translated (SNAT and DSR reverse-SNAT are mutually
    // exclusive translations of the very same src field, and must not both fire).
    let mut is_dsr = false;
    if let Some(key) = ct_key(&*pkt, ip_off, in_.meta.vni) {
        if let Some(d) = maps.dsr_get(&key) {
            let e = CtEntry {
                xlate_ip: [d.vip[0], d.vip[1], d.vip[2], d.vip[3]],
                flags: CT_REWRITE_SRC,
                ..Default::default()
            };
            ct_apply(pkt, ip_off, &e);
            is_dsr = true;
        }
    }

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
    //
    // Skipped entirely for a DSR reply (`is_dsr`): a DSR flow has no `NAT` config, so `snat_egress`
    // would already no-op (`nat_get` miss) — the explicit skip just documents that SNAT and the
    // DSR reverse-SNAT above are mutually exclusive translations of the same src field.
    let is_ext = route.is_external != 0;
    if !is_dsr
        && snat_egress(pkt, maps, ip_off, in_.meta.vni, is_ext, in_.now) == SnatOutcome::Exhausted
    {
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
///     shaping reflects real wire bytes) → `Redirect(uplink_ifindex)`. Representation-identical to
///     the v4 encap arm — there is no outer next-header difference on the wire; the packet's own
///     ethertype says which family it is;
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

    // DSR reverse-SNAT. If this is the guest's REPLY to a DSR-load-balanced flow, the backend's
    // ingress `uplink_dsr_note6` tcx pre-program already noted the VIP the edge dispatched, keyed
    // on this exact reply 5-tuple (`invert_key6(ct_key6(forwarded))` == `ct_key6(reply)`). Rewrite src
    // (this guest's own overlay IP) -> that VIP so the reply is client-visible as coming from the VIP;
    // the subsequent route decision keys off DST (the client), so it is unaffected by this src rewrite
    // — the reply then falls through the ordinary route6/deliver tail exactly like any other flow
    // (typically an encap toward the external/public route, since the real client has no local
    // INTERFACES6 entry). Runs BEFORE stage 2 (route6 + deliver), same relative position as v4's
    // insertion before its route lookup — after the firewall/conntrack stage above, which already
    // tracked this flow's ORIGINAL (pre-rewrite) 5-tuple, matching what `dsr_note6` keyed off.
    let mut did_dsr = false;
    if let Some(key) = ct_key6(&*pkt, ip_off, in_.meta.vni) {
        if let Some(d) = maps.dsr6_get(&key) {
            if let Some(src) = pkt.read_array::<16>(ip_off + 8) {
                let nexthdr = pkt.read_u8(ip_off + 6).unwrap_or(0);
                rewrite_v6_addr(pkt, ip_off, ip_off + 8, nexthdr, &src, &d.vip);
                did_dsr = true;
            }
        }
    }

    // NAT66 egress SNAT — v6 sibling of process_guest_tx's stage-4 snat_egress. Runs when the
    // v6 route is EXTERNAL and the guest has a NAT66 config; the src rewrite doesn't disturb the
    // dst-keyed route_decision6 below. Skipped after a DSR reverse-SNAT (mutually-exclusive src
    // rewrites — a DSR flow has no NAT config so snat_egress6 would no-op anyway, the skip documents
    // it). is_external comes from a route6 lookup on the inner dst (route_decision6 re-looks-up).
    if !did_dsr {
        let is_ext6 = pkt
            .read_array::<16>(ip_off + 24)
            .and_then(|dst| maps.route6_get(in_.meta.vni, &dst))
            .map(|r| r.is_external != 0)
            .unwrap_or(false);
        if snat_egress6(pkt, maps, ip_off, in_.meta.vni, is_ext6, in_.now) == SnatOutcome::Exhausted
        {
            return GuestTxOut {
                action: Action::Drop,
                edt_tstamp,
                tunnel: None,
            };
        }
    }

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
