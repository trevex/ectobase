use flowplane_common::{CtEntry, PortMeta, CT_REWRITE_SRC};
use flowplane_core::encap::TunnelEncap;
use flowplane_core::maps::Maps;
use flowplane_core::pkt::Pkt;

use crate::parse::ETH_LEN;

/// What the per-program glue should do after the in-place egress pipeline runs.
pub enum EgressVerdict {
    Pass,
    Drop,
    Local {
        tap_ifindex: u32,
        guest_mac: [u8; 6],
    },
    /// Overlay-egress: stamp the Geneve tunnel key and redirect to the geneve device (see
    /// `crate::tunnel`). Mirrors `flowplane_core::egress::Deliver::Encap`'s `tunnel` decision;
    /// `uplink_ifindex` is dropped here — the tc glue always redirects to the configured geneve
    /// device (`crate::maps::geneve_ifindex()`), which resolves the real underlay nexthop itself.
    Encap(TunnelEncap),
}

/// Run the in-place IPv4 egress pipeline (conntrack/firewall/lb_ip/nat/meter/route) and decide what
/// the caller's glue should do. Map-driven; used by tc `tc_guest_tx`. Mutates the packet in place
/// but does NOT resize. Caller has already verified ethertype == ETH_P_IP and that ETH_LEN+20
/// bytes are present.
#[inline(always)]
pub fn forward_decision_v4(
    data: usize,
    data_end: usize,
    ifindex: u32,
    meta: &PortMeta,
) -> EgressVerdict {
    let p = data as *const u8;
    // Conntrack + egress firewall. Established flows: apply translation + refresh. New flows:
    // enforce the SOURCE interface's EGRESS firewall. The firewall is DENY-BY-DEFAULT: with no
    // FW_META entry, or no egress rule that matches, `fw_classify` returns DROP (see its impl).
    // So an egress-INITIATED flow needs an explicit egress-allow FirewallPolicy; an ingress-
    // ESTABLISHED flow is exempt because its reverse conntrack entry (pre-seeded by ct_*_default)
    // makes this a CT hit, skipping the firewall entirely.
    //
    // Only apply CT_REWRITE_SRC (egress-direction) translations here. CT_REWRITE_DST entries are
    // reverse-NAT entries created for ingress return traffic; they must NOT be applied in the
    // egress path (otherwise a non-NAT'd VM replying to a NATted peer would have its dst
    // incorrectly rewritten and be delivered locally instead of going out to the router).
    // `was_new` = this is the flow's first packet (conntrack miss). New flows enforce the SOURCE
    // egress firewall here, and — on the local fast path below — the DESTINATION ingress firewall
    // (same-node delivery must still honor the dest's ingress policy; established flows, incl. the
    // reverse/reply entry seeded here, skip both, mirroring the cross-node uplink_rx behavior).
    let mut was_new = false;
    if let Some(key) = crate::conntrack::ct_key(data, data_end, ETH_LEN, meta.vni) {
        match unsafe { crate::maps::CONNTRACK.get(&key) } {
            Some(e) => {
                let mut e = *e;
                if e.flags & flowplane_common::CT_REWRITE_SRC != 0
                    && !crate::conntrack::ct_apply(data, data_end, ETH_LEN, &e)
                {
                    // Required SNAT translation unapplied (IP options / short window): dropping
                    // beats emitting the guest's untranslated source onto an external path.
                    return EgressVerdict::Drop;
                }
                crate::conntrack::ct_touch(data, data_end, ETH_LEN, &key, &mut e);
            }
            None => {
                was_new = true;
                if flowplane_core::firewall::fw_classify(
                    &crate::coreimpl::RawPkt::new(data, data_end),
                    &crate::coreimpl::GlobalMaps,
                    ETH_LEN,
                    ifindex,
                    flowplane_common::FW_DIR_EGRESS,
                ) == flowplane_common::FW_ACTION_DROP
                {
                    return EgressVerdict::Drop;
                }
            }
        }
    }
    // B8b: DSR reverse-SNAT. If this is the guest's REPLY to a DSR-load-balanced flow, the backend's
    // ingress `uplink_dsr_note` tcx pre-program (B7c) already noted the client-visible LB address for this
    // exact reply 5-tuple (`invert_key(ct_key(forwarded))` == `ct_key(reply)`) in the `DSR` map.
    // Rewrite the inner src (this guest's own overlay IP) -> that LB_IP_CONST, mirroring
    // `flowplane_core::datapath::process_guest_tx`'s B8 stage byte-for-byte (same `ct_key` lookup,
    // same transient `CtEntry{ xlate_ip, flags: CT_REWRITE_SRC, .. }` fed through `ct_apply` — the
    // SAME rewrite path the established-flow CT hit above already uses). Out-of-line so this stays a
    // separate, sequential BPF stack frame — see `dsr_reverse_snat_v4`'s doc comment.
    if !dsr_reverse_snat_v4(data, data_end, meta.vni) {
        // DSR reverse-SNAT required but unapplied — see the core `process_guest_tx` DSR arm: the
        // reply would otherwise leave carrying this guest's own overlay src, not the LB address.
        return EgressVerdict::Drop;
    }
    // SNAT: rewrite inner IPv4 source if an LB address mapping exists (G->V).
    crate::floatingip::snat_egress(data, data_end, ETH_LEN, meta.vni);
    // DNAT: rewrite inner IPv4 destination if an LB address mapping exists (V->G). This handles
    // same-host LB address traffic where the sender sends to another VM's LB_IP_CONST; the ingress path
    // (uplink_rx) never sees this packet, so DNAT must be applied here before route lookup.
    crate::floatingip::dnat_egress(data, data_end, ETH_LEN, meta.vni);
    // inner IPv4 dst at ETH_LEN + 16
    let dst = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 16) as *const [u8; 4]) };
    // Route lookup via the shared core seam (`ROUTES` LPM at prefix_len 64). Same bytecode result as
    // the old inline `ROUTES.get(Key::new(64, ..))`, now single-sourced in `flowplane_core::egress`.
    let route = match flowplane_core::egress::route4(&crate::coreimpl::GlobalMaps, meta.vni, &dst) {
        Some(r) => r,
        None => return EgressVerdict::Pass,
    };
    // Network NAT: SNAT guest -> nat_ip:port when the dst route is external. Delegates to the shared
    // core `flowplane_core::nat::snat_egress` (the SAME code the native SimNode + BPF_PROG_TEST_RUN
    // anchor run) over a fresh `RawPkt` window on `[data, data_end)` — the wrapper re-derives the
    // packet bounds on every read/write, so the variable-IHL L4 accesses stay verifier-provable
    // across the bpf-to-bpf subprogram-call boundary. `now()` stamps the conntrack `last_seen`.
    let is_ext = route.is_external != 0;
    if flowplane_core::nat::snat_egress(
        &mut crate::coreimpl::RawPkt::new(data, data_end),
        &mut crate::coreimpl::GlobalMaps,
        ETH_LEN,
        meta.vni,
        is_ext,
        crate::conntrack::now(),
    ) != flowplane_core::nat::SnatOutcome::Continue
    {
        return EgressVerdict::Drop;
    }
    // Track every flow.
    if let Some(key) = crate::conntrack::ct_key(data, data_end, ETH_LEN, meta.vni) {
        if unsafe { crate::maps::CONNTRACK.get(&key) }.is_none() {
            crate::conntrack::ct_ensure_default(data, data_end, ETH_LEN, &key);
        }
    }
    // Public-lane policing (external egress only). Total egress is EDT-shaped at the uplink FQ
    // via `edt_stamp` in tc_guest_tx's encap path, not policed here.
    let frame_len = (data_end - data) as u64;
    if !crate::meter::public_pass(ifindex, frame_len, is_ext) {
        return EgressVerdict::Drop;
    }
    // Deliver decision via the shared core seam: local fast path (nexthop underlay is one of our own
    // LOCAL interfaces -> deliver to that tap, no encap) vs. encap toward the nexthop vs. pass. LB
    // anycast entries have tap_ifindex==0 and fall through to encap. Single-sourced in
    // `flowplane_core::egress::deliver` (the SAME decision the native SimNode runs). The dest ingress
    // firewall gate on the local path stays HERE in the wrapper — it needs `was_new` + the packet.
    let mut dst16 = [0u8; 16];
    dst16[..4].copy_from_slice(&dst);
    match flowplane_core::egress::deliver(
        &crate::coreimpl::GlobalMaps,
        meta.vni,
        &dst16,
        false,
        &route,
    ) {
        flowplane_core::egress::Deliver::Local {
            tap_ifindex,
            guest_mac,
        } => {
            // Destination ingress firewall on NEW flows (the cross-node uplink_rx path is skipped
            // for same-node delivery, so enforce the dest's ingress policy here). Deny-by-default.
            if was_new
                && flowplane_core::firewall::fw_classify(
                    &crate::coreimpl::RawPkt::new(data, data_end),
                    &crate::coreimpl::GlobalMaps,
                    ETH_LEN,
                    tap_ifindex,
                    flowplane_common::FW_DIR_INGRESS,
                ) == flowplane_common::FW_ACTION_DROP
            {
                // The flow's entries already exist (created after the egress check); drop them so
                // the next packet is new again and meets this check, not a conntrack bypass.
                egress_ct_forget_v4(data, data_end, meta.vni);
                return EgressVerdict::Drop;
            }
            EgressVerdict::Local {
                tap_ifindex,
                guest_mac,
            }
        }
        flowplane_core::egress::Deliver::Encap { tunnel, .. } => EgressVerdict::Encap(tunnel),
        flowplane_core::egress::Deliver::Pass => EgressVerdict::Pass,
    }
}

/// DSR reverse-SNAT (B8b) for the inner-v4 egress flow: v4 sibling of [`dsr_reverse_snat_v6`], and the
/// real-eBPF counterpart of `flowplane_core::datapath::process_guest_tx`'s B8 stage (byte-identical
/// rewrite: same `ct_key` lookup against the `DSR` map, same transient `CtEntry{ xlate_ip, flags:
/// CT_REWRITE_SRC, .. }` fed through `ct_apply` — the SAME rewrite mechanism the established-flow CT
/// hit in `forward_decision_v4` above already uses). A miss (no note, or not a DSR flow) is a no-op.
///
/// Out-of-line (`#[inline(never)]`) purely for STACK BUDGET: `forward_decision_v4` is
/// `#[inline(always)]`, so its whole body (CT/firewall, LB_IP_CONST, route, network-NAT, deliver) is one
/// large frame folded directly into `tc_guest_tx` — the biggest program in this crate. Making this
/// map-lookup-plus-rewrite its OWN out-of-line subprogram keeps its locals (`CtKey`, the transient
/// `CtEntry`) off that already-tight combined frame; the call is sequential (runs once, returns
/// before the caller continues into LB address/route/NAT below), so it does not nest with anything else.
/// Remove the conntrack entries a refused same-node flow created (core `ct_forget_default`).
/// Out-of-line for the same stack reason as [`dsr_reverse_snat_v4`]: its CtKey pair stays off
/// `tc_guest_tx`'s combined frame.
#[inline(never)]
fn egress_ct_forget_v4(data: usize, data_end: usize, vni: u32) {
    flowplane_core::conntrack::ct_forget_default(
        &crate::coreimpl::RawPkt::new(data, data_end),
        &mut crate::coreimpl::GlobalMaps,
        ETH_LEN,
        vni,
    );
}

/// IPv6 sibling of [`egress_ct_forget_v4`] (core `ct_forget_default6`), a sequential frame of
/// `forward_decision_v6`.
#[inline(never)]
fn egress_ct_forget_v6(data: usize, data_end: usize, vni: u32) {
    flowplane_core::conntrack::ct_forget_default6(
        &crate::coreimpl::RawPkt::new(data, data_end),
        &mut crate::coreimpl::GlobalMaps,
        ETH_LEN,
        vni,
    );
}

#[inline(never)]
fn dsr_reverse_snat_v4(data: usize, data_end: usize, vni: u32) -> bool {
    let mut pkt = crate::coreimpl::RawPkt::new(data, data_end);
    if let Some(key) = flowplane_core::conntrack::ct_key(&pkt, ETH_LEN, vni) {
        if let Some(d) = crate::coreimpl::GlobalMaps.dsr_get(&key) {
            let e = CtEntry {
                xlate_ip: [d.lb_ip[0], d.lb_ip[1], d.lb_ip[2], d.lb_ip[3]],
                flags: CT_REWRITE_SRC,
                ..Default::default()
            };
            return flowplane_core::conntrack::ct_apply(&mut pkt, ETH_LEN, &e);
        }
    }
    true
}

/// Conntrack lookup for the inner-v6 egress flow (stage 1a of `forward_decision_v6`): the shared core
/// `egress_ct6` — build the v6 key, refresh a hit. Out-of-line (`#[inline(never)]`) so its
/// CtKey6/CtEntry frame is freed before the firewall scan runs: `tc_guest_egress_v6`'s own frame +
/// CT locals + the 16-slot `FwRule6` scan, nested in one subprogram, sat at exactly the 512B
/// combined limit and went over on a register-allocation change (aya-ebpf 0.2). Scalar
/// `data`/`data_end` args, packet window reconstructed inside — no packet pointer crosses the call.
#[inline(never)]
fn egress_ct_v6(data: usize, data_end: usize, vni: u32) -> flowplane_core::egress::EgressCt6 {
    flowplane_core::egress::egress_ct6(
        &crate::coreimpl::RawPkt::new(data, data_end),
        &mut crate::coreimpl::GlobalMaps,
        ETH_LEN,
        vni,
        crate::conntrack::now(),
    )
}

/// Track a new, egress-allowed inner-v6 flow (stage 1c of `forward_decision_v6`): the shared core
/// `ct_create_default6`, in its own sequential frame for the same reason as [`egress_ct_v6`].
#[inline(never)]
fn egress_ct_create_v6(data: usize, data_end: usize, vni: u32) {
    flowplane_core::conntrack::ct_create_default6(
        &crate::coreimpl::RawPkt::new(data, data_end),
        &mut crate::coreimpl::GlobalMaps,
        ETH_LEN,
        vni,
        crate::conntrack::now(),
    );
}

/// The v6 firewall for one direction of one interface: `true` iff the packet must be DROPPED
/// (deny-by-default: no matching rule → `fw_classify6` returns DROP). Used for the SOURCE egress
/// check of a new flow (stage 1b of `forward_decision_v6`) and for the DESTINATION ingress check on
/// the same-node local fast path, where the cross-node `uplink_rx` ingress path is skipped —
/// mirroring the v4 `forward_decision_v4` Local arm. Out-of-line (`#[inline(never)]`) with SCALAR
/// `data`/`data_end` args (RawPkt reconstructed inside) so its FwRule6/selector frame (~180B) is a
/// SEPARATE, sequentially allocated frame, never coexisting with the conntrack or route-lookup
/// frames on the combined 512B BPF stack.
#[inline(never)]
fn fw_drop_v6(data: usize, data_end: usize, ifindex: u32, dir: u8) -> bool {
    flowplane_core::firewall::fw_classify6(
        &crate::coreimpl::RawPkt::new(data, data_end),
        &crate::coreimpl::GlobalMaps,
        ETH_LEN,
        ifindex,
        dir,
    ) == flowplane_common::FW_ACTION_DROP
}

/// Route6 lookup + deliver decision (local fast path / encap / pass) for the inner-v6 egress flow.
/// Out-of-line (`#[inline(never)]`) so its route-lookup `Key<RouteLpmData6>` frame (~264B) does not
/// coexist on the combined BPF stack with the stage-1 conntrack/firewall frames: all are called
/// SEQUENTIALLY from the thin `forward_decision_v6` dispatcher, so each is freed before the next
/// (512B combined limit). Takes `data`/`data_end` as scalars and
/// reconstructs the packet window inside — no packet pointer crosses the call boundary.
#[inline(never)]
fn route_decision_v6(data: usize, data_end: usize, meta: &PortMeta) -> EgressVerdict {
    // Seam-not-duplicate: delegate to the SHARED core stage (`flowplane_core::egress::route_decision6`
    // = `route6` + `deliver`) — the SAME code the native SimNode runs via `process_guest_tx_v6`.
    // GlobalMaps' `route6_get`/`underlay_get`/`local()` compile to the
    // same `ROUTES6`/`UNDERLAY`/`LOCAL[0]` accesses this wrapper used before, so the byte-relevant
    // decision is unchanged. This wrapper stays a `#[inline(never)]` subprogram so the core stage's
    // route-lookup `Key<RouteLpmData6>` frame gets its own BPF stack frame, sequential to (never
    // coexisting with) the stage-1 conntrack/firewall frames (512B combined limit).
    match flowplane_core::egress::route_decision6(
        &crate::coreimpl::RawPkt::new(data, data_end),
        &crate::coreimpl::GlobalMaps,
        meta,
    ) {
        flowplane_core::egress::Deliver::Local {
            tap_ifindex,
            guest_mac,
        } => EgressVerdict::Local {
            tap_ifindex,
            guest_mac,
        },
        flowplane_core::egress::Deliver::Encap { tunnel, .. } => EgressVerdict::Encap(tunnel),
        flowplane_core::egress::Deliver::Pass => EgressVerdict::Pass,
    }
}

/// DSR reverse-SNAT (B8b) for the inner-v6 egress flow: v6 sibling of [`dsr_reverse_snat_v4`], and the
/// real-eBPF counterpart of `flowplane_core::datapath::process_guest_tx_v6`'s B8 stage (byte-identical
/// rewrite: same `ct_key6` lookup against the `DSR6` map, same address-only [`rewrite_v6_addr`] — no
/// port/ICMP rewrite; DSR preserves the client-visible IP:port). A miss (no note, or not a DSR flow)
/// is a no-op.
///
/// Out-of-line (`#[inline(never)]`) so its `CtKey6` + rewrite locals get their OWN sequential BPF
/// stack frame, called from the thin `forward_decision_v6` dispatcher right after stage 1 and freed
/// via return BEFORE `route_decision_v6` runs — none of the stages' heavy frames ever coexist on the
/// combined 512B stack.
#[inline(never)]
fn dsr_reverse_snat_v6(data: usize, data_end: usize, vni: u32) -> bool {
    let mut pkt = crate::coreimpl::RawPkt::new(data, data_end);
    if let Some(key) = flowplane_core::conntrack::ct_key6(&pkt, ETH_LEN, vni) {
        if let Some(d) = crate::coreimpl::GlobalMaps.dsr6_get(&key) {
            if let Some(src) = pkt.read_array::<16>(ETH_LEN + 8) {
                let nexthdr = pkt.read_u8(ETH_LEN + 6).unwrap_or(0);
                flowplane_core::conntrack::rewrite_v6_addr(
                    &mut pkt,
                    ETH_LEN,
                    ETH_LEN + 8,
                    nexthdr,
                    &src,
                    &d.lb_ip,
                );
                return true;
            }
        }
    }
    false
}

/// IPv6-inner egress decision (fw/ct + DSR reverse-SNAT + route6 + local/encap). Map-driven; used by
/// tc. No NAT64 (caller runs that first), no resize. Caller verified ETH_LEN+IPV6_LEN present and
/// ethertype==ETH_P_IPV6.
///
/// THIN dispatcher: the heavy stages — conntrack lookup (`egress_ct_v6`), source egress firewall
/// (`fw_drop_v6`) and conntrack create (`egress_ct_create_v6`), DSR reverse-SNAT
/// (`dsr_reverse_snat_v6`), and the route6 lookup + deliver (`route_decision_v6`) — are each their own
/// `#[inline(never)]` subprogram, called SEQUENTIALLY here. So none of the frames coexists with another on the combined BPF stack (512B
/// limit); this dispatcher itself carries no heavy locals. Established flows (CT hit) skip the
/// firewall; new flows are egress-firewalled then tracked, then (either way) checked for a DSR
/// reverse-SNAT note, then routed.
#[inline(always)]
pub fn forward_decision_v6(
    data: usize,
    data_end: usize,
    ifindex: u32,
    meta: &PortMeta,
) -> EgressVerdict {
    // Stage 1: egress firewall + conntrack — the core `egress_fw_ct6`, run as three SEQUENTIAL
    // frames in the same order: CT lookup (refresh a hit), then on a miss the source egress firewall
    // and, if it allows, the CT create. Carries `was_new` (CT miss) up to the local fast path.
    let was_new = match egress_ct_v6(data, data_end, meta.vni) {
        flowplane_core::egress::EgressCt6::Established => false,
        flowplane_core::egress::EgressCt6::Unkeyable => return EgressVerdict::Drop,
        flowplane_core::egress::EgressCt6::Miss => {
            if fw_drop_v6(data, data_end, ifindex, flowplane_common::FW_DIR_EGRESS) {
                return EgressVerdict::Drop;
            }
            egress_ct_create_v6(data, data_end, meta.vni);
            true
        }
    };
    // Stage 2 (B8b): DSR reverse-SNAT — a no-op unless this reply's 5-tuple hit the `DSR6` map. Runs
    // BEFORE the route decision so a rewritten src still routes correctly (route/deliver key off DST).
    let did_dsr = dsr_reverse_snat_v6(data, data_end, meta.vni);
    // Stage 2b (Plan B): NAT66 egress SNAT when the v6 route is external. Skipped after a DSR
    // reverse-SNAT (mutually-exclusive src rewrites; a DSR flow has no NAT66 config anyway). Calls the
    // shared core `snat_egress6` DIRECTLY (mirrors v4's `forward_decision_v4` snat stage) — the heavy
    // port-alloc conntrack is out-of-lined inside `snat_egress6` (`snat6_pick_port`), so no wrapper is
    // needed here. `is_external` from a route6 lookup on the inner dst (snat rewrites SRC, not the
    // dst-keyed route decision below).
    if !did_dsr {
        let is_ext = {
            let pkt = crate::coreimpl::RawPkt::new(data, data_end);
            pkt.read_array::<16>(ETH_LEN + 24)
                .and_then(|dst| crate::coreimpl::GlobalMaps.route6_get(meta.vni, &dst))
                .map(|r| r.is_external != 0)
                .unwrap_or(false)
        };
        if flowplane_core::nat::snat_egress6(
            &mut crate::coreimpl::RawPkt::new(data, data_end),
            &mut crate::coreimpl::GlobalMaps,
            ETH_LEN,
            meta.vni,
            is_ext,
            crate::conntrack::now(),
        ) != flowplane_core::nat::SnatOutcome::Continue
        {
            return EgressVerdict::Drop;
        }
    }
    // Stage 3: route6 + deliver decision (its own sequential frame — freed before stage 4).
    let verdict = route_decision_v6(data, data_end, meta);
    // Stage 4: on a NEW flow delivered to a SAME-NODE guest, enforce the DESTINATION's ingress
    // firewall (uplink_rx is bypassed for same-node traffic). Deny-by-default. Mirrors the v4
    // `forward_decision_v4` Local arm. Established flows (was_new==false, incl. the pre-seeded
    // reverse entry for a same-node reply) skip this. `fw_drop_v6` is its own sequential
    // #[inline(never)] frame so its FwRule6 locals never coexist with stage 3's route-lookup frame.
    if let EgressVerdict::Local { tap_ifindex, .. } = verdict {
        if was_new
            && fw_drop_v6(
                data,
                data_end,
                tap_ifindex,
                flowplane_common::FW_DIR_INGRESS,
            )
        {
            // As in the v4 Local arm: forget the refused flow's entries (stage 1c created them).
            egress_ct_forget_v6(data, data_end, meta.vni);
            return EgressVerdict::Drop;
        }
    }
    verdict
}
