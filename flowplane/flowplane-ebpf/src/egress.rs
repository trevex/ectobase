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

/// Run the in-place IPv4 egress pipeline (conntrack/firewall/vip/nat/meter/route) and decide what
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
    // FW_META entry, or no egress rule that matches, `fw_eval_dir` returns DROP (see its impl).
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
                if e.flags & flowplane_common::CT_REWRITE_SRC != 0 {
                    crate::conntrack::ct_apply(data, data_end, ETH_LEN, &e);
                }
                crate::conntrack::ct_touch(data, data_end, ETH_LEN, &key, &mut e);
            }
            None => {
                was_new = true;
                if flowplane_core::firewall::fw_eval_dir(
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
    // ingress `uplink_dsr_note` tcx pre-program (B7c) already noted the client-visible VIP for this
    // exact reply 5-tuple (`invert_key(ct_key(forwarded))` == `ct_key(reply)`) in the `DSR` map.
    // Rewrite the inner src (this guest's own overlay IP) -> that VIP, mirroring
    // `flowplane_core::datapath::process_guest_tx`'s B8 stage byte-for-byte (same `ct_key` lookup,
    // same transient `CtEntry{ xlate_ip, flags: CT_REWRITE_SRC, .. }` fed through `ct_apply` — the
    // SAME rewrite path the established-flow CT hit above already uses). Out-of-line so this stays a
    // separate, sequential BPF stack frame — see `dsr_reverse_snat_v4`'s doc comment.
    dsr_reverse_snat_v4(data, data_end, meta.vni);
    // SNAT: rewrite inner IPv4 source if a VIP mapping exists (G->V).
    crate::vip::snat_egress(data, data_end, ETH_LEN, meta.vni);
    // DNAT: rewrite inner IPv4 destination if a VIP mapping exists (V->G). This handles
    // same-host VIP traffic where the sender sends to another VM's VIP; the ingress path
    // (uplink_rx) never sees this packet, so DNAT must be applied here before route lookup.
    crate::vip::dnat_egress(data, data_end, ETH_LEN, meta.vni);
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
    ) == flowplane_core::nat::SnatOutcome::Exhausted
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
                && flowplane_core::firewall::fw_eval_dir(
                    &crate::coreimpl::RawPkt::new(data, data_end),
                    &crate::coreimpl::GlobalMaps,
                    ETH_LEN,
                    tap_ifindex,
                    flowplane_common::FW_DIR_INGRESS,
                ) == flowplane_common::FW_ACTION_DROP
            {
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
/// `#[inline(always)]`, so its whole body (CT/firewall, VIP, route, network-NAT, deliver) is one
/// large frame folded directly into `tc_guest_tx` — the biggest program in this crate. Making this
/// map-lookup-plus-rewrite its OWN out-of-line subprogram keeps its locals (`CtKey`, the transient
/// `CtEntry`) off that already-tight combined frame; the call is sequential (runs once, returns
/// before the caller continues into VIP/route/NAT below), so it does not nest with anything else.
#[inline(never)]
fn dsr_reverse_snat_v4(data: usize, data_end: usize, vni: u32) {
    let mut pkt = crate::coreimpl::RawPkt::new(data, data_end);
    if let Some(key) = flowplane_core::conntrack::ct_key(&pkt, ETH_LEN, vni) {
        if let Some(d) = crate::coreimpl::GlobalMaps.dsr_get(&key) {
            let e = CtEntry {
                xlate_ip: [d.vip[0], d.vip[1], d.vip[2], d.vip[3]],
                flags: CT_REWRITE_SRC,
                ..Default::default()
            };
            flowplane_core::conntrack::ct_apply(&mut pkt, ETH_LEN, &e);
        }
    }
}

/// Result of the inner-v6 egress firewall/conntrack stage: either DROP the packet, or PASS it on
/// (carrying whether this was a NEW flow — a conntrack MISS). `was_new` is needed downstream so the
/// local fast path can enforce the DESTINATION's ingress firewall on new flows only (mirroring the
/// v4 `forward_decision_v4` Local arm); established flows (CT hit, incl. the pre-seeded reverse
/// entry for a same-node reply) skip both egress and dest-ingress firewalls. `#[repr(u8)]` so it is
/// a single scalar across the bpf-to-bpf call boundary (verifier-friendly, no stack traffic).
#[repr(u8)]
pub enum EgressFwCt {
    Drop,
    Pass { was_new: bool },
}

/// Stateful firewall + conntrack for the inner-v6 egress flow. Returns `EgressFwCt::Drop` if the
/// packet must be dropped (deny-by-default on a new flow), else `EgressFwCt::Pass { was_new }` where
/// `was_new` is true iff this was a conntrack MISS. Out-of-line (`#[inline(never)]`) so its
/// CtKey6/CtEntry stack frame is freed before the caller's route lookup runs — keeps `tc_guest_tx`
/// under the 512B combined BPF stack limit (the v6 CT key alone is ~48B and would otherwise coexist
/// with the route-lookup Key<RouteLpmData6>).
#[inline(never)]
fn egress_fw_ct_v6(data: usize, data_end: usize, ifindex: u32, vni: u32) -> EgressFwCt {
    // Seam-not-duplicate: delegate to the SHARED core stage (`flowplane_core::egress::egress_fw_ct6`)
    // — the SAME code the native SimNode runs via `process_guest_tx_v6`. This wrapper stays a
    // `#[inline(never)]` subprogram so the core stage's CtKey6/CtEntry locals get their own BPF stack
    // frame (freed before `route_decision_v6`'s route-lookup frame). Reconstruct the packet window
    // inside (scalar data/data_end args — no packet pointer crosses the call boundary).
    match flowplane_core::egress::egress_fw_ct6(
        &crate::coreimpl::RawPkt::new(data, data_end),
        &mut crate::coreimpl::GlobalMaps,
        ETH_LEN,
        ifindex,
        vni,
        crate::conntrack::now(),
    ) {
        flowplane_core::egress::EgressFwCt6::Drop => EgressFwCt::Drop,
        flowplane_core::egress::EgressFwCt6::Pass { was_new } => EgressFwCt::Pass { was_new },
    }
}

/// Destination INGRESS firewall for the v6 same-node local fast path. On a NEW egress flow delivered
/// to a SAME-NODE guest, the cross-node `uplink_rx` ingress path is skipped, so the destination's
/// ingress policy must be enforced HERE — mirroring the v4 `forward_decision_v4` Local arm exactly.
/// Deny-by-default: with no matching ingress rule, `fw_eval_dir6` returns DROP. Returns `true` iff
/// the packet must be dropped. Out-of-line (`#[inline(never)]`) with SCALAR `data`/`data_end` args
/// (RawPkt reconstructed inside) so its FwRule6/selector frame (~160B) is a SEPARATE, sequentially
/// allocated frame — never coexisting with `route_decision_v6`'s route-lookup Key frame on the
/// combined 512B BPF stack.
#[inline(never)]
fn dest_ingress_fw_v6(data: usize, data_end: usize, tap_ifindex: u32) -> bool {
    flowplane_core::firewall::fw_eval_dir6(
        &crate::coreimpl::RawPkt::new(data, data_end),
        &crate::coreimpl::GlobalMaps,
        ETH_LEN,
        tap_ifindex,
        flowplane_common::FW_DIR_INGRESS,
    ) == flowplane_common::FW_ACTION_DROP
}

/// Route6 lookup + deliver decision (local fast path / encap / pass) for the inner-v6 egress flow.
/// Out-of-line (`#[inline(never)]`) so its route-lookup `Key<RouteLpmData6>` frame (~264B) does not
/// coexist on the combined BPF stack with the `egress_fw_ct_v6` CtKey6/CtEntry frame (~336B): the
/// two heavy frames are called SEQUENTIALLY from the thin `forward_decision_v6` dispatcher, so each
/// is freed before the next (512B combined limit). Takes `data`/`data_end` as scalars and
/// reconstructs the packet window inside — no packet pointer crosses the call boundary.
#[inline(never)]
fn route_decision_v6(data: usize, data_end: usize, meta: &PortMeta) -> EgressVerdict {
    // Seam-not-duplicate: delegate to the SHARED core stage (`flowplane_core::egress::route_decision6`
    // = `route6` + `deliver`) — the SAME code the native SimNode runs via `process_guest_tx_v6`.
    // GlobalMaps' `route6_get`/`underlay_get`/`local()` compile to the
    // same `ROUTES6`/`UNDERLAY`/`LOCAL[0]` accesses this wrapper used before, so the byte-relevant
    // decision is unchanged. This wrapper stays a `#[inline(never)]` subprogram so the core stage's
    // route-lookup `Key<RouteLpmData6>` frame gets its own BPF stack frame, sequential to (never
    // coexisting with) `egress_fw_ct_v6`'s CtKey6 frame (512B combined limit).
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
/// port/ICMP rewrite; DSR preserves the client-visible VIP:port). A miss (no note, or not a DSR flow)
/// is a no-op.
///
/// Out-of-line (`#[inline(never)]`) so its `CtKey6` + rewrite locals get their OWN sequential BPF
/// stack frame, called from the thin `forward_decision_v6` dispatcher right after `egress_fw_ct_v6`
/// and freed via return BEFORE `route_decision_v6` runs — none of the three stages' heavy frames ever
/// coexist on the combined 512B stack.
#[inline(never)]
fn dsr_reverse_snat_v6(data: usize, data_end: usize, vni: u32) {
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
                    &d.vip,
                );
            }
        }
    }
}

/// IPv6-inner egress decision (fw/ct + DSR reverse-SNAT + route6 + local/encap). Map-driven; used by
/// tc. No NAT64 (caller runs that first), no resize. Caller verified ETH_LEN+IPV6_LEN present and
/// ethertype==ETH_P_IPV6.
///
/// THIN dispatcher: the three heavy stages — stateful firewall/conntrack (`egress_fw_ct_v6`, ~336B),
/// DSR reverse-SNAT (`dsr_reverse_snat_v6`, small but map-lookup-bearing), and the route6 lookup +
/// deliver (`route_decision_v6`, ~264B) — are each their own `#[inline(never)]` subprogram, called
/// SEQUENTIALLY here. So none of the frames coexists with another on the combined BPF stack (512B
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
    // Stage 1: egress firewall + conntrack. Carries `was_new` (CT miss) up to the local fast path.
    let was_new = match egress_fw_ct_v6(data, data_end, ifindex, meta.vni) {
        EgressFwCt::Drop => return EgressVerdict::Drop,
        EgressFwCt::Pass { was_new } => was_new,
    };
    // Stage 2 (B8b): DSR reverse-SNAT — a no-op unless this reply's 5-tuple hit the `DSR6` map. Runs
    // BEFORE the route decision so a rewritten src still routes correctly (route/deliver key off DST).
    dsr_reverse_snat_v6(data, data_end, meta.vni);
    // Stage 3: route6 + deliver decision (its own sequential frame — freed before stage 4).
    let verdict = route_decision_v6(data, data_end, meta);
    // Stage 4: on a NEW flow delivered to a SAME-NODE guest, enforce the DESTINATION's ingress
    // firewall (uplink_rx is bypassed for same-node traffic). Deny-by-default. Mirrors the v4
    // `forward_decision_v4` Local arm. Established flows (was_new==false, incl. the pre-seeded
    // reverse entry for a same-node reply) skip this. `dest_ingress_fw_v6` is its own sequential
    // #[inline(never)] frame so its FwRule6 locals never coexist with stage 3's route-lookup frame.
    if let EgressVerdict::Local { tap_ifindex, .. } = verdict {
        if was_new && dest_ingress_fw_v6(data, data_end, tap_ifindex) {
            return EgressVerdict::Drop;
        }
    }
    verdict
}
