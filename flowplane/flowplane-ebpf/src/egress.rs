use flowplane_common::PortMeta;
use flowplane_core::encap::EncapParams;

use crate::parse::ETH_LEN;

/// What the per-program glue should do after the in-place egress pipeline runs.
pub enum EgressVerdict {
    Pass,
    Drop,
    Local {
        tap_ifindex: u32,
        guest_mac: [u8; 6],
    },
    Encap(EncapParams),
}

/// Compute the outer IPv6 flow label from the inner packet, as a NON-inlined BPF subprogram so its
/// locals get their own stack frame instead of piling onto `tc_guest_tx` (which is already at the
/// 512-byte BPF stack limit). Takes `data`/`data_end` as scalars and reconstructs the packet window
/// inside — no packet pointer crosses the call boundary, so the verifier re-derives bounds cleanly.
/// The combined call-chain stack (tc_guest_tx + this frame) must stay under 512B, so
/// `inner_flow_label` folds the 5-tuple incrementally rather than materializing address arrays.
#[inline(never)]
fn egress_flow_label(data: usize, data_end: usize, is_v6: bool) -> u32 {
    flowplane_core::parse::inner_flow_label(
        &crate::coreimpl::RawPkt::new(data, data_end),
        ETH_LEN,
        is_v6,
    )
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
    flowplane_core::nat::snat_egress(
        &mut crate::coreimpl::RawPkt::new(data, data_end),
        &mut crate::coreimpl::GlobalMaps,
        ETH_LEN,
        meta.vni,
        is_ext,
        crate::conntrack::now(),
    );
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
    // Outer IPv6 flow label from the (post-NAT) inner 5-tuple, for RFC 6438 fabric ECMP.
    let flow_label = egress_flow_label(data, data_end, false);
    match flowplane_core::egress::deliver(
        &crate::coreimpl::GlobalMaps,
        &route,
        meta,
        crate::parse::IPPROTO_IPIP,
        flow_label,
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
        flowplane_core::egress::Deliver::Encap(e) => EgressVerdict::Encap(e),
        flowplane_core::egress::Deliver::Pass => EgressVerdict::Pass,
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
    // — the SAME code the native SimNode + DPDK `process_guest_tx_v6` run. This wrapper stays a
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
    // = `route6` + `deliver`, `inner_proto = IPPROTO_IPV6`) — the SAME code the native SimNode + DPDK
    // `process_guest_tx_v6` run. GlobalMaps' `route6_get`/`underlay_get`/`local()` compile to the
    // same `ROUTES6`/`UNDERLAY`/`LOCAL[0]` accesses this wrapper used before, so the byte-relevant
    // decision is unchanged. This wrapper stays a `#[inline(never)]` subprogram so the core stage's
    // route-lookup `Key<RouteLpmData6>` frame gets its own BPF stack frame, sequential to (never
    // coexisting with) `egress_fw_ct_v6`'s CtKey6 frame (512B combined limit). The outer flow label
    // is computed here (out-of-line via `egress_flow_label`) and passed in, so no address arrays land
    // on this frame.
    let flow_label = egress_flow_label(data, data_end, true);
    match flowplane_core::egress::route_decision6(
        &crate::coreimpl::RawPkt::new(data, data_end),
        &crate::coreimpl::GlobalMaps,
        meta,
        flow_label,
    ) {
        flowplane_core::egress::Deliver::Local {
            tap_ifindex,
            guest_mac,
        } => EgressVerdict::Local {
            tap_ifindex,
            guest_mac,
        },
        flowplane_core::egress::Deliver::Encap(e) => EgressVerdict::Encap(e),
        flowplane_core::egress::Deliver::Pass => EgressVerdict::Pass,
    }
}

/// IPv6-inner egress decision (fw/ct + route6 + local/encap). Map-driven; used by tc. No NAT64
/// (caller runs that first), no resize. Caller verified ETH_LEN+IPV6_LEN present and
/// ethertype==ETH_P_IPV6.
///
/// THIN dispatcher: the two heavy stages — stateful firewall/conntrack (`egress_fw_ct_v6`, ~336B)
/// and the route6 lookup + deliver (`route_decision_v6`, ~264B) — are each their own
/// `#[inline(never)]` subprogram, called SEQUENTIALLY here. So neither of the big frames coexists
/// with the other on the combined BPF stack (512B limit); this dispatcher itself carries no heavy
/// locals. Established flows (CT hit) skip the firewall; new flows are egress-firewalled then
/// tracked, then routed.
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
    // Stage 2: route6 + deliver decision (its own sequential frame — freed before stage 3).
    let verdict = route_decision_v6(data, data_end, meta);
    // Stage 3: on a NEW flow delivered to a SAME-NODE guest, enforce the DESTINATION's ingress
    // firewall (uplink_rx is bypassed for same-node traffic). Deny-by-default. Mirrors the v4
    // `forward_decision_v4` Local arm. Established flows (was_new==false, incl. the pre-seeded
    // reverse entry for a same-node reply) skip this. `dest_ingress_fw_v6` is its own sequential
    // #[inline(never)] frame so its FwRule6 locals never coexist with stage 2's route-lookup frame.
    if let EgressVerdict::Local { tap_ifindex, .. } = verdict {
        if was_new && dest_ingress_fw_v6(data, data_end, tap_ifindex) {
            return EgressVerdict::Drop;
        }
    }
    verdict
}
