use flowplane_common::{PortMeta, RouteLpmData6};
use flowplane_core::encap::EncapParams;

use crate::maps::{LOCAL, ROUTES6, UNDERLAY};
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
    // So an egress-INITIATED flow needs an explicit egress-allow NetworkPolicy; an ingress-
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
    match flowplane_core::egress::deliver(
        &crate::coreimpl::GlobalMaps,
        &route,
        meta,
        crate::parse::IPPROTO_IPIP,
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

/// IPv6-inner egress decision (route6 + local/encap). Map-driven; used by tc. No NAT64 (caller
/// runs that first), no resize. Caller verified ETH_LEN+IPV6_LEN present and
/// ethertype==ETH_P_IPV6.
#[inline(always)]
pub fn forward_decision_v6(
    data: usize,
    _data_end: usize,
    _ifindex: u32,
    meta: &PortMeta,
) -> EgressVerdict {
    let p = data as *const u8;
    // inner IPv6 dst at ETH_LEN + 24
    let dst = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 24) as *const [u8; 16]) };
    let route = match ROUTES6.get(&aya_ebpf::maps::lpm_trie::Key::new(
        160,
        RouteLpmData6 {
            vni: meta.vni.to_be_bytes(),
            ipv6: dst,
        },
    )) {
        Some(r) => r,
        None => return EgressVerdict::Pass,
    };
    // Local fast path: if the nexthop underlay is a LOCAL interface, deliver straight to that tap.
    if let Some(u) = unsafe { UNDERLAY.get(&route.nexthop_ipv6) } {
        if u.tap_ifindex != 0 {
            return EgressVerdict::Local {
                tap_ifindex: u.tap_ifindex,
                guest_mac: u.guest_mac,
            };
        }
    }
    let local = match LOCAL.get(0) {
        Some(l) => l,
        None => return EgressVerdict::Pass,
    };
    EgressVerdict::Encap(EncapParams {
        gateway_mac: local.gateway_mac,
        uplink_mac: local.uplink_mac,
        uplink_ifindex: local.uplink_ifindex,
        src_underlay: meta.underlay_ipv6,
        nexthop_ipv6: route.nexthop_ipv6,
        inner_proto: crate::parse::IPPROTO_IPV6,
    })
}
