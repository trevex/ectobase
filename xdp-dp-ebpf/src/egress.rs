use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use xdp_dp_common::{PortMeta, RouteLpmData6};
use xdp_dp_core::encap::EncapParams;

use crate::arp_nd::try_arp_reply;
use crate::coreimpl::CtxPkt;
use crate::maps::{LOCAL, PORT_META, ROUTES, ROUTES6, UNDERLAY};
use crate::parse::{write6, ETH_LEN, ETH_P_IP, IPV6_LEN};

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
/// the caller's glue should do. Map-driven; shared by XDP `guest_tx` and tc `tc_guest_tx`. Mutates
/// the packet in place but does NOT resize. Caller has already verified ethertype == ETH_P_IP and
/// that ETH_LEN+20 bytes are present.
#[inline(always)]
pub fn forward_decision_v4(
    data: usize,
    data_end: usize,
    ifindex: u32,
    meta: &PortMeta,
) -> EgressVerdict {
    let p = data as *const u8;
    // Conntrack + egress firewall. Established flows: apply translation + refresh. New flows:
    // enforce the SOURCE interface's EGRESS firewall (whitelist; no rules => accept).
    //
    // Only apply CT_REWRITE_SRC (egress-direction) translations here. CT_REWRITE_DST entries are
    // reverse-NAT entries created for ingress return traffic; they must NOT be applied in the
    // egress path (otherwise a non-NAT'd VM replying to a NATted peer would have its dst
    // incorrectly rewritten and be delivered locally instead of going out to the router).
    if let Some(key) = crate::conntrack::ct_key(data, data_end, ETH_LEN, meta.vni) {
        match unsafe { crate::maps::CONNTRACK.get(&key) } {
            Some(e) => {
                let mut e = *e;
                if e.flags & xdp_dp_common::CT_REWRITE_SRC != 0 {
                    crate::conntrack::ct_apply(data, data_end, ETH_LEN, &e);
                }
                crate::conntrack::ct_touch(data, data_end, ETH_LEN, &key, &mut e);
            }
            None => {
                if xdp_dp_core::firewall::fw_eval_dir(
                    &crate::coreimpl::RawPkt { data, data_end },
                    &crate::coreimpl::GlobalMaps,
                    ETH_LEN,
                    ifindex,
                    xdp_dp_common::FW_DIR_EGRESS,
                ) == xdp_dp_common::FW_ACTION_DROP
                    && crate::firewall::fw_enforcing()
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
    let route = match ROUTES.get(&aya_ebpf::maps::lpm_trie::Key::new(
        64,
        xdp_dp_common::RouteLpmData {
            vni: meta.vni.to_be_bytes(),
            ipv4: dst,
        },
    )) {
        Some(r) => r,
        None => return EgressVerdict::Pass,
    };
    // Network NAT: SNAT guest -> nat_ip:port when the dst route is external.
    let is_ext = route.is_external != 0;
    crate::nat::nat_snat_egress(data, data_end, ETH_LEN, meta.vni, is_ext);
    // Track every flow.
    if let Some(key) = crate::conntrack::ct_key(data, data_end, ETH_LEN, meta.vni) {
        if unsafe { crate::maps::CONNTRACK.get(&key) }.is_none() {
            crate::conntrack::ct_ensure_default(data, data_end, ETH_LEN, &key);
        }
    }
    // Rate metering.
    let frame_len = (data_end - data) as u64;
    if !crate::meter::meter_pass(ifindex, frame_len, is_ext) {
        return EgressVerdict::Drop;
    }
    // Local fast path: if the route's nexthop underlay is one of our own LOCAL interfaces, deliver
    // straight to that tap (no encap, no PF hairpin). LB anycast entries have tap_ifindex==0 and
    // are skipped (they encap to the selected backend underlay as usual).
    if let Some(u) = unsafe { UNDERLAY.get(&route.nexthop_ipv6) } {
        if u.tap_ifindex != 0 {
            return EgressVerdict::Local {
                tap_ifindex: u.tap_ifindex,
                guest_mac: u.guest_mac,
            };
        }
    }
    let inner_len = (data_end - data - ETH_LEN) as u16;
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
        inner_len,
        inner_proto: crate::parse::IPPROTO_IPIP,
    })
}

/// IPv6-inner egress decision (route6 + local/encap). Map-driven; shared by XDP `v6_guest_tx` and
/// tc. No NAT64 (caller runs that first on XDP), no resize. Caller verified ETH_LEN+IPV6_LEN present
/// and ethertype==ETH_P_IPV6.
#[inline(always)]
pub fn forward_decision_v6(
    data: usize,
    data_end: usize,
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
    let inner_len = (data_end - data - ETH_LEN) as u16;
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
        inner_len,
        inner_proto: crate::parse::IPPROTO_IPV6,
    })
}

pub fn try_guest_tx(ctx: &XdpContext) -> Result<u32, ()> {
    // Identify the port by its ingress ifindex.
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let meta = unsafe { PORT_META.get(&ifindex) }.ok_or(())?;

    // Answer ARP for the gateway in-datapath.
    if let Some(act) = try_arp_reply(ctx, meta) {
        return Ok(act);
    }

    // Answer IPv6 Neighbor Discovery for the gateway in-datapath.
    if let Some(act) = crate::arp_nd::try_nd_reply(ctx, meta) {
        return Ok(act);
    }

    // DHCP (v4: IPv4/UDP dport 67, v6: IPv6/UDP dport 547) is handled by the separate `guest_dhcp`
    // program via tail call, so its verifier cost does not stack onto this program's IPv4 forwarding
    // path. Classification is port-only; `guest_dhcp` re-validates and answers DISCOVER/REQUEST (v4)
    // and SOLICIT/REQUEST/CONFIRM (v6), returning XDP_PASS otherwise.
    //
    // NOTE: this changes one corner case versus the old inline path. Previously a 67/547 frame the
    // responders did NOT answer (e.g. a v6 RENEW/RELEASE, or a v4 INFORM) fell through to the
    // forwarder. Now such frames PASS. This is behaviour-neutral in practice — unanswered DHCP is
    // broadcast/multicast (255.255.255.255, ff02::1:2), which misses the route lookup and PASSes
    // there too — and arguably more correct (guest-originated DHCP is never overlay-forwarded). A
    // genuine tail-call miss (slot unpopulated / depth limit) also falls through to PASS here.
    if is_dhcp_request(ctx) {
        let _ = unsafe { crate::maps::GUEST_PROGS.tail_call(ctx, xdp_dp_common::GUEST_PROG_DHCP) };
        return Ok(xdp_action::XDP_PASS);
    }

    // IPv6 inner frames take the v6 overlay path.
    {
        let d = ctx.data();
        if d + 14 <= ctx.data_end() {
            let et = u16::from_be(unsafe {
                core::ptr::read_unaligned((d as *const u8).add(12) as *const u16)
            });
            if et == crate::parse::ETH_P_IPV6 {
                return crate::v6::v6_guest_tx(ctx, meta);
            }
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let ethertype = u16::from_be(unsafe {
        core::ptr::read_unaligned((data as *const u8).add(12) as *const u16)
    });
    if ethertype != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    match forward_decision_v4(ctx.data(), ctx.data_end(), ifindex, meta) {
        EgressVerdict::Pass => Ok(xdp_action::XDP_PASS),
        EgressVerdict::Drop => Ok(xdp_action::XDP_DROP),
        EgressVerdict::Local {
            tap_ifindex,
            guest_mac,
        } => {
            if ctx.data() + ETH_LEN > ctx.data_end() {
                return Ok(xdp_action::XDP_PASS);
            }
            let q = ctx.data() as *mut u8;
            unsafe {
                write6(q, &guest_mac); // dst = local guest MAC
                write6(q.add(6), &crate::arp_nd::GW_MAC); // src = gateway MAC
                                                          // ethertype stays ETH_P_IP
            }
            Ok(unsafe { aya_ebpf::helpers::bpf_redirect(tap_ifindex, 0) } as u32)
        }
        EgressVerdict::Encap(e) => {
            if unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.ctx, -(IPV6_LEN as i32)) } != 0 {
                return Err(());
            }
            let mut pkt = CtxPkt { ctx };
            if xdp_dp_core::encap::write_outer_v6(&mut pkt, &e) {
                Ok(unsafe { aya_ebpf::helpers::bpf_redirect(e.uplink_ifindex, 0) } as u32)
            } else {
                Err(())
            }
        }
    }
}

/// True if the frame is a DHCP request a guest would send: IPv4/UDP to dport 67, or IPv6/UDP to
/// dport 547. Pure reads, constant offsets, no packet mutation — cheap to run on every frame.
#[inline(always)]
fn is_dhcp_request(ctx: &XdpContext) -> bool {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + 44 > data_end {
        return false;
    }
    let p = data as *const u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype == ETH_P_IP {
        // Assumes IHL==5 (UDP dport at ETH+22). DHCP requests carry no IP options; an IHL>5 frame
        // that happens to read 67 here is harmless — `try_dhcpv4_reply` re-checks IHL==5 and PASSes.
        if unsafe { *p.add(ETH_LEN + 9) } != crate::parse::IPPROTO_UDP {
            return false;
        }
        let dport =
            u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 22) as *const u16) });
        return dport == 67;
    }
    if ethertype == crate::parse::ETH_P_IPV6 {
        if unsafe { *p.add(ETH_LEN + 6) } != crate::parse::IPPROTO_UDP {
            return false;
        }
        let dport = u16::from_be(unsafe {
            core::ptr::read_unaligned(p.add(ETH_LEN + 40 + 2) as *const u16)
        });
        return dport == 547;
    }
    false
}

/// Tail-call target: run the in-datapath DHCPv4 + DHCPv6 responders. Re-looks-up the port by its
/// ingress ifindex (tail calls invalidate the previous program's pointers/locals). Returns
/// `XDP_PASS` when the frame is not actually a DHCP request we answer.
pub fn dhcp_handle(ctx: &XdpContext) -> u32 {
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let meta = match unsafe { PORT_META.get(&ifindex) } {
        Some(m) => m,
        None => return xdp_action::XDP_PASS,
    };
    if let Some(act) = crate::dhcp::try_dhcpv4_reply(ctx, meta) {
        return act;
    }
    if let Some(act) = crate::dhcp::try_dhcpv6_reply(ctx, meta) {
        return act;
    }
    xdp_action::XDP_PASS
}
