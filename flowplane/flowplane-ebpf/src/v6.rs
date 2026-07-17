use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
    programs::XdpContext,
};
use flowplane_common::PortMeta;
use flowplane_core::err::DpErr;

use crate::arp_nd::GW_MAC;
use crate::coreimpl::CtxPkt;
use crate::encap::reforward;
use crate::maps::{LOCAL, UNDERLAY};
use crate::parse::{write16, write6, ETH_LEN, ETH_P_IPV6, IPPROTO_ICMPV6, IPV6_LEN};

const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

/// Generate an ICMPv6 echo reply in-place for an inner-IPv6-in-IPv6 packet where the inner
/// dst is a v6 LB VIP (no VM to respond). Rewrites the packet as an ICMPv6EchoReply and
/// re-encaps it back out the uplink toward the original sender.
/// Returns Some(xdp_action) if handled, None to fall through to normal processing.
#[inline(always)]
fn try_icmpv6_echo_reply(
    ctx: &XdpContext,
    outer_src: [u8; 16], // outer IPv6 src (sender's underlay)
    outer_dst: [u8; 16], // outer IPv6 dst (our LB underlay)
) -> Option<u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    // Packet layout: ETH(14) + outer IPv6(40) + inner IPv6(40) + ICMPv6(at least 8).
    let inner_ip6_off = ETH_LEN + IPV6_LEN;
    let icmpv6_off = inner_ip6_off + IPV6_LEN;
    if data + icmpv6_off + 8 > data_end {
        return None;
    }
    let p = data as *mut u8;

    // Inner IPv6 next-header must be ICMPv6.
    if unsafe { *p.add(inner_ip6_off + 6) } != IPPROTO_ICMPV6 {
        return None;
    }
    // ICMPv6 type must be EchoRequest (128).
    if unsafe { *p.add(icmpv6_off) } != ICMPV6_ECHO_REQUEST {
        return None;
    }

    // Rewrite in-place: flip type 128 -> 129 and recompute ICMPv6 checksum.
    // ICMPv6 checksum covers the ICMPv6 message + IPv6 pseudo-header.
    // Incremental update: type changes from 128 to 129, one byte delta.
    // old_val (first u16 of ICMPv6: type=128, code=0) = 0x8000
    // new_val (type=129, code=0) = 0x8100
    // RFC 1624: new_cksum = ~(~old_cksum - old_halfword + new_halfword)
    // Using one's complement: new_cksum = ~(~old_cksum + ~old_halfword + new_halfword)
    let old_cksum =
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(icmpv6_off + 2) as *const u16) });
    let old_type_code: u16 = 0x8000; // type=128, code=0
    let new_type_code: u16 = 0x8100; // type=129, code=0
    let mut sum = !old_cksum as u32 + !old_type_code as u32 + new_type_code as u32;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    let new_cksum = !(sum as u16);

    unsafe {
        // Flip ICMPv6 type to EchoReply.
        *p.add(icmpv6_off) = ICMPV6_ECHO_REPLY;
        core::ptr::write_unaligned(p.add(icmpv6_off + 2) as *mut u16, new_cksum.to_be());
    }

    // Swap inner IPv6 src/dst (inner src becomes the LB VIP, inner dst becomes public sender).
    let inner_src6 =
        unsafe { core::ptr::read_unaligned(p.add(inner_ip6_off + 8) as *const [u8; 16]) };
    let inner_dst6 =
        unsafe { core::ptr::read_unaligned(p.add(inner_ip6_off + 24) as *const [u8; 16]) };
    unsafe {
        core::ptr::write_unaligned(p.add(inner_ip6_off + 8) as *mut [u8; 16], inner_dst6);
        core::ptr::write_unaligned(p.add(inner_ip6_off + 24) as *mut [u8; 16], inner_src6);
    }

    // Swap outer IPv6 src/dst and rewrite Ethernet for uplink output.
    let local = LOCAL.get(0)?;
    unsafe {
        write6(p, &local.gateway_mac); // dst = gateway MAC
        write6(p.add(6), &local.uplink_mac); // src = our uplink MAC
        write16(p.add(ETH_LEN + 8), &outer_dst); // outer IPv6 src = our LB underlay
        write16(p.add(ETH_LEN + 24), &outer_src); // outer IPv6 dst = sender's underlay
    }

    Some(unsafe { bpf_redirect(local.uplink_ifindex, 0) } as u32)
}

/// Egress for an inner IPv6 frame: run NAT64 first (XDP-only, size-changing), then execute the
/// shared `forward_decision_v6` verdict (route6 + local/encap).
#[inline(always)]
pub fn v6_guest_tx(ctx: &XdpContext, meta: &PortMeta) -> Result<u32, DpErr> {
    // NAT64: intercept packets destined to 64:ff9b::/96, translate IPv6→IPv4, SNAT, encap.
    if let Some(act) =
        crate::nat64::nat64_egress(ctx, meta.vni, meta.guest_ipv4, &meta.underlay_ipv6)?
    {
        return Ok(act);
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    match crate::egress::forward_decision_v6(ctx.data(), ctx.data_end(), 0, meta) {
        crate::egress::EgressVerdict::Pass => Ok(xdp_action::XDP_PASS),
        crate::egress::EgressVerdict::Drop => Ok(xdp_action::XDP_DROP),
        crate::egress::EgressVerdict::Local {
            tap_ifindex,
            guest_mac,
        } => {
            if ctx.data() + ETH_LEN > ctx.data_end() {
                return Ok(xdp_action::XDP_PASS);
            }
            let q = ctx.data() as *mut u8;
            unsafe {
                write6(q, &guest_mac);
                write6(q.add(6), &GW_MAC);
                core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IPV6.to_be());
            }
            Ok(unsafe { bpf_redirect(tap_ifindex, 0) } as u32)
        }
        crate::egress::EgressVerdict::Encap(e) => {
            if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(IPV6_LEN as i32)) } != 0 {
                return Err(DpErr::Bounds);
            }
            let mut pkt = CtxPkt { ctx };
            if flowplane_core::encap::write_outer_v6(&mut pkt, &e) {
                Ok(unsafe { bpf_redirect(e.uplink_ifindex, 0) } as u32)
            } else {
                Err(DpErr::Bounds)
            }
        }
    }
}

/// Ingress for an inner IPv6 frame (outer next-header 41): deliver by outer IPv6 dst, decap, write
/// the inner Ethernet (Ethertype IPv6), redirect to the tap.
#[inline(always)]
pub fn v6_uplink_rx(ctx: &XdpContext) -> Result<u32, DpErr> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN + 40 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let p = data as *const u8;
    let outer_dst = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 24) as *const [u8; 16]) };
    let outer_src = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 8) as *const [u8; 16]) };
    let u = match unsafe { UNDERLAY.get(&outer_dst) } {
        Some(u) => *u,
        None => return Ok(xdp_action::XDP_PASS),
    };
    let vni = u.vni;
    // IPv6 LB: if the inner IPv6 dst is an LB VIP, Maglev-select a backend.
    // - Remote backend: reforward the encapped packet without decap.
    // - Local backend: decap and deliver to the backend VM's tap (not the LB VNF tap).
    // The inner IPv6 header starts at ETH_LEN + IPV6_LEN (immediately after outer Eth+IPv6).
    let lb_backend = crate::lb::lb_select_forward_v6(ctx, ETH_LEN + IPV6_LEN, vni);
    if let Some(bul) = lb_backend {
        match unsafe { UNDERLAY.get(&bul) } {
            Some(bu) => {
                // Local backend: decap and deliver to the backend VM's tap.
                let guest_mac = bu.guest_mac;
                let tap_ifindex = bu.tap_ifindex;
                if unsafe { bpf_xdp_adjust_head(ctx.ctx, IPV6_LEN as i32) } != 0 {
                    return Err(DpErr::Bounds);
                }
                let data2 = ctx.data();
                let data_end2 = ctx.data_end();
                if data2 + ETH_LEN > data_end2 {
                    return Err(DpErr::Bounds);
                }
                let q = data2 as *mut u8;
                unsafe {
                    write6(q, &guest_mac);
                    write6(q.add(6), &GW_MAC);
                    core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IPV6.to_be());
                }
                return Ok(unsafe { bpf_redirect(tap_ifindex, 0) } as u32);
            }
            None => {
                // Remote backend: reforward without decap.
                let local = LOCAL.get(0).ok_or(DpErr::NoRoute)?;
                return Ok(reforward(ctx, local, &outer_dst, &bul));
            }
        }
    }
    // No LB match — check for ICMPv6 echo request destined to an LB VIP (tap=0).
    // The LB VNF underlay has tap_ifindex=0; generate the reply in-place.
    if u.tap_ifindex == 0 {
        if let Some(act) = try_icmpv6_echo_reply(ctx, outer_src, outer_dst) {
            return Ok(act);
        }
        // Unknown packet for LB VNF: drop.
        return Ok(xdp_action::XDP_DROP);
    }
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, IPV6_LEN as i32) } != 0 {
        return Err(DpErr::Bounds);
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN > data_end {
        return Err(DpErr::Bounds);
    }
    let q = data as *mut u8;
    unsafe {
        write6(q, &u.guest_mac);
        write6(q.add(6), &GW_MAC);
        core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IPV6.to_be());
    }
    Ok(unsafe { bpf_redirect(u.tap_ifindex, 0) } as u32)
}
