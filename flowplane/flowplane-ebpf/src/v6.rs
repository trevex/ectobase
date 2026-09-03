use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
    programs::XdpContext,
};
use flowplane_core::err::DpErr;

use crate::arp_nd::GW_MAC;
use crate::maps::{LOCAL, UNDERLAY};
use crate::parse::{write16, write6, ETH_LEN, ETH_P_IPV6, IPPROTO_ICMPV6, IPV6_LEN};
use crate::xdp_encap::reforward;

const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

/// Generate an ICMPv6 echo reply in-place for an inner-IPv6-in-IPv6 packet where the inner
/// dst is a v6 LB VIP (no VM to respond). Rewrites the packet as an ICMPv6EchoReply and
/// re-encaps it back out the uplink toward the original sender.
/// Returns Some(xdp_action) if handled, None to fall through to normal processing.
///
/// Out-of-line (`#[inline(never)]`) so its rewrite/checksum locals get their own BPF stack frame
/// instead of inflating `v6_uplink_rx`'s frame — that frame is held live across the heavy
/// `ingress_fw_ct_v6` subprogram call, and the two must stay under the 512B combined stack limit.
/// Takes `data`/`data_end` as SCALARS (not `&XdpContext`): passing the ctx across the bpf-to-bpf
/// boundary makes the compiler hand the callee `pkt`/`pkt_end` pointers, and the bounds arithmetic
/// here then trips the verifier's "R_ pointer arithmetic on pkt_end prohibited". The in-place
/// rewrite works on `data as *mut u8`; the final `bpf_redirect` needs no ctx.
#[inline(never)]
fn try_icmpv6_echo_reply(
    data: usize,
    data_end: usize,
    outer_src: [u8; 16], // outer IPv6 src (sender's underlay)
    outer_dst: [u8; 16], // outer IPv6 dst (our LB underlay)
) -> Option<u32> {
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

/// Stateless ingress firewall for the inner-v6 LB-local delivery path (no conntrack: DSR keeps the
/// inner dst = VIP). Returns `true` if the packet must be dropped. Out-of-line (`#[inline(never)]`)
/// so its firewall stack frame is freed before returning into the caller — keeps `try_uplink_rx`
/// under the 512B combined BPF stack limit.
///
/// Takes `data`/`data_end` as SCALARS and reconstructs the packet window inside via `RawPkt` — no
/// `XdpContext`/pkt pointer crosses the bpf-to-bpf boundary (passing one and then deriving `pkt_end`
/// in the callee trips the verifier's "R_ pointer arithmetic on pkt_end prohibited"). Mirrors the
/// egress `egress_fw_ct_v6` shape.
#[inline(never)]
fn ingress_fw_lb_v6(data: usize, data_end: usize, tap_ifindex: u32) -> bool {
    flowplane_core::firewall::fw_eval_dir6(
        &crate::coreimpl::RawPkt::new(data, data_end),
        &crate::coreimpl::GlobalMaps,
        ETH_LEN + IPV6_LEN,
        tap_ifindex,
        flowplane_common::FW_DIR_INGRESS,
    ) == flowplane_common::FW_ACTION_DROP
}

/// Stateful firewall + conntrack for the inner-v6 normal (non-LB) ingress delivery path, applied
/// pre-decap (inner v6 header at ETH_LEN + IPV6_LEN). Returns `true` if the packet must be dropped
/// (deny-by-default on a new flow). Out-of-line (`#[inline(never)]`) so its CtKey6/CtEntry stack
/// frame stays off the combined `try_uplink_rx` BPF stack (512B limit).
///
/// Takes `data`/`data_end` as SCALARS and reconstructs the packet window inside via `RawPkt` — no
/// `XdpContext`/pkt pointer crosses the bpf-to-bpf boundary (passing one and then deriving `pkt_end`
/// in the callee trips the verifier's "R_ pointer arithmetic on pkt_end prohibited"). Mirrors the
/// egress `egress_fw_ct_v6` shape.
#[inline(never)]
fn ingress_fw_ct_v6(data: usize, data_end: usize, tap_ifindex: u32, vni: u32) -> bool {
    if let Some(key) = crate::conntrack::ct_key6(data, data_end, ETH_LEN + IPV6_LEN, vni) {
        match unsafe { crate::maps::CONNTRACK6.get(&key) } {
            Some(e) => {
                let mut e = *e;
                crate::conntrack::ct_touch6(data, data_end, ETH_LEN + IPV6_LEN, &key, &mut e);
            }
            None => {
                if flowplane_core::firewall::fw_eval_dir6(
                    &crate::coreimpl::RawPkt::new(data, data_end),
                    &crate::coreimpl::GlobalMaps,
                    ETH_LEN + IPV6_LEN,
                    tap_ifindex,
                    flowplane_common::FW_DIR_INGRESS,
                ) == flowplane_common::FW_ACTION_DROP
                {
                    return true;
                }
                flowplane_core::conntrack::ct_create_default6(
                    &crate::coreimpl::RawPkt::new(data, data_end),
                    &mut crate::coreimpl::GlobalMaps,
                    ETH_LEN + IPV6_LEN,
                    vni,
                    crate::conntrack::now(),
                );
            }
        }
    }
    false
}

/// Decap an inner-IPv6-in-IPv6 frame (strip the 40B outer IPv6 via `adjust_head`), write the inner
/// Ethernet header (dst=guest MAC, src=GW_MAC, ethertype=IPv6), and redirect to the tap. Shared by
/// the LB-local and normal delivery arms.
///
/// Out-of-line (`#[inline(never)]`) so its post-`adjust_head` bounds-recheck + eth-write locals live
/// in their own BPF stack frame rather than inflating `v6_uplink_rx`'s frame (which is held live
/// across the `ingress_fw_ct_v6`/`ingress_fw_lb_v6` subprogram calls — 512B combined stack limit).
#[inline(never)]
fn decap_deliver_v6(ctx: &XdpContext, guest_mac: [u8; 6], tap_ifindex: u32) -> Result<u32, DpErr> {
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
        write6(q, &guest_mac);
        write6(q.add(6), &GW_MAC);
        core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IPV6.to_be());
    }
    Ok(unsafe { bpf_redirect(tap_ifindex, 0) } as u32)
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
                // Stateless ingress firewall for LB-local delivery (no conntrack: DSR keeps the
                // inner dst = VIP, and LB flows are not CT-tracked on this path). Out-of-line so
                // its firewall stack frame stays off the combined try_uplink_rx BPF stack (512B).
                if ingress_fw_lb_v6(ctx.data(), ctx.data_end(), bu.tap_ifindex) {
                    return Ok(xdp_action::XDP_DROP);
                }
                return decap_deliver_v6(ctx, guest_mac, tap_ifindex);
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
        if let Some(act) = try_icmpv6_echo_reply(ctx.data(), ctx.data_end(), outer_src, outer_dst) {
            return Ok(act);
        }
        // Unknown packet for LB VNF: drop.
        return Ok(xdp_action::XDP_DROP);
    }
    // Stateful firewall + conntrack on the inner-v6 flow before decap (mirrors the v4 uplink_rx
    // site). Inner v6 header is at ETH_LEN + IPV6_LEN pre-decap; new flows are ingress-firewalled
    // then tracked, established flows (CT hit) skip the firewall. Out-of-line so its CtKey6/CtEntry
    // stack frame stays off the combined try_uplink_rx BPF stack (512B limit).
    if ingress_fw_ct_v6(ctx.data(), ctx.data_end(), u.tap_ifindex, vni) {
        return Ok(xdp_action::XDP_DROP);
    }
    decap_deliver_v6(ctx, u.guest_mac, u.tap_ifindex)
}
