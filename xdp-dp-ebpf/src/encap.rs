use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
    programs::XdpContext,
};
use xdp_dp_common::{Local, RouteValue};
use xdp_dp_core::encap::{write_outer_v6, EncapParams, IPV6_LEN};

use crate::coreimpl::CtxPkt;
use crate::parse::{write16, write6, ETH_LEN};

/// Encapsulate the current inner IPv4 frame into Eth+IPv6 toward `route.nexthop_ipv6` and
/// redirect out the local uplink. `inner_len` = (frame len - inner ETH_LEN), captured BEFORE
/// adjust_head. `inner_proto` = IPv6 next-header byte (e.g. IPPROTO_IPIP for IPv4, IPPROTO_IPV6
/// for IPv6).
#[inline(always)]
pub fn encap_and_redirect(
    ctx: &XdpContext,
    local: &Local,
    src_underlay: &[u8; 16],
    route: &RouteValue,
    inner_len: u16,
    inner_proto: u8,
) -> Result<u32, ()> {
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(IPV6_LEN as i32)) } != 0 {
        return Err(());
    }
    let e = EncapParams {
        gateway_mac: local.gateway_mac,
        uplink_mac: local.uplink_mac,
        uplink_ifindex: local.uplink_ifindex,
        src_underlay: *src_underlay,
        nexthop_ipv6: route.nexthop_ipv6,
        inner_len,
        inner_proto,
    };
    let mut pkt = CtxPkt { ctx };
    if write_outer_v6(&mut pkt, &e) {
        Ok(unsafe { bpf_redirect(e.uplink_ifindex, 0) } as u32)
    } else {
        Err(())
    }
}

/// Re-forward an already-encapped packet to a new backend underlay (LB remote backend): rewrite
/// the outer Ethernet (dst=gateway_mac, src=uplink_mac) + outer IPv6 (src=lb_underlay,
/// dst=backend) and redirect out the uplink WITHOUT decap. Returns the XDP action.
#[inline(always)]
pub fn reforward(
    ctx: &XdpContext,
    local: &Local,
    lb_underlay: &[u8; 16],
    backend: &[u8; 16],
) -> u32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN > data_end {
        return xdp_action::XDP_DROP;
    }
    let p = data as *mut u8;
    unsafe {
        write6(p, &local.gateway_mac);
        write6(p.add(6), &local.uplink_mac);
        let ip = p.add(ETH_LEN);
        write16(ip.add(8), lb_underlay);
        write16(ip.add(24), backend);
        bpf_redirect(local.uplink_ifindex, 0) as u32
    }
}
