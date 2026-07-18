use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
    programs::XdpContext,
};
use flowplane_common::{Local, RouteValue};
use flowplane_core::encap::{write_outer_v6, EncapParams, IPV6_LEN};
use flowplane_core::err::DpErr;

use crate::coreimpl::CtxPkt;

/// Grow headroom and write the outer Eth+IPv6 for an encap toward `route.nexthop_ipv6`. Returns
/// `true` on success.
/// `inner_proto` = IPv6 next-header byte (IPPROTO_IPIP for an IPv4 inner, IPPROTO_IPV6 for IPv6).
#[inline(always)]
fn write_encap_outer(
    ctx: &XdpContext,
    local: &Local,
    src_underlay: &[u8; 16],
    route: &RouteValue,
    inner_proto: u8,
) -> bool {
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(IPV6_LEN as i32)) } != 0 {
        return false;
    }
    let e = EncapParams {
        gateway_mac: local.gateway_mac,
        uplink_mac: local.uplink_mac,
        uplink_ifindex: local.uplink_ifindex,
        src_underlay: *src_underlay,
        nexthop_ipv6: route.nexthop_ipv6,
        inner_proto,
    };
    write_outer_v6(&mut CtxPkt { ctx }, &e)
}

/// Like [`encap_and_redirect`] but redirects via the `UPLINK_DEV` devmap (slot 0 == uplink ifindex)
/// instead of a plain `bpf_redirect`. On containerlab veth uplinks a plain XDP_REDIRECT is silently
/// dropped unless the peer port has an XDP program (veth `ndo_xdp_xmit` peer requirement); the devmap
/// path avoids that. Used ONLY by the edge `wan_rx` branches (which have no tail calls). Production
/// real NICs are unaffected either way.
#[inline(always)]
pub fn encap_and_redirect_via_devmap(
    ctx: &XdpContext,
    local: &Local,
    src_underlay: &[u8; 16],
    route: &RouteValue,
    inner_proto: u8,
) -> Result<u32, DpErr> {
    if write_encap_outer(ctx, local, src_underlay, route, inner_proto) {
        Ok(crate::maps::UPLINK_DEV
            .redirect(0, 0)
            .unwrap_or(xdp_action::XDP_ABORTED))
    } else {
        Err(DpErr::Bounds)
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
    match flowplane_core::encap::reforward(
        &mut crate::coreimpl::CtxPkt { ctx },
        local,
        lb_underlay,
        backend,
    ) {
        flowplane_core::pkt::Action::Redirect(ifindex) => {
            (unsafe { bpf_redirect(ifindex, 0) }) as u32
        }
        _ => xdp_action::XDP_DROP,
    }
}
