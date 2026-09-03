//! Outer Eth+IPv6 byte writer for the uplink/WAN-edge XDP programs — a STOPGAP kept ONLY because
//! those programs cannot adopt the Geneve `bpf_skb_set_tunnel_key` mechanism the tc guest-egress
//! path now uses (see `crate::tunnel`): that helper is skb-only (tc/cls_act) and has no XDP
//! counterpart — XDP runs before skb allocation, so there is no `collect_md` metadata dst to stamp.
//!
//! Migrating `ingress.rs`'s `try_uplink_rx` (LB remote-backend reforward, neighbor-NAT relay) and
//! `try_wan_rx` (WAN-VIP encap, neighbor-NAT relay) to tc — so THEY can use `crate::tunnel` too and
//! this module can be deleted — is a separate, larger conversion (XDP -> tcx) explicitly out of
//! scope for the encap-path migration this module's sibling `crate::tunnel` implements. Until that
//! lands, these programs keep hand-writing the outer header exactly as
//! `flowplane_core::encap::{EncapParams, write_outer_v6, reforward}` did before P2 replaced that
//! core module with the pure `TunnelEncap` decision — relocated here (no longer core-shared) since
//! core no longer owns byte-written outer headers.

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
    programs::XdpContext,
};
use flowplane_common::{Local, RouteValue};
use flowplane_core::err::DpErr;
use flowplane_core::pkt::Pkt;

use crate::coreimpl::CtxPkt;
use crate::parse::{ETH_LEN, ETH_P_IPV6, IPV6_LEN};

/// Faithful copy of the pre-P2 `flowplane_core::encap::EncapParams` (minus the unused
/// `flow_label`/`uplink_ifindex` fields these XDP call sites never populated with real values).
#[derive(Copy, Clone)]
struct EncapParams {
    gateway_mac: [u8; 6],
    uplink_mac: [u8; 6],
    src_underlay: [u8; 16],
    nexthop_ipv6: [u8; 16],
    inner_proto: u8,
}

/// Faithful copy of the pre-P2 `flowplane_core::encap::write_outer_v6` (RFC 6438 flow-label entropy
/// dropped: these WAN/neighbor-NAT relay call sites never threaded one through either, both before
/// and after this port).
#[inline(always)]
fn write_outer_v6<P: Pkt>(pkt: &mut P, e: &EncapParams) -> bool {
    if ETH_LEN + IPV6_LEN > pkt.len() {
        return false;
    }
    let inner_len = pkt.logical_len().saturating_sub(ETH_LEN + IPV6_LEN) as u16;
    let mut ok = true;
    ok &= pkt.write_bytes(0, &e.gateway_mac);
    ok &= pkt.write_bytes(6, &e.uplink_mac);
    ok &= pkt.write_bytes(12, &ETH_P_IPV6.to_be_bytes());
    let ip = ETH_LEN;
    ok &= pkt.write_bytes(ip, &[0x60, 0, 0, 0]); // version=6, traffic-class=0, flow-label=0
    ok &= pkt.write_bytes(ip + 4, &inner_len.to_be_bytes());
    ok &= pkt.write_bytes(ip + 6, &[e.inner_proto, 64]); // [next_header, hop_limit=64]
    ok &= pkt.write_bytes(ip + 8, &e.src_underlay);
    ok &= pkt.write_bytes(ip + 24, &e.nexthop_ipv6);
    ok
}

/// Grow headroom and write the outer Eth+IPv6 for an encap toward `route.nexthop_ipv6`. Returns
/// `true` on success. `inner_proto` = IPv6 next-header byte (IPPROTO_IPIP for an IPv4 inner,
/// IPPROTO_IPV6 for IPv6).
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
        src_underlay: *src_underlay,
        nexthop_ipv6: route.nexthop_ipv6,
        inner_proto,
    };
    write_outer_v6(&mut CtxPkt { ctx }, &e)
}

/// Encap + redirect via the `UPLINK_DEV` devmap (slot 0 == uplink ifindex) instead of a plain
/// `bpf_redirect`. On containerlab veth uplinks a plain XDP_REDIRECT is silently dropped unless the
/// peer port has an XDP program (veth `ndo_xdp_xmit` peer requirement); the devmap path avoids that.
/// Used ONLY by the edge `wan_rx` branches (which have no tail calls). Production real NICs are
/// unaffected either way.
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
    if ETH_LEN + IPV6_LEN > (ctx.data_end() - ctx.data()) {
        return xdp_action::XDP_DROP;
    }
    let mut pkt = CtxPkt { ctx };
    let mut ok = true;
    ok &= pkt.write_bytes(0, &local.gateway_mac);
    ok &= pkt.write_bytes(6, &local.uplink_mac);
    ok &= pkt.write_bytes(ETH_LEN + 8, lb_underlay);
    ok &= pkt.write_bytes(ETH_LEN + 24, backend);
    if !ok {
        return xdp_action::XDP_DROP;
    }
    (unsafe { bpf_redirect(local.uplink_ifindex, 0) }) as u32
}
