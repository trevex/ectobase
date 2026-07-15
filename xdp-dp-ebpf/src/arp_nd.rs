use aya_ebpf::programs::XdpContext;
use xdp_dp_common::PortMeta;

/// Virtual gateway MAC the datapath answers ARP with (and uses as inner-eth src on delivery).
/// Single-sourced in `xdp_dp_common::proto` so eBPF, core, and sim share the exact same value.
pub use xdp_dp_common::proto::GW_MAC;

/// Reflect a rewritten-in-place reply (ARP / ND / DHCP) back to the guest it arrived from, and
/// return the XDP action to use.
///
/// We use `bpf_redirect(ingress_ifindex)` rather than `XDP_TX`. On a vhost-net-backed tun, the
/// XDP_TX path is NOT drained back to the guest: the guest's RX is fed by vhost reading the tun's
/// `ptr_ring`, which `ndo_xdp_xmit` (redirect) feeds but the XDP_TX bounce path does not — so
/// XDP_TX replies are silently lost under vhost (which native XDP requires; see the ioiab setup).
/// Redirecting to the ingress ifindex reuses the exact delivery path overlay traffic already uses
/// to reach a guest, and behaves identically in generic (SKB) mode, so conformance is unaffected.
#[inline(always)]
pub fn reflect(ctx: &XdpContext) -> u32 {
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    unsafe { aya_ebpf::helpers::bpf_redirect(ifindex, 0) as u32 }
}

/// If the frame is an ARP request for `meta.gateway_ipv4`, rewrite it in place into an ARP
/// reply (from GW_MAC / gateway IP) and return `Some(XDP_TX)`. Otherwise return `None` and the
/// caller continues its pipeline.
#[inline(always)]
pub fn try_arp_reply(ctx: &XdpContext, meta: &PortMeta) -> Option<u32> {
    if unsafe {
        xdp_dp_common::arp_nd::try_write_arp_reply(
            ctx.data(),
            ctx.data_end(),
            meta.gateway_ipv4,
            meta.guest_mac,
        )
    } {
        Some(reflect(ctx))
    } else {
        None
    }
}

/// If the frame is an ICMPv6 Neighbor Solicitation for `meta.gateway_ipv6`, rewrite it in place
/// into a solicited Neighbor Advertisement from GW_MAC and return Some(XDP_TX). NS/NA are a fixed
/// size here (40 IPv6 + 32 ICMPv6) so all accesses are constant-offset (verifier-friendly).
#[inline(always)]
pub fn try_nd_reply(ctx: &XdpContext, meta: &PortMeta) -> Option<u32> {
    if unsafe {
        xdp_dp_common::arp_nd::try_write_nd_reply(
            ctx.data(),
            ctx.data_end(),
            meta.gateway_ipv6,
            meta.guest_mac,
        )
    } {
        Some(reflect(ctx))
    } else {
        None
    }
}
