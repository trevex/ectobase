use crate::pkt::{Action, Pkt};
use flowplane_common::Local;

/// Parameters describing the outer Eth+IPv6 header written by [`write_outer_v6`].
///
/// `uplink_ifindex` is NOT used by the writer itself — it rides along for the caller's
/// `bpf_redirect(uplink_ifindex, ..)` after the header is written.
#[derive(Copy, Clone)]
pub struct EncapParams {
    pub gateway_mac: [u8; 6],
    pub uplink_mac: [u8; 6],
    pub uplink_ifindex: u32,
    pub src_underlay: [u8; 16],
    pub nexthop_ipv6: [u8; 16],
    pub inner_proto: u8,
    /// 20-bit IPv6 flow label written into the outer header for RFC 6438 fabric ECMP. Callers set
    /// it from [`crate::parse::flow_label20`] of the inner flow hash; 0 = no ECMP hint.
    pub flow_label: u32,
}

// Single-sourced in `flowplane_common::proto`; re-exported so `flowplane_core::encap::{ETH_LEN, ..}` holds.
pub use flowplane_common::proto::{ETH_LEN, ETH_P_IPV6, IPV6_LEN};

/// Write outer Eth+IPv6 into a frame that already has IPV6_LEN bytes of front room. Pure byte
/// writes via `Pkt` — no resize, no redirect. Returns false on bounds failure.
///
/// The outer IPv6 `payload_length` (the encapsulated inner length) is derived from the packet's
/// LOGICAL length, not its linear head: the frame here is laid out `[outer_eth(ETH_LEN)]
/// [outer_ipv6(IPV6_LEN)][inner_ip…]`, so `inner_len = logical_len - ETH_LEN - IPV6_LEN`. Using
/// `logical_len()` (skb->len on tc) makes a non-linear skb encapsulate with the correct outer
/// length instead of a short, truncated one.
#[inline(always)]
pub fn write_outer_v6<P: Pkt>(pkt: &mut P, e: &EncapParams) -> bool {
    if ETH_LEN + IPV6_LEN > pkt.len() {
        return false;
    }
    let inner_len = pkt.logical_len().saturating_sub(ETH_LEN + IPV6_LEN) as u16;
    let mut ok = true;
    ok &= pkt.write_bytes(0, &e.gateway_mac);
    ok &= pkt.write_bytes(6, &e.uplink_mac);
    ok &= pkt.write_bytes(12, &ETH_P_IPV6.to_be_bytes());
    let ip = ETH_LEN;
    // IPv6 first word: version(4b)=6, traffic-class(8b)=0, flow-label(20b). The 20-bit label carries
    // per-flow entropy for RFC 6438 fabric ECMP; masked so it can't spill into the version/TC nibble.
    let fl = e.flow_label & 0x000F_FFFF;
    ok &= pkt.write_bytes(ip, &[0x60, (fl >> 16) as u8, (fl >> 8) as u8, fl as u8]);
    ok &= pkt.write_bytes(ip + 4, &inner_len.to_be_bytes());
    ok &= pkt.write_bytes(ip + 6, &[e.inner_proto, 64]); // [next_header, hop_limit=64]
    ok &= pkt.write_bytes(ip + 8, &e.src_underlay);
    ok &= pkt.write_bytes(ip + 24, &e.nexthop_ipv6);
    ok
}

/// Re-forward an already-encapped frame to a new backend underlay (LB remote backend): rewrite the
/// outer Ethernet (dst=gateway_mac, src=uplink_mac) + outer IPv6 src=lb_underlay / dst=backend, and
/// return Redirect(uplink_ifindex) WITHOUT decap. Faithful port of eBPF `encap::reforward`.
#[inline(always)]
pub fn reforward<P: Pkt>(
    pkt: &mut P,
    local: &Local,
    lb_underlay: &[u8; 16],
    backend: &[u8; 16],
) -> Action {
    if ETH_LEN + IPV6_LEN > pkt.len() {
        return Action::Drop;
    }
    let mut ok = true;
    ok &= pkt.write_bytes(0, &local.gateway_mac);
    ok &= pkt.write_bytes(6, &local.uplink_mac);
    ok &= pkt.write_bytes(ETH_LEN + 8, lb_underlay);
    ok &= pkt.write_bytes(ETH_LEN + 24, backend);
    if !ok {
        return Action::Drop;
    }
    Action::Redirect(local.uplink_ifindex)
}
