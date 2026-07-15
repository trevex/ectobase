use crate::pkt::Pkt;

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
    pub inner_len: u16,
    pub inner_proto: u8,
}

// Single-sourced in `xdp_dp_common::proto`; re-exported so `xdp_dp_core::encap::{ETH_LEN, ..}` holds.
pub use xdp_dp_common::proto::{ETH_LEN, ETH_P_IPV6, IPV6_LEN};

/// Write outer Eth+IPv6 into a frame that already has IPV6_LEN bytes of front room. Pure byte
/// writes via `Pkt` — no resize, no redirect. Returns false on bounds failure.
#[inline(always)]
pub fn write_outer_v6<P: Pkt>(pkt: &mut P, e: &EncapParams) -> bool {
    if ETH_LEN + IPV6_LEN > pkt.len() {
        return false;
    }
    let mut ok = true;
    ok &= pkt.write_bytes(0, &e.gateway_mac);
    ok &= pkt.write_bytes(6, &e.uplink_mac);
    ok &= pkt.write_bytes(12, &ETH_P_IPV6.to_be_bytes());
    let ip = ETH_LEN;
    ok &= pkt.write_bytes(ip, &[0x60, 0, 0, 0]);
    ok &= pkt.write_bytes(ip + 4, &e.inner_len.to_be_bytes());
    ok &= pkt.write_bytes(ip + 6, &[e.inner_proto, 64]); // [next_header, hop_limit=64]
    ok &= pkt.write_bytes(ip + 8, &e.src_underlay);
    ok &= pkt.write_bytes(ip + 24, &e.nexthop_ipv6);
    ok
}
