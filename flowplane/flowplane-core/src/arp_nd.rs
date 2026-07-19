//! Guest-facing gateway responders (ARP + IPv6 Neighbor Discovery), ported over the `Pkt` trait so
//! the SAME in-place byte rewrite runs in the eBPF `guest_tx` datapath and natively in the sim.
//!
//! Faithful port of the previous inline builders in `flowplane_common::arp_nd`
//! (`try_write_arp_reply` / `try_write_nd_reply`): a guest ARP request for the virtual gateway IPv4
//! is rewritten in place into an ARP reply (op=reply, sender = gateway MAC/IP, target = original
//! requester, Ethernet src/dst swapped); a guest ICMPv6 Neighbor Solicitation for the gateway IPv6
//! is rewritten into a solicited Neighbor Advertisement (type 136, target = gateway, the
//! target-link-layer-address option = gateway MAC, solicited+override flags, recomputed ICMPv6
//! checksum over the IPv6 pseudo-header). Both replies are FIXED-SIZE in-place rewrites, so every
//! packet access is a constant-offset `read_array`/`write_array` — verifier-friendly.
//!
//! Scope: this covers only the byte rewrite. The eBPF glue owns the classification-entry
//! (ingress_ifindex -> `PortMeta`) and the reflect verdict (`bpf_redirect(ingress_ifindex)`); the
//! sim supplies the gateway config directly. `gateway_ipv4`/`gateway_ipv6`/`reply_mac` are passed in
//! (they live in the per-port `PortMeta`), so no `Maps` accessor is needed.

use crate::pkt::Pkt;
use flowplane_common::proto::{ETH_LEN, ETH_P_IPV6, IPV6_LEN};

/// EtherType for ARP.
pub const ETH_P_ARP: u16 = 0x0806;
/// ARP payload length after the Ethernet header: opcode@6 sha@8 spa@14 tha@18 tpa@24.
pub const ARP_LEN: usize = 28;
/// IPv6 next-header for ICMPv6.
pub const IPPROTO_ICMPV6: u8 = 58;
const ND_NS: u8 = 135;
const ND_NA: u8 = 136;
/// ICMPv6 Router Solicitation / Router Advertisement types.
pub const ND_RS: u8 = 133;
const ND_RA: u8 = 134;
/// Full RA frame length: Eth(14) + IPv6(40) + RA header(16) + SLLA option(8) + MTU option(8) = 86.
/// The RA is larger than a Router Solicitation, so the eBPF glue grows the skb to this before writing.
pub const RA_LEN: usize = ETH_LEN + IPV6_LEN + 32;

/// One's-complement checksum over `len` bytes of `pkt` starting at `off`, folded with an initial
/// `sum` (the IPv6 pseudo-header). Reads through the `Pkt` trait a `u16` at a time; `len` must be
/// even for the caller (the ICMPv6 NA header we sum is 32 bytes). Two fixed fold rounds suffice for
/// any 32-bit accumulator (the BPF verifier requires bounded loops). Byte-identical to the previous
/// `flowplane_common::arp_nd::csum16`.
#[inline(always)]
fn csum16<P: Pkt>(mut sum: u32, pkt: &P, off: usize, len: usize) -> u16 {
    let mut i = 0;
    while i + 1 < len {
        if let Some(b) = pkt.read_array::<2>(off + i) {
            sum += u16::from_be_bytes(b) as u32;
        }
        i += 2;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

/// If `pkt` is an ICMPv6 Neighbor Solicitation for `gateway_ipv6`, rewrite it in place into a
/// solicited Neighbor Advertisement from `reply_mac` and return true. Else false (unchanged).
///
/// NS/NA are a fixed size here (14 Eth + 40 IPv6 + 32 ICMPv6), so every access is constant-offset —
/// verifier-friendly. Faithful port of `flowplane_common::arp_nd::try_write_nd_reply`.
///
/// `#[inline(always)]`: the `tc_guest_tx` caller is stack-heavy (conntrack/nat/v6); keeping this
/// out-of-line makes it a separate BPF subprogram whose frame is summed with the caller's, blowing
/// the 512-byte BPF stack limit.
#[inline(always)]
pub fn nd_reply<P: Pkt>(pkt: &mut P, gateway_ipv6: [u8; 16], reply_mac: [u8; 6]) -> bool {
    // One dominating bound: the whole NS/NA frame must be present before any access.
    if pkt.read_array::<2>(ETH_LEN + IPV6_LEN + 32 - 2).is_none() {
        return false;
    }
    let ip = ETH_LEN;
    let icmp = ETH_LEN + IPV6_LEN;

    let ethertype = match pkt.read_u16_be(12) {
        Some(e) => e,
        None => return false,
    };
    if ethertype != ETH_P_IPV6 {
        return false;
    }
    if pkt.read_u8(ip + 6) != Some(IPPROTO_ICMPV6) {
        return false;
    }
    if pkt.read_u8(icmp) != Some(ND_NS) {
        return false;
    }
    let target = match pkt.read_array::<16>(icmp + 8) {
        Some(t) => t,
        None => return false,
    };
    if target != gateway_ipv6 {
        return false;
    }
    let req_mac = match pkt.read_array::<6>(6) {
        Some(m) => m,
        None => return false,
    };
    let req_src = match pkt.read_array::<16>(ip + 8) {
        Some(s) => s,
        None => return false,
    };
    let gw_mac = reply_mac;

    // Ethernet: dst = original requester's src MAC, src = gateway MAC.
    pkt.write_array::<6>(0, &req_mac);
    pkt.write_array::<6>(6, &gw_mac);
    // IPv6: src = gateway, dst = original requester's src; hop limit 255, payload length 32.
    pkt.write_array::<16>(ip + 8, &gateway_ipv6);
    pkt.write_array::<16>(ip + 24, &req_src);
    pkt.write_array::<1>(ip + 7, &[255]);
    pkt.write_array::<2>(ip + 4, &32u16.to_be_bytes());
    // ICMPv6 NA: type 136, code 0, checksum cleared (recomputed below), flags = solicited+override.
    pkt.write_array::<1>(icmp, &[ND_NA]);
    pkt.write_array::<1>(icmp + 1, &[0]);
    pkt.write_array::<2>(icmp + 2, &[0, 0]);
    pkt.write_array::<1>(icmp + 4, &[0x60]);
    pkt.write_array::<1>(icmp + 5, &[0]);
    pkt.write_array::<2>(icmp + 6, &[0, 0]);
    // target @ icmp+8 stays = gateway (== the solicited target). Option @ icmp+24: type=2 (target LL
    // addr), len=1 (8 bytes), gateway MAC.
    pkt.write_array::<1>(icmp + 24, &[2]);
    pkt.write_array::<1>(icmp + 25, &[1]);
    pkt.write_array::<6>(icmp + 26, &gw_mac);

    // ICMPv6 checksum over the pseudo-header (src+dst IPv6, upper-layer length 32, next-header 58)
    // plus the 32-byte NA message.
    let mut sum: u32 = 0;
    let mut k = 0;
    while k < 16 {
        if let Some(b) = pkt.read_array::<2>(ip + 8 + k) {
            sum += u16::from_be_bytes(b) as u32;
        }
        if let Some(b) = pkt.read_array::<2>(ip + 24 + k) {
            sum += u16::from_be_bytes(b) as u32;
        }
        k += 2;
    }
    sum += 32u32;
    sum += IPPROTO_ICMPV6 as u32;
    let cks = csum16(sum, pkt, icmp, 32);
    pkt.write_array::<2>(icmp + 2, &cks.to_be_bytes());
    true
}

/// If `pkt` is an ICMPv6 Router Solicitation (type 133), rewrite it in place into a solicited
/// Router Advertisement (type 134) advertising `gateway_ipv6` as a default router at `reply_mac`,
/// carrying the **MTU option** (`mtu`) and a Source-Link-Layer-Address option. Returns true on
/// rewrite, false if the frame is not an RS.
///
/// This is the IPv6 equivalent of DHCPv4 option 26: DHCPv6 has no MTU option, so a self-configuring
/// IPv6 guest/VM learns its link MTU (and its default router) only from an RA. The RA is a **Managed**
/// RA — the M-flag is set and NO SLAAC prefix is advertised, so addressing stays with our DHCPv6
/// responder / control-plane IPAM (a SLAAC prefix would let the guest pick an address we didn't
/// assign). Solicited-unicast back to the requester (mirrors `nd_reply`); a Router Solicitation from
/// the unspecified source (`::`, a host that hasn't configured a link-local yet) is a rare edge that
/// gets a unicast RA the guest ignores — it re-solicits once it has a link-local.
///
/// The RA (86 bytes) is LARGER than the RS, so the caller MUST grow the buffer to [`RA_LEN`] before
/// calling this. Every access is a constant offset — verifier-friendly. `#[inline(always)]` for the
/// same BPF-stack reason as [`nd_reply`].
#[inline(always)]
pub fn ra_reply<P: Pkt>(pkt: &mut P, gateway_ipv6: [u8; 16], reply_mac: [u8; 6], mtu: u32) -> bool {
    // One dominating bound: the whole RA frame must be present (the caller grew the skb to RA_LEN).
    if pkt.read_array::<2>(RA_LEN - 2).is_none() {
        return false;
    }
    let ip = ETH_LEN;
    let icmp = ETH_LEN + IPV6_LEN;

    if pkt.read_u16_be(12) != Some(ETH_P_IPV6) {
        return false;
    }
    if pkt.read_u8(ip + 6) != Some(IPPROTO_ICMPV6) {
        return false;
    }
    if pkt.read_u8(icmp) != Some(ND_RS) {
        return false;
    }
    let req_mac = match pkt.read_array::<6>(6) {
        Some(m) => m,
        None => return false,
    };
    let req_src = match pkt.read_array::<16>(ip + 8) {
        Some(s) => s,
        None => return false,
    };

    // Ethernet: dst = requester's src MAC, src = gateway (router) MAC.
    pkt.write_array::<6>(0, &req_mac);
    pkt.write_array::<6>(6, &reply_mac);
    // IPv6: src = gateway (link-local), dst = requester; hop limit 255 (required for RA), payload
    // length 32, next-header ICMPv6.
    pkt.write_array::<16>(ip + 8, &gateway_ipv6);
    pkt.write_array::<16>(ip + 24, &req_src);
    pkt.write_array::<1>(ip + 6, &[IPPROTO_ICMPV6]);
    pkt.write_array::<1>(ip + 7, &[255]);
    pkt.write_array::<2>(ip + 4, &32u16.to_be_bytes());
    // ICMPv6 Router Advertisement: type 134, code 0, checksum cleared (recomputed below), cur-hop-limit
    // 64, flags = Managed (0x80), router lifetime 1800s (install us as default router), reachable +
    // retrans timers unspecified (0).
    pkt.write_array::<1>(icmp, &[ND_RA]);
    pkt.write_array::<1>(icmp + 1, &[0]);
    pkt.write_array::<2>(icmp + 2, &[0, 0]);
    pkt.write_array::<1>(icmp + 4, &[64]);
    pkt.write_array::<1>(icmp + 5, &[0x80]);
    pkt.write_array::<2>(icmp + 6, &1800u16.to_be_bytes());
    pkt.write_array::<4>(icmp + 8, &[0, 0, 0, 0]);
    pkt.write_array::<4>(icmp + 12, &[0, 0, 0, 0]);
    // Option: Source Link-Layer Address (type 1, len 1 = 8 bytes) = the router MAC.
    pkt.write_array::<1>(icmp + 16, &[1]);
    pkt.write_array::<1>(icmp + 17, &[1]);
    pkt.write_array::<6>(icmp + 18, &reply_mac);
    // Option: MTU (type 5, len 1 = 8 bytes): type, len, reserved(2), MTU(4).
    pkt.write_array::<1>(icmp + 24, &[5]);
    pkt.write_array::<1>(icmp + 25, &[1]);
    pkt.write_array::<2>(icmp + 26, &[0, 0]);
    pkt.write_array::<4>(icmp + 28, &mtu.to_be_bytes());

    // ICMPv6 checksum over the pseudo-header (src+dst IPv6, upper-layer length 32, next-header 58)
    // plus the 32-byte RA message.
    let mut sum: u32 = 0;
    let mut k = 0;
    while k < 16 {
        if let Some(b) = pkt.read_array::<2>(ip + 8 + k) {
            sum += u16::from_be_bytes(b) as u32;
        }
        if let Some(b) = pkt.read_array::<2>(ip + 24 + k) {
            sum += u16::from_be_bytes(b) as u32;
        }
        k += 2;
    }
    sum += 32u32;
    sum += IPPROTO_ICMPV6 as u32;
    let cks = csum16(sum, pkt, icmp, 32);
    pkt.write_array::<2>(icmp + 2, &cks.to_be_bytes());
    true
}

/// If `pkt` is an ARP request for `gateway_ipv4`, rewrite it in place into an ARP reply from
/// `reply_mac`/`gateway_ipv4` and return true. Else false (unchanged).
///
/// Faithful port of `flowplane_common::arp_nd::try_write_arp_reply`. `#[inline(always)]` for the
/// same BPF-stack reason as [`nd_reply`].
#[inline(always)]
pub fn arp_reply<P: Pkt>(pkt: &mut P, gateway_ipv4: [u8; 4], reply_mac: [u8; 6]) -> bool {
    // One dominating bound: the whole ARP frame must be present before any access.
    if pkt.read_array::<2>(ETH_LEN + ARP_LEN - 2).is_none() {
        return false;
    }
    let arp = ETH_LEN;

    let ethertype = match pkt.read_u16_be(12) {
        Some(e) => e,
        None => return false,
    };
    if ethertype != ETH_P_ARP {
        return false;
    }
    let opcode = match pkt.read_u16_be(arp + 6) {
        Some(o) => o,
        None => return false,
    };
    if opcode != 1 {
        return false;
    }
    let tpa = match pkt.read_array::<4>(arp + 24) {
        Some(t) => t,
        None => return false,
    };
    if tpa != gateway_ipv4 {
        return false;
    }
    let sender_mac = match pkt.read_array::<6>(arp + 8) {
        Some(m) => m,
        None => return false,
    };
    let spa = match pkt.read_array::<4>(arp + 14) {
        Some(s) => s,
        None => return false,
    };

    // Ethernet: dst = requester's MAC, src = gateway MAC.
    pkt.write_array::<6>(0, &sender_mac);
    pkt.write_array::<6>(6, &reply_mac);
    // ARP: op=reply(2); sender = gateway MAC/IP; target = original requester's MAC/IP.
    pkt.write_array::<2>(arp + 6, &2u16.to_be_bytes());
    pkt.write_array::<6>(arp + 8, &reply_mac);
    pkt.write_array::<4>(arp + 14, &gateway_ipv4);
    pkt.write_array::<6>(arp + 18, &sender_mac);
    pkt.write_array::<4>(arp + 24, &spa);
    true
}
