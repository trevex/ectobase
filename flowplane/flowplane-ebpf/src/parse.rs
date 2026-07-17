// L2/L3 protocol constants single-sourced in `flowplane_common::proto`; re-exported so existing
// `crate::parse::{ETH_LEN, IPV6_LEN, ETH_P_IP, ETH_P_IPV6}` import paths keep resolving.
pub use flowplane_common::proto::{ETH_LEN, ETH_P_IP, ETH_P_IPV6, IPV6_LEN};
pub use flowplane_core::parse::hash5;
pub const IPPROTO_IPIP: u8 = 4; // IPv4 encapsulated in IPv6 (outer next-header)
pub const IPPROTO_IPV6: u8 = 41; // IPv6 encapsulated in IPv6 (outer next-header)
pub const IPPROTO_ICMPV6: u8 = 58; // ICMPv6

/// # Safety
/// `dst` must point to at least 6 writable, in-bounds bytes (the caller is responsible for the
/// XDP/tc `data_end` bounds check before calling).
#[inline(always)]
pub unsafe fn write6(dst: *mut u8, src: &[u8; 6]) {
    let mut i = 0;
    while i < 6 {
        *dst.add(i) = src[i];
        i += 1;
    }
}

/// # Safety
/// `dst` must point to at least 16 writable, in-bounds bytes (the caller is responsible for the
/// XDP/tc `data_end` bounds check before calling).
#[inline(always)]
pub unsafe fn write16(dst: *mut u8, src: &[u8; 16]) {
    let mut i = 0;
    while i < 16 {
        *dst.add(i) = src[i];
        i += 1;
    }
}

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Read the L4 "ports" for a parsed IPv4 packet at `ip_off`. For TCP/UDP returns (proto,sport,dport)
/// with ports in host order; for ICMP returns (proto,id,id). Returns None if out of bounds /
/// unsupported. `data`/`data_end` are the current packet bounds.
#[inline(always)]
pub fn l4_ports(data: usize, data_end: usize, ip_off: usize) -> Option<(u8, u16, u16)> {
    let p = data as *const u8;
    if data + ip_off + 20 > data_end {
        return None;
    }
    let ihl = (unsafe { *p.add(ip_off) } & 0x0f) as usize * 4;
    let proto = unsafe { *p.add(ip_off + 9) };
    let l4 = ip_off + ihl;
    match proto {
        IPPROTO_TCP | IPPROTO_UDP => {
            if data + l4 + 4 > data_end {
                return None;
            }
            let sp = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4) as *const u16) });
            let dp =
                u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 2) as *const u16) });
            Some((proto, sp, dp))
        }
        IPPROTO_ICMP => {
            if data + l4 + 6 > data_end {
                return None;
            }
            let id =
                u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 4) as *const u16) });
            Some((proto, id, id))
        }
        _ => None,
    }
}

/// Read the TCP flags byte for an IPv4 packet at `ip_off`, or None if not TCP / out of bounds /
/// IP options present (IHL != 5). The TCP flags are at the standard offset 13 of the TCP header.
#[inline(always)]
pub fn tcp_flags(data: usize, data_end: usize, ip_off: usize) -> Option<u8> {
    let p = data as *const u8;
    if data + ip_off + 20 > data_end {
        return None;
    }
    if unsafe { *p.add(ip_off + 9) } != IPPROTO_TCP {
        return None;
    }
    // Constrain to no IP options so the L4 offset is a constant (BPF verifier friendliness).
    if unsafe { *p.add(ip_off) } & 0x0f != 5 {
        return None;
    }
    let l4 = ip_off + 20;
    if data + l4 + 14 > data_end {
        return None;
    }
    Some(unsafe { *p.add(l4 + 13) })
}
