use aya_ebpf::programs::XdpContext;
use xdp_dp_common::{LbKey, MaglevKey};

use crate::maps::{LB, MAGLEV};
use crate::parse::{hash5, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};

/// If the inner IPv4 dst+port is an LB service, Maglev-select a backend and return its underlay
/// /128. No DNAT, no conntrack — the backend VF owns the LB IP (anycast) and replies from it.
#[inline(always)]
pub fn lb_select_forward(ctx: &XdpContext, ip_off: usize, vni: u32) -> Option<[u8; 16]> {
    xdp_dp_core::lb::lb_select_forward(
        &crate::coreimpl::CtxPkt { ctx },
        &crate::coreimpl::GlobalMaps,
        ip_off,
        vni,
    )
}

/// ICMP error relay: the outer IPv4 at `ip_off` carries an ICMP error (type 3/11/12) whose
/// embedded inner header describes the ORIGINAL flow destined to an LB VIP. We extract the
/// embedded inner src (= LB IP), embedded inner L4 src port (= LB service port), and select a
/// backend via Maglev. Returns the backend underlay on success.
///
/// Packet layout at `ip_off`:
///   [outer IPv4 (20)] [ICMP error header (8)] [inner IPv4 (20)] [inner TCP/UDP (4+)]
///
/// IHL==5 is required for both outer and inner IPv4 to keep offsets constant.
#[inline(always)]
pub fn lb_select_forward_icmp_error(ctx: &XdpContext, ip_off: usize, vni: u32) -> Option<[u8; 16]> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let p = data as *const u8;

    // Outer IPv4: require IHL==5, proto==ICMP.
    if data + ip_off + 20 > data_end {
        return None;
    }
    if unsafe { *p.add(ip_off) } & 0x0f != 5 {
        return None;
    }
    if unsafe { *p.add(ip_off + 9) } != IPPROTO_ICMP {
        return None;
    }
    // ICMP error: type must be 3 (Destination Unreachable), 11 (Time Exceeded), or 12 (Param Prob).
    let icmp_off = ip_off + 20;
    if data + icmp_off + 8 > data_end {
        return None;
    }
    let icmp_type = unsafe { *p.add(icmp_off) };
    if icmp_type != 3 && icmp_type != 11 && icmp_type != 12 {
        return None;
    }
    // Embedded inner IPv4 starts at icmp_off + 8. Require IHL==5.
    let inner_ip_off = icmp_off + 8;
    if data + inner_ip_off + 20 > data_end {
        return None;
    }
    if unsafe { *p.add(inner_ip_off) } & 0x0f != 5 {
        return None;
    }
    let inner_proto = unsafe { *p.add(inner_ip_off + 9) };
    // Only relay TCP/UDP ICMP errors (matching dpservice behaviour).
    if inner_proto != IPPROTO_TCP && inner_proto != IPPROTO_UDP {
        return None;
    }
    // The embedded inner packet was the ORIGINAL flow: src=lb_ip, dst=public_ip.
    // We use inner_src (= lb_ip) for the LB lookup key.
    let inner_src =
        unsafe { core::ptr::read_unaligned(p.add(inner_ip_off + 12) as *const [u8; 4]) };
    let inner_dst =
        unsafe { core::ptr::read_unaligned(p.add(inner_ip_off + 16) as *const [u8; 4]) };
    // Inner L4: sport is the LB service port.
    let inner_l4_off = inner_ip_off + 20;
    if data + inner_l4_off + 4 > data_end {
        return None;
    }
    let inner_sport =
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(inner_l4_off) as *const u16) });
    let inner_dport =
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(inner_l4_off + 2) as *const u16) });
    // LB lookup key: dst=inner_src (lb_ip), port=inner_sport (lb port), proto=inner_proto.
    let lb = unsafe {
        LB.get(&LbKey {
            vni,
            ipv4: inner_src,
            port: inner_sport,
            proto: inner_proto,
            _pad: 0,
        })
    }?;
    if lb.size == 0 {
        return None;
    }
    // Hash with swapped 5-tuple (from the ICMP error perspective: src=public_ip, dst=lb_ip).
    let slot = hash5(
        &inner_dst,
        &inner_src,
        inner_dport,
        inner_sport,
        inner_proto,
    ) % lb.size;
    let backend = unsafe {
        MAGLEV.get(&MaglevKey {
            table_id: lb.table_id,
            slot,
        })
    }?;
    Some(*backend)
}

/// If the inner IPv6 dst (last 4 bytes) matches an LB service, Maglev-select a backend and return
/// its underlay /128. Used for IPv6-in-IPv6 uplink relay (outer next-header 41).
/// `ip_off` points to the inner IPv6 header (= ETH_LEN + outer_IPV6_LEN).
#[inline(always)]
pub fn lb_select_forward_v6(ctx: &XdpContext, ip_off: usize, vni: u32) -> Option<[u8; 16]> {
    xdp_dp_core::lb::lb_select_forward_v6(
        &crate::coreimpl::CtxPkt { ctx },
        &crate::coreimpl::GlobalMaps,
        ip_off,
        vni,
    )
}
