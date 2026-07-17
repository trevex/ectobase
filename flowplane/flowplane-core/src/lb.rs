use crate::maps::Maps;
use crate::parse::{hash5, l4_ports};
use crate::pkt::Pkt;
use flowplane_common::{LbKey, MaglevKey};

/// Maglev backend select for an LB service. Faithful port of eBPF `lb::lb_select_forward` (primary
/// TCP/UDP/ICMP path). Reads the inner IPv4 at `ip_off`; returns the backend underlay /128, or None
/// if `(vni, dst, port, proto)` is not an LB service (or the table is empty).
#[inline(always)]
pub fn lb_select_forward<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &M,
    ip_off: usize,
    vni: u32,
) -> Option<[u8; 16]> {
    let dst = pkt.read_array::<4>(ip_off + 16)?;
    let src = pkt.read_array::<4>(ip_off + 12)?;
    let (proto, sport, dport) = l4_ports(pkt, ip_off)?;
    let lookup_port = if proto == 1 { 0 } else { dport };
    let lb = maps.lb_get(&LbKey {
        vni,
        ipv4: dst,
        port: lookup_port,
        proto,
        _pad: 0,
    })?;
    if lb.size == 0 {
        return None;
    }
    let slot = hash5(&src, &dst, sport, dport, proto) % lb.size;
    maps.maglev_get(&MaglevKey {
        table_id: lb.table_id,
        slot,
    })
}

/// Maglev backend select for an IPv6 LB service. Faithful port of eBPF `lb::lb_select_forward_v6`
/// (the IPv6-in-IPv6 uplink relay path). Reads the inner IPv6 at `ip_off`; the LB key uses the
/// last 4 bytes of the v6 dst (matching the control-plane `last4`). Returns the backend underlay
/// /128, or None if `(vni, dst4, port, proto)` is not an LB service (or the table is empty).
#[inline(always)]
pub fn lb_select_forward_v6<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &M,
    ip_off: usize,
    vni: u32,
) -> Option<[u8; 16]> {
    let nexthdr = pkt.read_u8(ip_off + 6)?;
    // Only relay TCP/UDP (matching dpservice behaviour).
    if nexthdr != 6 && nexthdr != 17 {
        return None;
    }
    let dst6 = pkt.read_array::<16>(ip_off + 24)?;
    let src6 = pkt.read_array::<16>(ip_off + 8)?;
    // LB key uses the last 4 bytes of the IPv6 address (matching the control-plane `last4`).
    let dst4: [u8; 4] = [dst6[12], dst6[13], dst6[14], dst6[15]];
    let src4: [u8; 4] = [src6[12], src6[13], src6[14], src6[15]];
    // L4 ports at ip_off + 40 (right after inner IPv6 header; no extension headers assumed).
    let sport = u16::from_be_bytes(pkt.read_array::<2>(ip_off + 40)?);
    let dport = u16::from_be_bytes(pkt.read_array::<2>(ip_off + 42)?);
    let lb = maps.lb_get(&LbKey {
        vni,
        ipv4: dst4,
        port: dport,
        proto: nexthdr,
        _pad: 0,
    })?;
    if lb.size == 0 {
        return None;
    }
    let slot = hash5(&src4, &dst4, sport, dport, nexthdr) % lb.size;
    maps.maglev_get(&MaglevKey {
        table_id: lb.table_id,
        slot,
    })
}
