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

/// ICMP-error LB relay select (v4). If the outer IPv4 at `ip_off` is an ICMP error (type 3/11/12)
/// whose embedded inner IPv4 (at `outer_l4 + 8`) is a TCP/UDP flow SOURCED from an LB VIP, Maglev-
/// select the backend that owns that flow and return its underlay /128; else None. The LB key uses
/// the embedded SRC (= the VIP) + embedded SPORT (= the service port); the Maglev slot is hashed over
/// the SWAPPED embedded tuple, reconstructing the original client->VIP forward-flow hash so the error
/// lands on the same backend. Faithful port of the pre-P2 eBPF `lb::lb_select_forward_icmp_error`
/// (recovered from 7a9a962). IHL==5 required for both outer + embedded IPv4 to keep offsets constant.
///
/// KNOWN LIMITATION (deferred to the N/S-LB edge spec): the relayed error reuses the shared LB
/// delivery path, so `process_uplink`'s ingress firewall evaluates it on its OUTER ICMP tuple
/// (src = the erroring router, proto = ICMP). A typical backend policy ("allow TCP/443 from any")
/// does not match ICMP, so the relayed error is firewall-dropped in production — a latent PMTUD gap,
/// consistent with how all DSR-LB traffic is firewall-gated today. The fix (exempt relayed ICMP
/// errors, or evaluate against the embedded flow) belongs to the N/S-LB edge spec.
///
/// `#[inline(always)]`: it reads the packet, and out-of-lining a packet-reading subprogram loses the
/// eBPF verifier's pkt-pointer range tracking across the call boundary ("R3 pointer arithmetic on
/// pkt_end prohibited"). The frame budget it adds to `process_uplink` is instead reclaimed by
/// out-of-lining the packet-FREE `resolve_uplink_target` (see there).
#[inline(always)]
pub fn lb_select_forward_icmp_error<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &M,
    ip_off: usize,
    vni: u32,
) -> Option<[u8; 16]> {
    // Outer IPv4: IHL==5, proto==ICMP(1).
    if pkt.read_u8(ip_off)? & 0x0f != 5 {
        return None;
    }
    if pkt.read_u8(ip_off + 9)? != 1 {
        return None;
    }
    // ICMP error type at outer_l4[0]; outer_l4 = ip_off + 20 (IHL==5).
    let icmp_off = ip_off + 20;
    let icmp_type = pkt.read_u8(icmp_off)?;
    if icmp_type != 3 && icmp_type != 11 && icmp_type != 12 {
        return None;
    }
    // Embedded inner IPv4 at icmp_off + 8, IHL==5.
    let inner_ip_off = icmp_off + 8;
    if pkt.read_u8(inner_ip_off)? & 0x0f != 5 {
        return None;
    }
    let inner_proto = pkt.read_u8(inner_ip_off + 9)?;
    // Only relay TCP/UDP (matching dpservice behaviour).
    if inner_proto != 6 && inner_proto != 17 {
        return None;
    }
    let inner_src = pkt.read_array::<4>(inner_ip_off + 12)?; // = the VIP
    let inner_dst = pkt.read_array::<4>(inner_ip_off + 16)?; // = the client
    let inner_l4_off = inner_ip_off + 20;
    let inner_sport = u16::from_be_bytes(pkt.read_array::<2>(inner_l4_off)?); // = service port
    let inner_dport = u16::from_be_bytes(pkt.read_array::<2>(inner_l4_off + 2)?);
    // LB key: dst = inner_src (VIP), port = inner_sport (service port), proto = inner_proto.
    let lb = maps.lb_get(&LbKey {
        vni,
        ipv4: inner_src,
        port: inner_sport,
        proto: inner_proto,
        _pad: 0,
    })?;
    if lb.size == 0 {
        return None;
    }
    // Swapped 5-tuple (client->VIP perspective) reconstructs the original forward-flow hash.
    let slot = hash5(
        &inner_dst,
        &inner_src,
        inner_dport,
        inner_sport,
        inner_proto,
    ) % lb.size;
    maps.maglev_get(&MaglevKey {
        table_id: lb.table_id,
        slot,
    })
}
