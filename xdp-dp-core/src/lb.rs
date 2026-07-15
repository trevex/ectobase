use crate::maps::Maps;
use crate::parse::{hash5, l4_ports};
use crate::pkt::Pkt;
use xdp_dp_common::{LbKey, MaglevKey};

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
