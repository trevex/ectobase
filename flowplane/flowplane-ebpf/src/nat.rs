use flowplane_common::{CtEntry, CtKey, NatKey, NeighborNatEntry, NB_MAX_ENTRIES};

use crate::csum::{csum_replace2, csum_replace4};
use crate::maps::{NAT, NEIGHBOR_NAT, NEIGHBOR_NAT_COUNT};
use crate::parse::{hash5, l4_ports};

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
pub const PROBE_LIMIT: u16 = 64;

/// Egress network SNAT. If `is_external` and the guest (vni, src) has a NAT config, allocate a
/// source port (reusing the forward-conntrack port if the flow is already tracked), rewrite
/// src IP -> nat_ip and the L4 src port / ICMP id -> nat_port (+checksums), and pin forward +
/// reverse conntrack. Returns true if the packet was NAT'd.
#[inline(always)]
pub fn nat_snat_egress(
    data: usize,
    data_end: usize,
    ip_off: usize,
    vni: u32,
    is_external: bool,
) -> bool {
    if !is_external {
        return false;
    }
    if data + ip_off + 20 > data_end {
        return false;
    }
    let p = data as *mut u8;
    let src = unsafe { core::ptr::read_unaligned(p.add(ip_off + 12) as *const [u8; 4]) };
    let dst = unsafe { core::ptr::read_unaligned(p.add(ip_off + 16) as *const [u8; 4]) };
    let nat = match unsafe { NAT.get(&NatKey { vni, ipv4: src }) } {
        Some(v) => *v,
        None => return false,
    };
    let range = nat.port_max.wrapping_sub(nat.port_min);
    if range == 0 {
        return false;
    }
    let (proto, sport, dport) = match l4_ports(data, data_end, ip_off) {
        Some(v) => v,
        None => return false,
    };

    // Forward conntrack: reuse the allocated port for an already-tracked flow.
    let fwd_key = CtKey {
        vni,
        src_ip: src,
        dst_ip: dst,
        src_port: sport,
        dst_port: dport,
        proto,
        _pad: [0; 3],
    };
    let nat_port = match unsafe { crate::maps::CONNTRACK.get(&fwd_key) } {
        Some(v) if v.flags & flowplane_common::CT_F_SRC_NAT != 0 => v.xlate_port,
        _ => {
            // Allocate: hash the flow to a start slot, linear-probe for a free reverse key.
            let start = (hash5(&src, &dst, sport, dport, proto) % range as u32) as u16;
            let mut chosen = nat.port_min.wrapping_add(start);
            let mut i: u16 = 0;
            while i < PROBE_LIMIT {
                let cand = nat.port_min.wrapping_add((start.wrapping_add(i)) % range);
                // Peer-independent NAT return key: (vni, 0, nat_ip, 0, nat_port). The external peer
                // (src ip) and the external port are NOT part of the key, so an allocated nat_port
                // is GLOBALLY unique per nat_ip (dpservice model) — two flows to different
                // destinations cannot share a port. Ingress reverses returns by the same zeroed key.
                let rev_key = CtKey {
                    vni,
                    src_ip: [0; 4],
                    dst_ip: nat.nat_ipv4,
                    src_port: 0,
                    dst_port: cand,
                    proto,
                    _pad: [0; 3],
                };
                if unsafe { crate::maps::CONNTRACK.get(&rev_key) }.is_none() {
                    chosen = cand;
                    let _ = crate::maps::CONNTRACK.insert(
                        &rev_key,
                        &CtEntry {
                            last_seen: crate::conntrack::now(),
                            xlate_ip: src,
                            xlate_port: sport,
                            flags: flowplane_common::CT_REWRITE_DST
                                | flowplane_common::CT_F_SRC_NAT,
                            tcp_state: 0,
                            fwall_action: 0,
                            _pad: [0; 7],
                        },
                        0,
                    );
                    break;
                }
                i += 1;
            }
            let _ = crate::maps::CONNTRACK.insert(
                &fwd_key,
                &CtEntry {
                    last_seen: crate::conntrack::now(),
                    xlate_ip: nat.nat_ipv4,
                    xlate_port: chosen,
                    flags: flowplane_common::CT_REWRITE_SRC | flowplane_common::CT_F_SRC_NAT,
                    tcp_state: 0,
                    fwall_action: 0,
                    _pad: [0; 7],
                },
                0,
            );
            chosen
        }
    };

    // Rewrite src IP guest -> nat_ip (+ IP checksum), then the L4 src port / ICMP id -> nat_port.
    let ihl = (unsafe { *p.add(ip_off) } & 0x0f) as usize * 4;
    unsafe {
        core::ptr::write_unaligned(p.add(ip_off + 12) as *mut [u8; 4], nat.nat_ipv4);
        let ipc = u16::from_be(core::ptr::read_unaligned(p.add(ip_off + 10) as *const u16));
        core::ptr::write_unaligned(
            p.add(ip_off + 10) as *mut u16,
            csum_replace4(ipc, &src, &nat.nat_ipv4).to_be(),
        );
        let l4 = ip_off + ihl;
        if proto == IPPROTO_TCP && data + l4 + 18 <= data_end {
            let c0 = u16::from_be(core::ptr::read_unaligned(p.add(l4 + 16) as *const u16));
            let c1 = csum_replace4(c0, &src, &nat.nat_ipv4);
            let c2 = csum_replace2(c1, sport, nat_port);
            core::ptr::write_unaligned(p.add(l4 + 16) as *mut u16, c2.to_be());
            core::ptr::write_unaligned(p.add(l4) as *mut u16, nat_port.to_be());
        } else if proto == IPPROTO_UDP && data + l4 + 8 <= data_end {
            let c0 = u16::from_be(core::ptr::read_unaligned(p.add(l4 + 6) as *const u16));
            if c0 != 0 {
                let c1 = csum_replace4(c0, &src, &nat.nat_ipv4);
                let c2 = csum_replace2(c1, sport, nat_port);
                core::ptr::write_unaligned(p.add(l4 + 6) as *mut u16, c2.to_be());
            }
            core::ptr::write_unaligned(p.add(l4) as *mut u16, nat_port.to_be());
        } else if proto == IPPROTO_ICMP && data + l4 + 8 <= data_end {
            // ICMP checksum at l4+2, identifier at l4+4. Address change does not affect it.
            let c0 = u16::from_be(core::ptr::read_unaligned(p.add(l4 + 2) as *const u16));
            let c1 = csum_replace2(c0, sport, nat_port);
            core::ptr::write_unaligned(p.add(l4 + 2) as *mut u16, c1.to_be());
            core::ptr::write_unaligned(p.add(l4 + 4) as *mut u16, nat_port.to_be());
        }
    }
    true
}

/// If `(vni, dst, dport)` matches a neighbor-NAT entry, return the owning node's underlay /128.
#[inline(always)]
pub fn neighbor_nat_lookup(vni: u32, dst: [u8; 4], dport: u16) -> Option<[u8; 16]> {
    let count = match NEIGHBOR_NAT_COUNT.get(0) {
        Some(c) => *c,
        None => return None,
    };
    let mut idx: u32 = 0;
    while idx < NB_MAX_ENTRIES {
        if idx >= count {
            break;
        }
        if let Some(e) = unsafe { NEIGHBOR_NAT.get(&idx) } {
            let e: NeighborNatEntry = *e;
            if e.enabled != 0
                && e.vni == vni
                && e.nat_ip == dst
                && dport >= e.port_min
                && dport < e.port_max
            {
                return Some(e.underlay);
            }
        }
        idx += 1;
    }
    None
}

/// VNI-agnostic neighbor-NAT lookup for the WAN edge return path: a plain IPv4 return packet
/// arriving from the internet carries no overlay VNI, so match on `(nat_ip, dport)` alone and
/// return BOTH the owning node's underlay /128 AND the owner's VNI. The edge encaps the return
/// toward `underlay` with that VNI so the owner's reverse-conntrack key `(vni,0,nat_ip,0,nat_port)`
/// matches. (dpservice reaches the same end via `ALL_VNI=0` entries.)
#[inline(always)]
pub fn neighbor_nat_lookup_any(dst: [u8; 4], dport: u16) -> Option<([u8; 16], u32)> {
    let count = match NEIGHBOR_NAT_COUNT.get(0) {
        Some(c) => *c,
        None => return None,
    };
    let mut idx: u32 = 0;
    while idx < NB_MAX_ENTRIES {
        if idx >= count {
            break;
        }
        if let Some(e) = unsafe { NEIGHBOR_NAT.get(&idx) } {
            let e: NeighborNatEntry = *e;
            if e.enabled != 0 && e.nat_ip == dst && dport >= e.port_min && dport < e.port_max {
                return Some((e.underlay, e.vni));
            }
        }
        idx += 1;
    }
    None
}
