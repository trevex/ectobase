use flowplane_common::{NeighborNatEntry, NB_MAX_ENTRIES};

use crate::maps::{NEIGHBOR_NAT, NEIGHBOR_NAT_COUNT};

// The egress network-SNAT rewriter now lives in `flowplane_core::nat::snat_egress` — the SINGLE
// source shared by the eBPF `guest_tx` path (called from `egress::forward_decision_v4` over a
// `RawPkt`/`GlobalMaps` seam), the native `SimNode::guest_tx`, and the `BPF_PROG_TEST_RUN` byte-parity
// anchor. The former eBPF-local `nat_snat_egress` copy was deleted so there is exactly one impl.

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
