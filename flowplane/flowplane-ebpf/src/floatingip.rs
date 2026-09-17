use flowplane_common::FloatingIPKey;

use crate::csum::csum_replace4;
use crate::maps::FLOATING_IPS;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Egress SNAT: rewrite the inner IPv4 SOURCE if an LB address exists for it. `ip_off` = offset of the
/// IPv4 header from packet start. No-op if no LB address. Bounds are re-checked here.
#[inline(always)]
pub fn snat_egress(data: usize, data_end: usize, ip_off: usize, vni: u32) {
    rewrite_raw(data, data_end, ip_off, vni, true);
}

/// Egress DNAT: rewrite the inner IPv4 DESTINATION if an LB address maps to a guest IP. Used for
/// same-host LB address traffic where the sender's packet never reaches the ingress (uplink_rx) path.
#[inline(always)]
pub fn dnat_egress(data: usize, data_end: usize, ip_off: usize, vni: u32) {
    rewrite_raw(data, data_end, ip_off, vni, false);
}

// The ingress-side DNAT wrapper (LB address V->G rewrite on an inbound frame) now lives in
// `flowplane_core::datapath::process_uplink` (rebuilt as F2, 2026-09-05) — `uplink_rx` delegates to
// the core orchestrator, which DNATs V->G via `Maps::floating_ip_get` and delivers to G's tap. Only the
// egress SNAT/DNAT (`snat_egress`/`dnat_egress`) remain here (raw-pointer, same-host LB address traffic).

#[inline(always)]
fn rewrite_raw(data: usize, data_end: usize, ip_off: usize, vni: u32, is_src: bool) {
    if data + ip_off + 20 > data_end {
        return;
    }
    let p = data as *mut u8;
    let addr_off = ip_off + if is_src { 12 } else { 16 };
    let old = unsafe { core::ptr::read_unaligned(p.add(addr_off) as *const [u8; 4]) };
    let new = match unsafe { FLOATING_IPS.get(&FloatingIPKey { vni, ipv4: old }) } {
        Some(v) => *v,
        None => return,
    };
    let ihl = ((unsafe { *p.add(ip_off) }) & 0x0f) as usize * 4;
    let proto = unsafe { *p.add(ip_off + 9) };
    unsafe {
        core::ptr::write_unaligned(p.add(addr_off) as *mut [u8; 4], new);
        let ipchk = u16::from_be(core::ptr::read_unaligned(p.add(ip_off + 10) as *const u16));
        let ipchk2 = csum_replace4(ipchk, &old, &new);
        core::ptr::write_unaligned(p.add(ip_off + 10) as *mut u16, ipchk2.to_be());
        let l4 = ip_off + ihl;
        if proto == IPPROTO_TCP && data + l4 + 18 <= data_end {
            let c = u16::from_be(core::ptr::read_unaligned(p.add(l4 + 16) as *const u16));
            let c2 = csum_replace4(c, &old, &new);
            core::ptr::write_unaligned(p.add(l4 + 16) as *mut u16, c2.to_be());
        } else if proto == IPPROTO_UDP && data + l4 + 8 <= data_end {
            let c = u16::from_be(core::ptr::read_unaligned(p.add(l4 + 6) as *const u16));
            if c != 0 {
                let c2 = csum_replace4(c, &old, &new);
                core::ptr::write_unaligned(p.add(l4 + 6) as *mut u16, c2.to_be());
            }
        }
    }
}
