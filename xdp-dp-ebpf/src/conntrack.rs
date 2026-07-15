use aya_ebpf::helpers::bpf_ktime_get_ns;
use xdp_dp_common::{CtEntry, CtKey, CT_REWRITE_SRC};

// The pure TCP-state advance is single-sourced in `xdp-dp-core`; re-export so `ct_touch` below keeps
// using `crate::conntrack::tcp_advance`. (`invert_key` is also in core, used there by ct_create_default.)
pub use xdp_dp_core::conntrack::tcp_advance;

use crate::coreimpl::{GlobalMaps, RawPkt};
use crate::csum::{csum_replace2, csum_replace4};
use crate::parse::l4_ports;

/// Current kernel monotonic time (ns).
#[inline(always)]
pub fn now() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

/// Build the VNI-keyed 5-tuple key for the packet at `ip_off` (host-order ports; ICMP id in both ports).
#[inline(always)]
pub fn ct_key(data: usize, data_end: usize, ip_off: usize, vni: u32) -> Option<CtKey> {
    let p = data as *const u8;
    if data + ip_off + 20 > data_end {
        return None;
    }
    let src = unsafe { core::ptr::read_unaligned(p.add(ip_off + 12) as *const [u8; 4]) };
    let dst = unsafe { core::ptr::read_unaligned(p.add(ip_off + 16) as *const [u8; 4]) };
    let (proto, sport, dport) = l4_ports(data, data_end, ip_off)?;
    Some(CtKey {
        vni,
        src_ip: src,
        dst_ip: dst,
        src_port: sport,
        dst_port: dport,
        proto,
        _pad: [0; 3],
    })
}

/// Apply a conntrack entry's translation to the packet at `ip_off`.
///
/// Rewrites the src address (CT_REWRITE_SRC) or dst address (otherwise) to `xlate_ip` and
/// updates the corresponding L4 port / ICMP id to `xlate_port` (when non-zero), fixing IP and
/// L4/ICMP checksums.
///
/// Only handles packets with a standard 20-byte IPv4 header (IHL == 5 / no options), which
/// covers all conntrack-tracked flows in this datapath (options are dropped at ingress).
///
/// All reads happen before any writes so the verifier's pkt-range tracking is not invalidated
/// mid-function. All L4 offsets are constants (ip_off + 20 = ETH_LEN + 20 = 34 is fixed), so
/// the verifier can check every access against known bounds without variable-offset pkt pointers.
#[inline(always)]
pub fn ct_apply(data: usize, data_end: usize, ip_off: usize, e: &CtEntry) {
    // DEFAULT (flag-less) entries carry no translation — never rewrite, or we'd null the address.
    if e.flags & (xdp_dp_common::CT_REWRITE_SRC | xdp_dp_common::CT_REWRITE_DST) == 0 {
        return;
    }
    // data/data_end are passed by the caller after any preceding helper calls so the verifier's
    // pkt-range tracking is already re-established at the call site.
    let p = data as *mut u8;

    // Only handle standard 20-byte IP headers (IHL == 5).
    // This covers all conntrack-tracked flows; packets with options were dropped at ingress.
    if data + ip_off + 20 > data_end {
        return;
    }
    let ihl_byte = unsafe { *p.add(ip_off) };
    if ihl_byte & 0x0f != 5 {
        return;
    }
    // From here: l4 = ip_off + 20 is a constant (no variable-offset pkt access).
    let l4 = ip_off + 20;

    let proto = unsafe { *p.add(ip_off + 9) };
    let rewrite_src = e.flags & CT_REWRITE_SRC != 0;
    let addr_off = ip_off + if rewrite_src { 12 } else { 16 };

    // --- Phase 1: read all packet fields before any write ---
    let old_addr = unsafe { core::ptr::read_unaligned(p.add(addr_off) as *const [u8; 4]) };
    let new_addr = e.xlate_ip;
    let old_ip_csum =
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ip_off + 10) as *const u16) });

    // Bounds checks at fixed offsets: all l4+N are compile-time constants.
    let tcp_ok = proto == 6 && data + l4 + 18 <= data_end;
    let udp_ok = proto == 17 && data + l4 + 8 <= data_end;
    let icmp_ok = proto == 1 && data + l4 + 8 <= data_end;

    let tcp_csum = if tcp_ok {
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 16) as *const u16) })
    } else {
        0
    };
    let udp_csum = if udp_ok {
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 6) as *const u16) })
    } else {
        0
    };
    let icmp_csum = if icmp_ok {
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 2) as *const u16) })
    } else {
        0
    };
    let icmp_id = if icmp_ok {
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 4) as *const u16) })
    } else {
        0
    };

    // Port offsets: src port at l4+0, dst port at l4+2. All constants.
    let src_port_off = l4;
    let dst_port_off = l4 + 2;
    let port_off = if rewrite_src {
        src_port_off
    } else {
        dst_port_off
    };

    let old_port = if (tcp_ok || udp_ok) && e.xlate_port != 0 {
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(port_off) as *const u16) })
    } else {
        0
    };

    // --- Phase 2: compute new checksums (pure arithmetic, no packet access) ---
    let new_ip_csum = csum_replace4(old_ip_csum, &old_addr, &new_addr);

    let new_tcp_csum = if tcp_ok {
        let c1 = csum_replace4(tcp_csum, &old_addr, &new_addr);
        if e.xlate_port != 0 {
            csum_replace2(c1, old_port, e.xlate_port)
        } else {
            c1
        }
    } else {
        0
    };

    let new_udp_csum = if udp_ok && udp_csum != 0 {
        let c1 = csum_replace4(udp_csum, &old_addr, &new_addr);
        if e.xlate_port != 0 {
            csum_replace2(c1, old_port, e.xlate_port)
        } else {
            c1
        }
    } else {
        0
    };

    let new_icmp_csum = if icmp_ok && e.xlate_port != 0 {
        csum_replace2(icmp_csum, icmp_id, e.xlate_port)
    } else {
        0
    };

    // --- Phase 3: write all modified fields ---
    unsafe {
        // IP address + checksum
        core::ptr::write_unaligned(p.add(addr_off) as *mut [u8; 4], new_addr);
        core::ptr::write_unaligned(p.add(ip_off + 10) as *mut u16, new_ip_csum.to_be());

        if tcp_ok {
            core::ptr::write_unaligned(p.add(l4 + 16) as *mut u16, new_tcp_csum.to_be());
            if e.xlate_port != 0 {
                core::ptr::write_unaligned(p.add(port_off) as *mut u16, e.xlate_port.to_be());
            }
        } else if udp_ok {
            if udp_csum != 0 {
                core::ptr::write_unaligned(p.add(l4 + 6) as *mut u16, new_udp_csum.to_be());
            }
            if e.xlate_port != 0 {
                core::ptr::write_unaligned(p.add(port_off) as *mut u16, e.xlate_port.to_be());
            }
        } else if icmp_ok && e.xlate_port != 0 {
            core::ptr::write_unaligned(p.add(l4 + 2) as *mut u16, new_icmp_csum.to_be());
            core::ptr::write_unaligned(p.add(l4 + 4) as *mut u16, e.xlate_port.to_be());
        }
    }
}

/// Refresh last_seen (and TCP state for TCP) on a matched entry, writing it back.
#[inline(always)]
pub fn ct_touch(data: usize, data_end: usize, ip_off: usize, key: &CtKey, e: &mut CtEntry) {
    e.last_seen = now();
    if let Some(fl) = crate::parse::tcp_flags(data, data_end, ip_off) {
        e.tcp_state = tcp_advance(e.tcp_state, fl);
    }
    let _ = crate::maps::CONNTRACK.insert(key, e, 0);
}

/// Insert a no-translation DEFAULT conntrack entry for a flow on conntrack-miss, so every flow is
/// tracked (firewall + aging see it). Delegates to the single-sourced core `ct_create_default` so
/// the default entry (fields + reverse-key pre-seed) lives in one place. `key` is already the
/// forward key derived from the same packet at `ip_off`; core re-derives it identically.
#[inline(always)]
pub fn ct_ensure_default(data: usize, data_end: usize, ip_off: usize, key: &CtKey) {
    let pkt = RawPkt::new(data, data_end);
    let mut maps = GlobalMaps;
    xdp_dp_core::conntrack::ct_create_default(&pkt, &mut maps, ip_off, key.vni, now());
}
