use aya_ebpf::helpers::bpf_ktime_get_ns;
use flowplane_common::{CtEntry, CtKey, CtKey6};

// The pure TCP-state advance is single-sourced in `flowplane-core`; re-export so `ct_touch` below keeps
// using `crate::conntrack::tcp_advance`. (`invert_key` is also in core, used there by ct_create_default.)
pub use flowplane_core::conntrack::tcp_advance;

use crate::coreimpl::{GlobalMaps, RawPkt};
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

/// Apply a conntrack entry's translation to the packet at `ip_off` by delegating to the shared
/// `flowplane_core::conntrack::ct_apply` (the SAME code the native `SimNode` + the `BPF_PROG_TEST_RUN`
/// byte-parity anchor run). Rewrites the src address (`CT_REWRITE_SRC`) or dst address (otherwise) to
/// `xlate_ip` + the corresponding L4 port / ICMP id to `xlate_port` (when non-zero), fixing IP and
/// L4/ICMP checksums. Byte-identical to the former inline eBPF impl.
///
/// Wraps `[data, data_end)` in a fresh `RawPkt` so the core's `read_array`/`write_array` re-derive
/// the packet bounds on every access — the core uses the read-modify-write window idiom, keeping the
/// variable-nothing (IHL==5, so `l4 = ip_off + 20` is constant) accesses verifier-provable across the
/// bpf-to-bpf subprogram-call boundary. `data`/`data_end` are passed by the caller after any preceding
/// helper calls so the verifier's pkt-range tracking is already re-established at the call site.
#[inline(always)]
pub fn ct_apply(data: usize, data_end: usize, ip_off: usize, e: &CtEntry) {
    let mut pkt = RawPkt::new(data, data_end);
    flowplane_core::conntrack::ct_apply(&mut pkt, ip_off, e);
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

/// Read the v6 L4 "ports" for a parsed IPv6 packet at `ip_off` (fixed 40-byte header, no extension
/// headers — mirrors the fixed-offset v4 `parse::l4_ports`). For TCP/UDP returns (nexthdr,sport,dport)
/// in host order; for ICMPv6 returns (58,id,id). Returns None if out of bounds / unsupported.
#[inline(always)]
fn l4_ports6(data: usize, data_end: usize, ip_off: usize) -> Option<(u8, u16, u16)> {
    let p = data as *const u8;
    if data + ip_off + 40 > data_end {
        return None;
    }
    let nexthdr = unsafe { *p.add(ip_off + 6) };
    let l4 = ip_off + 40;
    match nexthdr {
        crate::parse::IPPROTO_TCP | crate::parse::IPPROTO_UDP => {
            if data + l4 + 4 > data_end {
                return None;
            }
            let sp = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4) as *const u16) });
            let dp =
                u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 2) as *const u16) });
            Some((nexthdr, sp, dp))
        }
        crate::parse::IPPROTO_ICMPV6 => {
            if data + l4 + 6 > data_end {
                return None;
            }
            let id =
                u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 4) as *const u16) });
            Some((nexthdr, id, id))
        }
        _ => None,
    }
}

/// Build the VNI-keyed IPv6 5-tuple key for the packet at `ip_off` (host-order ports; ICMPv6 id in
/// both ports). Firewall-only v6 mirror of [`ct_key`]: reads src @ `ip_off + 8` and dst @ `ip_off + 24`
/// from the fixed 40-byte IPv6 header. Falls back to `(next-header, 0, 0)` when `l4_ports6` yields
/// nothing (unrecognised next-header / truncated L4), so every v6 flow is still tracked.
#[inline(always)]
pub fn ct_key6(data: usize, data_end: usize, ip_off: usize, vni: u32) -> Option<CtKey6> {
    let p = data as *const u8;
    if data + ip_off + 40 > data_end {
        return None;
    }
    let src = unsafe { core::ptr::read_unaligned(p.add(ip_off + 8) as *const [u8; 16]) };
    let dst = unsafe { core::ptr::read_unaligned(p.add(ip_off + 24) as *const [u8; 16]) };
    let nexthdr = unsafe { *p.add(ip_off + 6) };
    let (proto, sport, dport) = l4_ports6(data, data_end, ip_off).unwrap_or((nexthdr, 0, 0));
    Some(CtKey6 {
        vni,
        src_ip: src,
        dst_ip: dst,
        src_port: sport,
        dst_port: dport,
        proto,
        _pad: [0; 3],
    })
}

/// Read the TCP flags byte for an IPv6 packet at `ip_off`, or None if the next header is not TCP /
/// out of bounds. v6 mirror of `parse::tcp_flags`: the IPv6 header is a fixed 40 bytes (no options in
/// the firewall path), so the L4 offset is the constant `ip_off + 40`; TCP flags are at offset 13.
#[inline(always)]
fn tcp_flags6(data: usize, data_end: usize, ip_off: usize) -> Option<u8> {
    let p = data as *const u8;
    if data + ip_off + 40 > data_end {
        return None;
    }
    if unsafe { *p.add(ip_off + 6) } != crate::parse::IPPROTO_TCP {
        return None;
    }
    let l4 = ip_off + 40;
    if data + l4 + 14 > data_end {
        return None;
    }
    Some(unsafe { *p.add(l4 + 13) })
}

/// Refresh last_seen (and TCP state for TCP) on a matched IPv6 entry, writing it back. v6 mirror of
/// [`ct_touch`].
#[inline(always)]
pub fn ct_touch6(data: usize, data_end: usize, ip_off: usize, key: &CtKey6, e: &mut CtEntry) {
    e.last_seen = now();
    if let Some(fl) = tcp_flags6(data, data_end, ip_off) {
        e.tcp_state = tcp_advance(e.tcp_state, fl);
    }
    let _ = crate::maps::CONNTRACK6.insert(key, e, 0);
}

/// Insert a no-translation DEFAULT conntrack entry for a flow on conntrack-miss, so every flow is
/// tracked (firewall + aging see it). Delegates to the single-sourced core `ct_create_default` so
/// the default entry (fields + reverse-key pre-seed) lives in one place. `key` is already the
/// forward key derived from the same packet at `ip_off`; core re-derives it identically.
#[inline(always)]
pub fn ct_ensure_default(data: usize, data_end: usize, ip_off: usize, key: &CtKey) {
    let pkt = RawPkt::new(data, data_end);
    let mut maps = GlobalMaps;
    flowplane_core::conntrack::ct_create_default(&pkt, &mut maps, ip_off, key.vni, now());
}
