//! Conntrack key derivation + default-entry creation, ported over the `Pkt`/`Maps` traits so the
//! same logic runs in eBPF and natively. Faithful ports of the eBPF `conntrack::ct_key` /
//! `ct_ensure_default` (+ the pure `tcp_advance` / `invert_key` helpers they depend on).
//!
//! Time impurity: the eBPF default-create stamps `last_seen` from `bpf_ktime_get_ns()`, which has no
//! native equivalent. `ct_create_default` therefore takes `now: u64` as a parameter — the eBPF
//! wrapper passes `now()`, the sim passes 0.
//!
//! GC expiry: `timeout_ns` + `ct_is_expired` live here so the production GC loop and conformance
//! tests share a single implementation. Mirrors dpservice (30 s default, 24 h established-TCP).

use crate::maps::Maps;
use crate::parse::{l4_ports, l4_ports_v6, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};
use crate::pkt::Pkt;
use flowplane_common::csum::{csum_replace2, csum_replace4};
use flowplane_common::{
    CtEntry, CtKey, CT_F_DEFAULT, CT_REWRITE_DST, CT_REWRITE_SRC, TCP_ESTABLISHED, TCP_FINWAIT,
    TCP_NEW_SYN, TCP_NEW_SYNACK, TCP_RST_FIN,
};

/// Idle timeout for non-established flows (30 s), in nanoseconds. Mirrors dpservice.
pub const DEFAULT_TIMEOUT_NS: u64 = 30 * 1_000_000_000;

/// Idle timeout for TCP-ESTABLISHED flows (24 h), in nanoseconds. Mirrors dpservice.
pub const TCP_ESTABLISHED_TIMEOUT_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

/// Return the idle timeout (ns) for a conntrack entry: 24 h for ESTABLISHED TCP, 30 s otherwise.
#[inline(always)]
pub fn timeout_ns(e: &CtEntry) -> u64 {
    if e.tcp_state == TCP_ESTABLISHED {
        TCP_ESTABLISHED_TIMEOUT_NS
    } else {
        DEFAULT_TIMEOUT_NS
    }
}

/// Return `true` if the entry has been idle long enough at `now` (kernel-monotonic ns) to be
/// evicted: `now.saturating_sub(e.last_seen) > timeout_ns(e)`.
#[inline(always)]
pub fn ct_is_expired(e: &CtEntry, now: u64) -> bool {
    now.saturating_sub(e.last_seen) > timeout_ns(e)
}

/// Build the VNI-keyed 5-tuple key for the packet at `ip_off` (host-order ports; ICMP id in both
/// ports). Faithful port of the eBPF `conntrack::ct_key`.
#[inline(always)]
pub fn ct_key<P: Pkt>(pkt: &P, ip_off: usize, vni: u32) -> Option<CtKey> {
    // Faithful to the eBPF bound `data + ip_off + 20 > data_end`: read the src/dst addresses from
    // the standard 20-byte IPv4 header (options-free flows only).
    let src = pkt.read_array::<4>(ip_off + 12)?;
    let dst = pkt.read_array::<4>(ip_off + 16)?;
    // Fall back to `(protocol, 0, 0)` for an unrecognised L4 (GRE/ESP/etc.), mirroring `ct_key6`, so
    // EVERY v4 flow is conntracked AND firewalled (deny-by-default) instead of bypassing both. The
    // protocol byte is at `ip_off + 9` (inside the already-bounded 20-byte header).
    let (proto, sport, dport) =
        l4_ports(pkt, ip_off).unwrap_or((pkt.read_u8(ip_off + 9).unwrap_or(0), 0, 0));
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

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Advance the TCP state for a flow given a packet's TCP flags (functional parity with dpservice's
/// NONE->NEW_SYN->NEW_SYNACK->ESTABLISHED->FINWAIT->RST_FIN progression). Pure.
#[inline(always)]
pub fn tcp_advance(state: u8, flags: u8) -> u8 {
    if flags & TCP_RST != 0 {
        return TCP_RST_FIN;
    }
    if flags & TCP_FIN != 0 {
        return TCP_FINWAIT;
    }
    if flags & TCP_SYN != 0 {
        if flags & TCP_ACK != 0 {
            return TCP_NEW_SYNACK;
        }
        return TCP_NEW_SYN;
    }
    if flags & TCP_ACK != 0
        && (state == TCP_NEW_SYNACK || state == TCP_NEW_SYN || state == TCP_ESTABLISHED)
    {
        return TCP_ESTABLISHED;
    }
    state
}

/// Invert a 5-tuple key (swap src/dst addr + port) — the expected reverse-direction key.
#[inline(always)]
pub fn invert_key(k: &CtKey) -> CtKey {
    CtKey {
        vni: k.vni,
        src_ip: k.dst_ip,
        dst_ip: k.src_ip,
        src_port: k.dst_port,
        dst_port: k.src_port,
        proto: k.proto,
        _pad: [0; 3],
    }
}

/// Build the VNI-keyed IPv6 5-tuple key for the packet at `ip_off` (host-order ports; ICMPv6 id in
/// both ports). Firewall-only v6 mirror of [`ct_key`]: reads the src/dst addresses from the fixed
/// 40-byte IPv6 header (src @ +8, dst @ +24). Falls back to `(next-header, 0, 0)` when `l4_ports_v6`
/// yields nothing (unrecognised next-header / truncated L4), so every v6 flow is still tracked.
#[inline(always)]
pub fn ct_key6<P: Pkt>(pkt: &P, ip_off: usize, vni: u32) -> Option<flowplane_common::CtKey6> {
    let src = pkt.read_array::<16>(ip_off + 8)?;
    let dst = pkt.read_array::<16>(ip_off + 24)?;
    let (proto, sport, dport) =
        l4_ports_v6(pkt, ip_off).unwrap_or((pkt.read_u8(ip_off + 6).unwrap_or(0), 0, 0));
    Some(flowplane_common::CtKey6 {
        vni,
        src_ip: src,
        dst_ip: dst,
        src_port: sport,
        dst_port: dport,
        proto,
        _pad: [0; 3],
    })
}

/// Invert an IPv6 5-tuple key (swap src/dst addr + port) — the expected reverse-direction key.
#[inline(always)]
pub fn invert_key6(k: &flowplane_common::CtKey6) -> flowplane_common::CtKey6 {
    flowplane_common::CtKey6 {
        vni: k.vni,
        src_ip: k.dst_ip,
        dst_ip: k.src_ip,
        src_port: k.dst_port,
        dst_port: k.src_port,
        proto: k.proto,
        _pad: [0; 3],
    }
}

/// Apply a conntrack entry's translation to the IPv4 packet at `ip_off`, ported over the `Pkt`
/// trait so the SAME rewrite runs in eBPF and natively. Faithful port of the eBPF
/// `conntrack::ct_apply`:
///
/// - `CT_REWRITE_SRC` rewrites the inner src IP (+ src L4 port / ICMP id); otherwise `CT_REWRITE_DST`
///   rewrites the inner dst IP (+ dst L4 port). Flag-less DEFAULT entries carry no translation and
///   are left untouched (returns without writing).
/// - The address change is folded into the IP checksum and into the L4 checksum (TCP / non-zero
///   UDP), and the port change (when `xlate_port != 0`) into the L4 checksum, with the exact RFC-1624
///   incremental updates of the inline path. ICMP folds the id change into the ICMP checksum.
///
/// Only handles standard 20-byte IPv4 headers (IHL == 5); packets with options were dropped at
/// ingress, so `l4 = ip_off + 20` is a CONSTANT offset (no variable-offset provenance to fight).
///
/// eBPF-verifier seam: the inline path split reads (phase 1) from writes (phase 3) with raw pointers
/// re-derived against a single dominating bound. Here we use the READ-MODIFY-WRITE window idiom (as
/// in `nat::snat_egress`): ONE `read_array::<20>(ip_off)` proves the IP header window, ONE
/// `read_array::<N>(l4)` proves the L4 window; the address/port/checksum edits happen inside the
/// stack-local arrays; then ONE `write_array` per window re-checks the SAME range and stores it back.
/// Byte-identical to the deleted inline rewrite (same fields, same checksum ops, same conditions).
#[inline(always)]
pub fn ct_apply<P: Pkt>(pkt: &mut P, ip_off: usize, e: &CtEntry) {
    // DEFAULT (flag-less) entries carry no translation — never rewrite, or we'd null the address.
    if e.flags & (CT_REWRITE_SRC | CT_REWRITE_DST) == 0 {
        return;
    }
    // Read the whole 20-byte IPv4 header window (faithful to the eBPF `ip_off + 20 > data_end`).
    let mut ip = match pkt.read_array::<20>(ip_off) {
        Some(h) => h,
        None => return,
    };
    // Only handle standard 20-byte headers (IHL == 5); options-carrying flows were dropped upstream.
    if ip[0] & 0x0f != 5 {
        return;
    }
    let proto = ip[9];
    let rewrite_src = e.flags & CT_REWRITE_SRC != 0;
    // Address field offset WITHIN the IP header window: src at +12, dst at +16.
    let addr_rel = if rewrite_src { 12 } else { 16 };
    let old_addr: [u8; 4] = [
        ip[addr_rel],
        ip[addr_rel + 1],
        ip[addr_rel + 2],
        ip[addr_rel + 3],
    ];
    let new_addr = e.xlate_ip;

    // IP checksum at +10: fold the address change in.
    let old_ip_csum = u16::from_be_bytes([ip[10], ip[11]]);
    let new_ip_csum = csum_replace4(old_ip_csum, &old_addr, &new_addr);
    ip[10..12].copy_from_slice(&new_ip_csum.to_be_bytes());
    // Rewrite the address in the window.
    ip[addr_rel..addr_rel + 4].copy_from_slice(&new_addr);
    // Store the IP header window back (single re-checked write).
    if !pkt.write_array(ip_off, &ip) {
        return;
    }

    // L4 rewrite. `l4 = ip_off + 20` is a constant. Port offset: src at l4+0, dst at l4+2.
    let l4 = ip_off + 20;
    let port_rel = if rewrite_src { 0 } else { 2 };
    if proto == IPPROTO_TCP {
        // TCP window = 18 bytes: ports at [0..4], checksum at [16..18].
        if let Some(mut h) = pkt.read_array::<18>(l4) {
            let c0 = u16::from_be_bytes([h[16], h[17]]);
            let c1 = csum_replace4(c0, &old_addr, &new_addr);
            let c2 = if e.xlate_port != 0 {
                let old_port = u16::from_be_bytes([h[port_rel], h[port_rel + 1]]);
                csum_replace2(c1, old_port, e.xlate_port)
            } else {
                c1
            };
            h[16..18].copy_from_slice(&c2.to_be_bytes());
            if e.xlate_port != 0 {
                h[port_rel..port_rel + 2].copy_from_slice(&e.xlate_port.to_be_bytes());
            }
            pkt.write_array(l4, &h);
        }
    } else if proto == IPPROTO_UDP {
        // UDP window = 8 bytes: ports at [0..4], checksum at [6..8]. A zero UDP checksum stays zero.
        if let Some(mut h) = pkt.read_array::<8>(l4) {
            let c0 = u16::from_be_bytes([h[6], h[7]]);
            if c0 != 0 {
                let c1 = csum_replace4(c0, &old_addr, &new_addr);
                let c2 = if e.xlate_port != 0 {
                    let old_port = u16::from_be_bytes([h[port_rel], h[port_rel + 1]]);
                    csum_replace2(c1, old_port, e.xlate_port)
                } else {
                    c1
                };
                h[6..8].copy_from_slice(&c2.to_be_bytes());
            }
            if e.xlate_port != 0 {
                h[port_rel..port_rel + 2].copy_from_slice(&e.xlate_port.to_be_bytes());
            }
            pkt.write_array(l4, &h);
        }
    } else if proto == IPPROTO_ICMP && e.xlate_port != 0 {
        // ICMP window = 8 bytes: checksum at [2..4], identifier at [4..6]. The address change does
        // not affect the ICMP checksum; only the id change is folded in.
        if let Some(mut h) = pkt.read_array::<8>(l4) {
            let icmp_id = u16::from_be_bytes([h[4], h[5]]);
            let c0 = u16::from_be_bytes([h[2], h[3]]);
            let c1 = csum_replace2(c0, icmp_id, e.xlate_port);
            h[2..4].copy_from_slice(&c1.to_be_bytes());
            h[4..6].copy_from_slice(&e.xlate_port.to_be_bytes());
            pkt.write_array(l4, &h);
        }
    }
}

/// Read the TCP flags byte for an IPv4 packet at `ip_off`, or None if not TCP / out of bounds /
/// IP options present (IHL != 5). Faithful port of the eBPF `parse::tcp_flags` over `Pkt`.
#[inline(always)]
fn tcp_flags<P: Pkt>(pkt: &P, ip_off: usize) -> Option<u8> {
    let hdr = pkt.read_array::<20>(ip_off)?;
    if hdr[9] != IPPROTO_TCP {
        return None;
    }
    // Constrain to no IP options so the L4 offset is a constant.
    if hdr[0] & 0x0f != 5 {
        return None;
    }
    let l4 = ip_off + 20;
    // TCP flags are at offset 13 of the TCP header.
    pkt.read_u8(l4 + 13)
}

/// Refresh a matched IPv4 conntrack entry on a HIT: bump `last_seen = now` and advance `tcp_state`
/// from the packet's TCP flags (TCP only). Faithful port of the eBPF `conntrack::ct_touch`
/// (ebpf/conntrack.rs:57), generic over `Pkt`/`Maps`. Named `ct_refresh` to avoid clashing with the
/// eBPF `ct_touch` (which re-exports `tcp_advance` from here).
///
/// This ONLY writes the conntrack map (last_seen + tcp_state); it never mutates the packet, so it is
/// byte-parity-neutral. Without it an established TCP flow keeps `tcp_state = 0` forever, so
/// `timeout_ns` returns the 30 s idle timeout instead of the 24 h ESTABLISHED timeout and the GC
/// evicts active NAT'd flows after 30 s.
#[inline(always)]
pub fn ct_refresh<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &mut M,
    ip_off: usize,
    key: &CtKey,
    e: &mut CtEntry,
    now: u64,
) {
    e.last_seen = now;
    if let Some(fl) = tcp_flags(pkt, ip_off) {
        e.tcp_state = tcp_advance(e.tcp_state, fl);
    }
    maps.conntrack_insert(*key, *e);
}

/// Insert a no-translation DEFAULT conntrack entry for a flow on conntrack-miss, so every flow is
/// tracked (firewall + aging see it). Records last_seen + initial TCP state. Also pre-seeds the
/// reverse-direction entry so return traffic is immediately recognised as established.
///
/// `now` is the current monotonic time (ns); the eBPF wrapper passes `now()`, the sim passes 0.
/// Faithful port of the eBPF `conntrack::ct_ensure_default`.
#[inline(always)]
pub fn ct_create_default<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &mut M,
    ip_off: usize,
    vni: u32,
    now: u64,
) {
    let key = match ct_key(pkt, ip_off, vni) {
        Some(k) => k,
        None => return,
    };
    let tcp = tcp_flags(pkt, ip_off)
        .map(|fl| tcp_advance(0, fl))
        .unwrap_or(0);
    let e = CtEntry {
        last_seen: now,
        xlate_ip: [0; 4],
        xlate_port: 0,
        flags: CT_F_DEFAULT,
        tcp_state: tcp,
        fwall_action: 0,
        _pad: [0; 7],
    };
    maps.conntrack_insert(key, e);
    // Pre-seed the reverse direction so return traffic is immediately recognised as established,
    // but only if no entry already exists (NAT reverse entries must not be overwritten).
    let rev = invert_key(&key);
    if maps.conntrack_get(&rev).is_none() {
        maps.conntrack_insert(rev, e);
    }
}

/// Read the TCP flags byte for an IPv6 packet at `ip_off`, or None if the next header is not TCP /
/// out of bounds. v6 mirror of [`tcp_flags`]: the IPv6 header is a fixed 40 bytes (no options in the
/// firewall path), so the L4 offset is the constant `ip_off + 40`; TCP flags are at TCP-header
/// offset 13.
#[inline(always)]
fn tcp_flags_v6<P: Pkt>(pkt: &P, ip_off: usize) -> Option<u8> {
    if pkt.read_u8(ip_off + 6) != Some(IPPROTO_TCP) {
        return None;
    }
    pkt.read_u8(ip_off + 40 + 13)
}

/// Insert a no-translation DEFAULT IPv6 conntrack entry on conntrack-miss so every v6 flow is tracked
/// (firewall + aging see it), pre-seeding the reverse direction. Firewall-only v6 mirror of
/// [`ct_create_default`]; `now` is the current monotonic time (ns), 0 in the sim.
#[inline(always)]
pub fn ct_create_default6<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &mut M,
    ip_off: usize,
    vni: u32,
    now: u64,
) {
    let key = match ct_key6(pkt, ip_off, vni) {
        Some(k) => k,
        None => return,
    };
    let tcp = tcp_flags_v6(pkt, ip_off)
        .map(|fl| tcp_advance(0, fl))
        .unwrap_or(0);
    let e = CtEntry {
        last_seen: now,
        xlate_ip: [0; 4],
        xlate_port: 0,
        flags: CT_F_DEFAULT,
        tcp_state: tcp,
        fwall_action: 0,
        _pad: [0; 7],
    };
    maps.conntrack6_insert(key, e);
    let rev = invert_key6(&key);
    if maps.conntrack6_get(&rev).is_none() {
        maps.conntrack6_insert(rev, e);
    }
}

/// Refresh a matched IPv6 conntrack entry on a HIT: bump `last_seen = now` and advance `tcp_state`
/// from the packet's TCP flags (TCP only). v6 mirror of [`ct_refresh`] / the eBPF `ct_touch6`
/// (ebpf/conntrack.rs:145). Map-only; never mutates the packet.
#[inline(always)]
pub fn ct_refresh6<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &mut M,
    ip_off: usize,
    key: &flowplane_common::CtKey6,
    e: &mut CtEntry,
    now: u64,
) {
    e.last_seen = now;
    if let Some(fl) = tcp_flags_v6(pkt, ip_off) {
        e.tcp_state = tcp_advance(e.tcp_state, fl);
    }
    maps.conntrack6_insert(*key, *e);
}
