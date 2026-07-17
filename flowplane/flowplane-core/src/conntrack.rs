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
use crate::parse::{l4_ports, IPPROTO_TCP};
use crate::pkt::Pkt;
use flowplane_common::{
    CtEntry, CtKey, CT_F_DEFAULT, TCP_ESTABLISHED, TCP_FINWAIT, TCP_NEW_SYN, TCP_NEW_SYNACK,
    TCP_RST_FIN,
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
    let (proto, sport, dport) = l4_ports(pkt, ip_off)?;
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
