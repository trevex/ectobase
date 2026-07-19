//! NAT64 (bidirectional IPv6 ⇆ IPv4 translation for the `64:ff9b::/96` prefix), ported over the
//! `Pkt` + `Maps` trait seam so the SAME translation runs in the eBPF datapath
//! (`RawPkt`/`GlobalMaps`), natively in the sim (`VecPkt`/`MemMaps`), and under the
//! `BPF_PROG_TEST_RUN` byte-parity anchor.
//!
//! Faithful port of the previous inline eBPF `nat64::nat64_egress` (XDP) / `tc_nat64_egress` (TC) +
//! `nat64::nat64_ingress` (XDP): the EGRESS path (guest IPv6 dst in `64:ff9b::/96` → external IPv4 +
//! SNAT, encapped IP-in-IPv6 toward the route nexthop) and the INGRESS path (an external IPv4 reply
//! whose reverse conntrack entry carries [`CT_F_NAT64`] → expanded back to the guest's IPv6 and
//! delivered to its tap) both live here now.
//!
//! ## The resize seam (why this is a two-call parse/write split)
//!
//! NAT64 egress shrinks the inner header from IPv6(40) to IPv4(20) — a frame RESIZE — which the eBPF
//! path performs with a native primitive (`bpf_xdp_adjust_head(+20)` on XDP, `adjust_room` on TC),
//! and which the sim performs with `VecPkt` resize. As with the DHCPv4 seam, the RESIZE stays in the
//! glue; the core is a pure `Pkt`-byte reader/writer. So this module exposes two fns:
//!
//!   1. [`nat64_egress_parse`] — runs on the PRE-resize `[Eth][IPv6][L4]` frame: verifies the dst is
//!      in `64:ff9b::/96`, reads the guest NAT config, allocates a source port (reusing the forward
//!      conntrack port for an already-tracked flow), pins the forward + reverse conntrack entries
//!      (both carrying [`CT_F_NAT64`]), and returns a [`Nat64Xlate`] holding every value the writer
//!      needs — including the original v6 src/dst (for the checksum pseudo-header translation) and
//!      the L4 fields read before the resize. `None` => the glue falls through to the normal v6 path.
//!   2. [`nat64_egress_write`] — runs on the POST-resize `[Eth][IPv4][L4]` frame (L4 at
//!      `ETH_LEN + 20`): writes the Ethernet ethertype (IPv4), builds + writes the 20-byte IPv4
//!      header (IHL=5, TTL from the v6 hop-limit, src=nat_ip, dst=embedded v4, +IPv4 checksum), and
//!      translates the L4 header in place (TCP/UDP checksum v6→v4 pseudo + src-port rewrite; ICMPv6
//!      echo → ICMPv4 echo type/id/checksum). Byte-identical to the deleted inline rewrite.
//!
//! Between the two calls the glue resizes the frame and re-wraps it (the resize invalidates the prior
//! packet bounds), exactly like the DHCPv4 responder wraps a fresh `RawPkt` after `adjust_tail`.
//!
//! ## Checksum helpers
//!
//! The pure checksum/translation helpers (`ipv4_hdr_checksum`, `icmpv4_echo_checksum`,
//! `tcp_udp_v6_to_v4`, `icmpv6_echo_checksum`, `tcp_udp_v4_to_v6`, `pseudo_v4`/`pseudo_v6`) are
//! ported verbatim from the eBPF module — they operate on fixed-size stack arrays and have no
//! packet/map dependency, so they cross the seam trivially.

use flowplane_common::{
    CtEntry, CtKey, NatKey, CT_F_NAT64, CT_F_SRC_NAT, CT_REWRITE_DST, CT_REWRITE_SRC,
};

use crate::maps::Maps;
use crate::parse::hash5;
use crate::pkt::Pkt;

// Frame geometry (mirrors the eBPF `parse` module).
const ETH_LEN: usize = 14;
const IPV6_LEN: usize = 40;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

/// L4 protocol numbers.
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

/// ICMPv6 / ICMPv4 echo type constants.
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMPv6 echo-REPLY type (the ingress reply path translates ICMPv4 echo-reply → this).
const ICMPV6_ECHO_REPLY: u8 = 129;

/// Port-allocation probe limit, single-sourced with the guest-egress SNAT allocator.
pub use crate::nat::PROBE_LIMIT;

/// The NAT64 well-known prefix `64:ff9b::/96` — first 12 bytes.
/// Full 16-byte form: `[0x00,0x64,0xff,0x9b, 0,0,0,0, 0,0,0,0, v4[0..3]]`.
pub const NAT64_PFX: [u8; 12] = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

/// Check if a 16-byte IPv6 address is in the NAT64 well-known prefix `64:ff9b::/96`. Fully unrolled
/// for the BPF verifier (no loops over slice references). Faithful port of the eBPF `is_nat64_addr`.
#[inline(always)]
pub fn is_nat64_addr(addr: &[u8; 16]) -> bool {
    addr[0] == NAT64_PFX[0]
        && addr[1] == NAT64_PFX[1]
        && addr[2] == NAT64_PFX[2]
        && addr[3] == NAT64_PFX[3]
        && addr[4] == NAT64_PFX[4]
        && addr[5] == NAT64_PFX[5]
        && addr[6] == NAT64_PFX[6]
        && addr[7] == NAT64_PFX[7]
        && addr[8] == NAT64_PFX[8]
        && addr[9] == NAT64_PFX[9]
        && addr[10] == NAT64_PFX[10]
        && addr[11] == NAT64_PFX[11]
}

// ─────────────────────────────────────────────────────────────────────────────
// Checksum helpers — all operate on fixed-size stack arrays, never on packet
// memory with variable offsets. Ported verbatim from the eBPF `nat64` module.
// ─────────────────────────────────────────────────────────────────────────────

/// Fold a 32-bit accumulated ones-complement sum into a 16-bit checksum.
#[inline(always)]
fn csum_fold(mut sum: u32) -> u16 {
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

/// Add a big-endian 16-bit word (from two bytes) to an accumulator.
#[inline(always)]
fn csum_add16(sum: u32, hi: u8, lo: u8) -> u32 {
    sum.wrapping_add(((hi as u32) << 8) | lo as u32)
}

/// Ones-complement checksum over a 20-byte IPv4 header in a stack buffer.
#[inline(always)]
fn ipv4_hdr_checksum(hdr: &[u8; 20]) -> u16 {
    let mut s: u32 = 0;
    s = csum_add16(s, hdr[0], hdr[1]);
    s = csum_add16(s, hdr[2], hdr[3]);
    s = csum_add16(s, hdr[4], hdr[5]);
    s = csum_add16(s, hdr[6], hdr[7]);
    s = csum_add16(s, hdr[8], hdr[9]);
    s = csum_add16(s, hdr[10], hdr[11]);
    s = csum_add16(s, hdr[12], hdr[13]);
    s = csum_add16(s, hdr[14], hdr[15]);
    s = csum_add16(s, hdr[16], hdr[17]);
    s = csum_add16(s, hdr[18], hdr[19]);
    csum_fold(s)
}

/// Checksum over an 8-byte ICMPv4 echo header (in a stack buffer).
#[inline(always)]
fn icmpv4_echo_checksum(hdr: &[u8; 8]) -> u16 {
    let mut s: u32 = 0;
    s = csum_add16(s, hdr[0], hdr[1]);
    s = csum_add16(s, hdr[2], hdr[3]);
    s = csum_add16(s, hdr[4], hdr[5]);
    s = csum_add16(s, hdr[6], hdr[7]);
    csum_fold(s)
}

/// Pseudo-header contribution for TCP/UDP (sum of src+dst+proto+len), host-byte-order words.
#[inline(always)]
fn pseudo_v4(src: [u8; 4], dst: [u8; 4], proto: u8, l4_len: u16) -> u32 {
    let mut s: u32 = 0;
    s = csum_add16(s, src[0], src[1]);
    s = csum_add16(s, src[2], src[3]);
    s = csum_add16(s, dst[0], dst[1]);
    s = csum_add16(s, dst[2], dst[3]);
    s = csum_add16(s, 0, proto);
    s = csum_add16(s, (l4_len >> 8) as u8, (l4_len & 0xff) as u8);
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    s
}

#[inline(always)]
fn pseudo_v6(src: &[u8; 16], dst: &[u8; 16], proto: u8, l4_len: u16) -> u32 {
    let mut s: u32 = 0;
    s = csum_add16(s, src[0], src[1]);
    s = csum_add16(s, src[2], src[3]);
    s = csum_add16(s, src[4], src[5]);
    s = csum_add16(s, src[6], src[7]);
    s = csum_add16(s, src[8], src[9]);
    s = csum_add16(s, src[10], src[11]);
    s = csum_add16(s, src[12], src[13]);
    s = csum_add16(s, src[14], src[15]);
    s = csum_add16(s, dst[0], dst[1]);
    s = csum_add16(s, dst[2], dst[3]);
    s = csum_add16(s, dst[4], dst[5]);
    s = csum_add16(s, dst[6], dst[7]);
    s = csum_add16(s, dst[8], dst[9]);
    s = csum_add16(s, dst[10], dst[11]);
    s = csum_add16(s, dst[12], dst[13]);
    s = csum_add16(s, dst[14], dst[15]);
    // Upper-layer length (32-bit big-endian, but l4_len < 65536 → high word = 0).
    s = csum_add16(s, 0, 0);
    s = csum_add16(s, (l4_len >> 8) as u8, (l4_len & 0xff) as u8);
    // Next-header.
    s = csum_add16(s, 0, proto);
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    s
}

/// Translate a TCP/UDP checksum from an IPv6 pseudo-header to an IPv4 pseudo-header + fold in the
/// source-port change, all via incremental update. All arguments in network byte order. Faithful
/// port of the eBPF `nat64::tcp_udp_v6_to_v4`.
///
/// new_cksum = ~(~HC_old + ~pseudo_v6 + pseudo_v4 + ~old_sport + new_sport).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn tcp_udp_v6_to_v4(
    cksum_be: u16,
    src6: &[u8; 16],
    dst6: &[u8; 16],
    src4: [u8; 4],
    dst4: [u8; 4],
    proto: u8,
    l4_len: u16,
    old_sport_be: u16,
    new_sport_be: u16,
) -> u16 {
    let s0 = !u16::from_be(cksum_be) as u32;
    let pv6 = pseudo_v6(src6, dst6, proto, l4_len);
    let pv4 = pseudo_v4(src4, dst4, proto, l4_len);
    let old_sp = !u16::from_be(old_sport_be) as u32;
    let new_sp = u16::from_be(new_sport_be) as u32;
    let mut sum = s0
        .wrapping_add(!pv6 as u16 as u32)
        .wrapping_add(pv4)
        .wrapping_add(old_sp)
        .wrapping_add(new_sp);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    (!(sum as u16)).to_be()
}

/// Build a `64:ff9b::` IPv6 address embedding a 4-byte IPv4 address. Used by the INGRESS path to
/// reconstruct the reply's IPv6 source from the external server's IPv4. Faithful port of the eBPF
/// `nat64_embed`.
#[inline(always)]
fn nat64_embed(ipv4: [u8; 4]) -> [u8; 16] {
    [
        0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, ipv4[0], ipv4[1], ipv4[2], ipv4[3],
    ]
}

/// Checksum over an 8-byte ICMPv6 echo header with an IPv6 pseudo-header. Faithful port of the eBPF
/// ingress `icmpv6_echo_checksum`. pseudo-header: src(16) + dst(16) + upper-layer length (4 BE) +
/// zeros(3) + next-header(1); upper-layer length is fixed at 8 (the echo header).
#[inline(always)]
fn icmpv6_echo_checksum(src: &[u8; 16], dst: &[u8; 16], hdr: &[u8; 8]) -> u16 {
    let mut s: u32 = 0;
    // src — 8 words.
    s = csum_add16(s, src[0], src[1]);
    s = csum_add16(s, src[2], src[3]);
    s = csum_add16(s, src[4], src[5]);
    s = csum_add16(s, src[6], src[7]);
    s = csum_add16(s, src[8], src[9]);
    s = csum_add16(s, src[10], src[11]);
    s = csum_add16(s, src[12], src[13]);
    s = csum_add16(s, src[14], src[15]);
    // dst — 8 words.
    s = csum_add16(s, dst[0], dst[1]);
    s = csum_add16(s, dst[2], dst[3]);
    s = csum_add16(s, dst[4], dst[5]);
    s = csum_add16(s, dst[6], dst[7]);
    s = csum_add16(s, dst[8], dst[9]);
    s = csum_add16(s, dst[10], dst[11]);
    s = csum_add16(s, dst[12], dst[13]);
    s = csum_add16(s, dst[14], dst[15]);
    // Upper-layer length = 8 (fits in low 16 bits).
    s = csum_add16(s, 0, 8);
    // Next-header = 58 (ICMPv6).
    s = csum_add16(s, 0, IPPROTO_ICMPV6);
    // ICMPv6 header — 4 words.
    s = csum_add16(s, hdr[0], hdr[1]);
    s = csum_add16(s, hdr[2], hdr[3]);
    s = csum_add16(s, hdr[4], hdr[5]);
    s = csum_add16(s, hdr[6], hdr[7]);
    csum_fold(s)
}

/// Translate a TCP/UDP checksum from an IPv4 pseudo-header to an IPv6 pseudo-header (INGRESS). The
/// port fields are assumed unchanged (the reverse `ct_apply` already restored the dst port + folded
/// it into the checksum before this runs). All arguments in network byte order. Faithful port of the
/// eBPF ingress `tcp_udp_v4_to_v6`.
///
/// new_cksum = ~(~HC_old + ~pseudo_v4 + pseudo_v6).
#[inline(always)]
fn tcp_udp_v4_to_v6(
    cksum_be: u16,
    src4: [u8; 4],
    dst4: [u8; 4],
    src6: &[u8; 16],
    dst6: &[u8; 16],
    proto: u8,
    l4_len: u16,
) -> u16 {
    let s0 = !u16::from_be(cksum_be) as u32;
    let pv4 = pseudo_v4(src4, dst4, proto, l4_len); // folded to 16-bit
    let pv6 = pseudo_v6(src6, dst6, proto, l4_len); // folded to 16-bit
    let mut sum = s0
        .wrapping_add(!pv4 as u16 as u32) // remove v4 pseudo contribution
        .wrapping_add(pv6); // add v6 pseudo contribution
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    (!(sum as u16)).to_be()
}

// ─────────────────────────────────────────────────────────────────────────────
// EGRESS parse + write over the Pkt/Maps seam
// ─────────────────────────────────────────────────────────────────────────────

/// The translation state `nat64_egress_parse` returns for `nat64_egress_write` to consume. Carries
/// the values read from the PRE-resize IPv6 frame (so the writer, running on the resized IPv4 frame,
/// can reproduce the exact v6→v4 header + checksum translation).
#[derive(Copy, Clone)]
pub struct Nat64Xlate {
    /// The guest's public NAT IPv4 (translated IPv4 src).
    pub nat_ipv4: [u8; 4],
    /// The embedded IPv4 dst extracted from the `64:ff9b::` prefix.
    pub ipv4_dst: [u8; 4],
    /// Allocated / reused NAT source port (or ICMP id).
    pub nat_port: u16,
    /// The translated IPv4 L4 protocol (TCP/UDP/ICMP).
    pub l4_proto_v4: u8,
    /// The original guest L4 source port (or ICMP id) — the checksum-delta "old" value.
    pub sport: u16,
    /// IPv6 payload length = L4 length (bytes). Feeds the IPv4 total-length + the pseudo-header.
    pub l4_len: u16,
    /// IPv6 hop-limit → the inner IPv4 TTL.
    pub hop_limit: u8,
    /// The original inner IPv6 src (for the checksum pseudo-header translation).
    pub ip6_src: [u8; 16],
    /// The original inner IPv6 dst (for the checksum pseudo-header translation).
    pub ip6_dst: [u8; 16],
    /// The original L4 checksum (big-endian, as read from the packet).
    pub old_l4_cksum_be: u16,
    /// The original Ethernet dst (preserved across the XDP in-place `adjust_head` shift).
    pub eth_dst: [u8; 6],
    /// The original Ethernet src (preserved across the XDP in-place `adjust_head` shift).
    pub eth_src: [u8; 6],
}

/// EGRESS parse phase — runs on the PRE-resize `[Eth][IPv6][L4]` guest frame at `ip6_off` (= the
/// offset of the IPv6 header, i.e. `ETH_LEN`). Verifies the dst is in `64:ff9b::/96`, reads the guest
/// NAT config, allocates/reuses a source port, pins the forward + reverse conntrack entries (both
/// carrying [`CT_F_NAT64`]), and returns the [`Nat64Xlate`] the writer needs. `None` => the glue
/// falls through (not a NAT64 frame, or no NAT config / empty range / unsupported L4).
///
/// `now` stamps the conntrack `last_seen` (eBPF: `now()`, sim: `0`) — a map-only field that never
/// touches the emitted packet bytes. Faithful to the eBPF `nat64_egress` pre-resize logic.
#[inline(always)]
pub fn nat64_egress_parse<P: Pkt, M: Maps>(
    pkt: &P,
    maps: &mut M,
    ip6_off: usize,
    vni: u32,
    meta_guest_ipv4: [u8; 4],
    now: u64,
) -> Option<Nat64Xlate> {
    // Eth(14) + IPv6(40) + min L4(8). Faithful to `data + ETH_LEN + IPV6_LEN + 8 > data_end`.
    let ip6_dst: [u8; 16] = pkt.read_array::<16>(ip6_off + 24)?;
    if !is_nat64_addr(&ip6_dst) {
        return None;
    }
    let ipv4_dst: [u8; 4] = [ip6_dst[12], ip6_dst[13], ip6_dst[14], ip6_dst[15]];

    // NAT config for this guest.
    let nat = maps.nat_get(&NatKey {
        vni,
        ipv4: meta_guest_ipv4,
    })?;
    let range = nat.port_max.wrapping_sub(nat.port_min);
    if range == 0 {
        return None;
    }

    let ip6_src: [u8; 16] = pkt.read_array::<16>(ip6_off + 8)?;
    let nh = pkt.read_u8(ip6_off + 6)?;
    let ip6_plen = pkt.read_u16_be(ip6_off + 4)?;
    let l4_len = ip6_plen as usize;
    // `ip6_plen` is attacker-controlled; it feeds the translated IPv4 total_len + the L4 pseudo-header
    // checksum length. Reject a claimed payload that overruns the buffer. Faithful to the eBPF bound
    // `data + ETH_LEN + IPV6_LEN + l4_len > data_end`: the last claimed payload byte must be present.
    if l4_len > 0 && pkt.read_u8(ip6_off + IPV6_LEN + l4_len - 1).is_none() {
        return None;
    }

    let l4 = ip6_off + IPV6_LEN;
    let (l4_proto_v4, sport, dport, old_l4_cksum_be): (u8, u16, u16, u16) = match nh {
        IPPROTO_ICMPV6 => {
            // Only ICMPv6 echo request is translated; other ICMPv6 types are not NAT64'd.
            if pkt.read_u8(l4)? != ICMPV6_ECHO_REQUEST {
                return None;
            }
            let id = pkt.read_u16_be(l4 + 4)?;
            let cksum = u16::from_be(pkt.read_u16_be(l4 + 2)?);
            (IPPROTO_ICMP, id, id, cksum)
        }
        IPPROTO_TCP => {
            let sp = pkt.read_u16_be(l4)?;
            let dp = pkt.read_u16_be(l4 + 2)?;
            let ck = u16::from_be(pkt.read_u16_be(l4 + 16)?);
            (IPPROTO_TCP, sp, dp, ck)
        }
        IPPROTO_UDP => {
            let sp = pkt.read_u16_be(l4)?;
            let dp = pkt.read_u16_be(l4 + 2)?;
            let ck = u16::from_be(pkt.read_u16_be(l4 + 6)?);
            (IPPROTO_UDP, sp, dp, ck)
        }
        _ => return None,
    };

    // Forward conntrack key (keyed on the IPv4 5-tuple after translation).
    let fwd_key = CtKey {
        vni,
        src_ip: meta_guest_ipv4,
        dst_ip: ipv4_dst,
        src_port: sport,
        dst_port: dport,
        proto: l4_proto_v4,
        _pad: [0; 3],
    };
    let nat_port = match maps.conntrack_get(&fwd_key) {
        Some(v) if v.flags & CT_F_SRC_NAT != 0 => v.xlate_port,
        _ => {
            let start = (hash5(&meta_guest_ipv4, &ipv4_dst, sport, dport, l4_proto_v4)
                % range as u32) as u16;
            let mut chosen = nat.port_min.wrapping_add(start);
            let mut i: u16 = 0;
            while i < PROBE_LIMIT {
                let cand = nat.port_min.wrapping_add((start.wrapping_add(i)) % range);
                let rev_key = CtKey {
                    vni,
                    src_ip: [0; 4],
                    dst_ip: nat.nat_ipv4,
                    src_port: 0,
                    dst_port: cand,
                    proto: l4_proto_v4,
                    _pad: [0; 3],
                };
                if maps.conntrack_get(&rev_key).is_none() {
                    chosen = cand;
                    // Reverse entry: guest xlate_ip + original sport/id in xlate_port. CT_F_NAT64
                    // tells the ingress path to do IPv4→IPv6 expansion on the reply.
                    maps.conntrack_insert(
                        rev_key,
                        CtEntry {
                            last_seen: now,
                            xlate_ip: meta_guest_ipv4,
                            xlate_port: sport,
                            flags: CT_REWRITE_DST | CT_F_SRC_NAT | CT_F_NAT64,
                            tcp_state: 0,
                            fwall_action: 0,
                            _pad: [0; 7],
                        },
                    );
                    break;
                }
                i += 1;
            }
            maps.conntrack_insert(
                fwd_key,
                CtEntry {
                    last_seen: now,
                    xlate_ip: nat.nat_ipv4,
                    xlate_port: chosen,
                    flags: CT_REWRITE_SRC | CT_F_SRC_NAT | CT_F_NAT64,
                    tcp_state: 0,
                    fwall_action: 0,
                    _pad: [0; 7],
                },
            );
            chosen
        }
    };

    let hop_limit = pkt.read_u8(ip6_off + 7)?;
    // Ethernet dst/src, preserved for the XDP in-place `adjust_head(+20)` writer (the 20-byte shift
    // drops the old Ethernet header off the front; the writer restores it in front of the IPv4 hdr).
    let eth_dst: [u8; 6] = pkt.read_array::<6>(ip6_off - ETH_LEN)?;
    let eth_src: [u8; 6] = pkt.read_array::<6>(ip6_off - ETH_LEN + 6)?;

    Some(Nat64Xlate {
        nat_ipv4: nat.nat_ipv4,
        ipv4_dst,
        nat_port,
        l4_proto_v4,
        sport,
        l4_len: l4_len as u16,
        hop_limit,
        ip6_src,
        ip6_dst,
        old_l4_cksum_be,
        eth_dst,
        eth_src,
    })
}

/// EGRESS write phase — runs on the POST-resize frame. `ip4_off` is the offset of the (freshly
/// created) IPv4 header; the L4 header is at `ip4_off + 20`. Builds + writes the 20-byte IPv4 header
/// (IHL=5, TTL from the v6 hop-limit, src=nat_ip, dst=embedded v4, +IPv4 checksum), then translates
/// the L4 header in place. Returns `false` on a bounds failure. Byte-identical to the deleted inline
/// eBPF rewrite.
///
/// `write_eth`: on the XDP in-place shrink path (`adjust_head(+20)`), the 20-byte front-shift drops
/// the old Ethernet header, so the writer restores it directly in front of the IPv4 header — the
/// preserved `eth_dst`/`eth_src` from parse + the IPv4 ethertype, exactly as the original
/// `nat64_egress` did. On the tc grow path the glue writes its OWN outer Eth+IPv6 frame around the
/// inner IPv4 (the writer only does the inner IPv4 + L4), so it calls with `write_eth = false`.
#[inline(always)]
pub fn nat64_egress_write<P: Pkt>(
    pkt: &mut P,
    ip4_off: usize,
    write_eth: bool,
    x: &Nat64Xlate,
) -> bool {
    // Ethernet header directly in front of the IPv4 header (XDP in-place shrink path only).
    if write_eth {
        let eth_off = ip4_off - ETH_LEN;
        let mut eth = [0u8; 14];
        eth[0..6].copy_from_slice(&x.eth_dst);
        eth[6..12].copy_from_slice(&x.eth_src);
        eth[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        if !pkt.write_array(eth_off, &eth) {
            return false;
        }
    }

    // Build the IPv4 header (20 bytes, IHL=5) in a stack buffer, then a single write.
    let total_len = 20u16.wrapping_add(x.l4_len);
    let mut ip4hdr = [0u8; 20];
    ip4hdr[0] = 0x45;
    ip4hdr[1] = 0;
    ip4hdr[2] = (total_len >> 8) as u8;
    ip4hdr[3] = (total_len & 0xff) as u8;
    // id = 0, flags/frag = 0 (already 0).
    ip4hdr[8] = x.hop_limit;
    ip4hdr[9] = x.l4_proto_v4;
    // checksum placeholder at [10..12] = 0.
    ip4hdr[12] = x.nat_ipv4[0];
    ip4hdr[13] = x.nat_ipv4[1];
    ip4hdr[14] = x.nat_ipv4[2];
    ip4hdr[15] = x.nat_ipv4[3];
    ip4hdr[16] = x.ipv4_dst[0];
    ip4hdr[17] = x.ipv4_dst[1];
    ip4hdr[18] = x.ipv4_dst[2];
    ip4hdr[19] = x.ipv4_dst[3];
    let ip4_chk = ipv4_hdr_checksum(&ip4hdr);
    ip4hdr[10] = (ip4_chk >> 8) as u8;
    ip4hdr[11] = (ip4_chk & 0xff) as u8;
    if !pkt.write_array(ip4_off, &ip4hdr) {
        return false;
    }

    // Translate the L4 header in place at ip4_off + 20.
    let l4 = ip4_off + 20;
    match x.l4_proto_v4 {
        IPPROTO_ICMP => {
            // ICMPv6→ICMPv4: type 128→8, id → nat_port, recompute ICMPv4 echo checksum. seq (bytes
            // [6..8]) is unchanged. Read the 8-byte window, patch in-place, write it back.
            let h = match pkt.read_array::<8>(l4) {
                Some(h) => h,
                None => return false,
            };
            let icmp4: [u8; 8] = [
                ICMP_ECHO_REQUEST,
                0,
                0,
                0,
                (x.nat_port >> 8) as u8,
                (x.nat_port & 0xff) as u8,
                h[6],
                h[7],
            ];
            let chk = icmpv4_echo_checksum(&icmp4);
            let out: [u8; 8] = [
                ICMP_ECHO_REQUEST,
                0,
                (chk >> 8) as u8,
                (chk & 0xff) as u8,
                (x.nat_port >> 8) as u8,
                (x.nat_port & 0xff) as u8,
                h[6],
                h[7],
            ];
            pkt.write_array(l4, &out)
        }
        IPPROTO_TCP => {
            let new_ck = tcp_udp_v6_to_v4(
                x.old_l4_cksum_be,
                &x.ip6_src,
                &x.ip6_dst,
                x.nat_ipv4,
                x.ipv4_dst,
                IPPROTO_TCP,
                x.l4_len,
                x.sport.to_be(),
                x.nat_port.to_be(),
            );
            // TCP: src port at l4[0..2], checksum at l4[16..18]. Window = 18 bytes, single RMW.
            let mut h = match pkt.read_array::<18>(l4) {
                Some(h) => h,
                None => return false,
            };
            h[0..2].copy_from_slice(&x.nat_port.to_be_bytes());
            h[16..18].copy_from_slice(&new_ck.to_ne_bytes());
            pkt.write_array(l4, &h)
        }
        IPPROTO_UDP => {
            let new_ck = tcp_udp_v6_to_v4(
                x.old_l4_cksum_be,
                &x.ip6_src,
                &x.ip6_dst,
                x.nat_ipv4,
                x.ipv4_dst,
                IPPROTO_UDP,
                x.l4_len,
                x.sport.to_be(),
                x.nat_port.to_be(),
            );
            // UDP: src port at l4[0..2], checksum at l4[6..8]. Window = 8 bytes, single RMW.
            let mut h = match pkt.read_array::<8>(l4) {
                Some(h) => h,
                None => return false,
            };
            h[0..2].copy_from_slice(&x.nat_port.to_be_bytes());
            h[6..8].copy_from_slice(&new_ck.to_ne_bytes());
            pkt.write_array(l4, &h)
        }
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// INGRESS parse + write over the Pkt/Maps seam
// ─────────────────────────────────────────────────────────────────────────────
//
// The INGRESS reply path is the mirror of egress: an external IPv4 reply whose reverse conntrack
// entry carries CT_F_NAT64 (detected by `try_uplink_rx`, which has already run `ct_apply` to restore
// the guest IPv4 dst + orig L4 port + fold both into the IPv4/L4 checksums) is expanded from IPv4
// back to IPv6 and delivered to the guest tap. Because the frame GROWS on the wire only in the outer
// sense — the layout goes `[Eth][outerIPv6(40)][innerIPv4(20)][L4]` (74+L4) →
// `[Eth][innerIPv6(40)][L4]` (54+L4), a net SHRINK of 20 — the eBPF path performs it with
// `bpf_xdp_adjust_head(+20)` (drop 20 bytes off the front) and the sim with `VecPkt::shrink_head(20)`.
// As with egress, the RESIZE stays in the glue; the core is a two-call parse/write split:
//
//   1. [`nat64_ingress_parse`] — runs on the PRE-resize `[Eth][outerIPv6][innerIPv4][L4]` frame:
//      checks IHL==5, reads the L4 proto / TTL / inner v4 src+dst / total-len / L4 checksum,
//      reconstructs the reply's IPv6 src from the embedded external v4 (`64:ff9b::src4`), takes the
//      guest's IPv6 dst from the caller (PORT_META `guest_ipv6`), and returns a [`Nat64InXlate`].
//      `None` => the glue falls through (short frame / IHL≠5 / unsupported L4 / no guest IPv6).
//   2. [`nat64_ingress_write`] — runs on the POST-resize `[Eth][innerIPv6][L4]` frame (L4 at
//      `ETH_LEN + IPV6_LEN`): writes the guest-facing Ethernet (dst=guest_mac, src=GW_MAC, IPv6
//      ethertype), the 40-byte inner IPv6 header (src=64:ff9b::server, dst=guest_ipv6, TTL from the
//      inner v4), and translates the L4 (TCP/UDP checksum v4→v6; ICMPv4 echo-reply → ICMPv6
//      echo-reply, id restored to `orig_sport`). Byte-identical to the deleted inline rewrite.

/// The translation state `nat64_ingress_parse` returns for `nat64_ingress_write` to consume. Carries
/// the values read from the PRE-resize `[Eth][outerIPv6][innerIPv4][L4]` frame (so the writer,
/// running on the resized `[Eth][innerIPv6][L4]` frame, reproduces the exact v4→v6 header + checksum
/// translation).
#[derive(Copy, Clone)]
pub struct Nat64InXlate {
    /// The inner IPv4 L4 protocol (TCP/UDP/ICMP) — the translated IPv6 next-header for TCP/UDP, or
    /// ICMPv6 for ICMP.
    pub l4_proto: u8,
    /// The inner IPv4 TTL → the inner IPv6 hop-limit.
    pub ttl: u8,
    /// The external server's IPv4 (inner IPv4 src) — embedded into the reconstructed IPv6 src.
    pub inner_src_v4: [u8; 4],
    /// The inner IPv4 dst (= the restored guest IPv4 after `ct_apply`) — for the checksum pseudo-hdr.
    pub inner_dst_v4: [u8; 4],
    /// L4 length (bytes) = IPv4 total_len − 20. Feeds the IPv6 payload-length + the pseudo-header.
    pub l4_len: u16,
    /// The original L4 checksum (big-endian, as read from the packet, POST-`ct_apply`).
    pub old_l4_cksum_be: u16,
    /// The reconstructed IPv6 src = `64:ff9b::inner_src_v4`.
    pub ipv6_src: [u8; 16],
    /// The guest's IPv6 dst (from PORT_META `guest_ipv6`, supplied by the caller).
    pub guest_ipv6: [u8; 16],
    /// The guest tap's MAC (Ethernet dst on the delivered frame).
    pub guest_mac: [u8; 6],
    /// The original guest L4 port / ICMP id (CT `xlate_port`) — restored into the ICMPv6 echo id.
    pub orig_sport: u16,
}

/// INGRESS parse phase — runs on the PRE-resize `[Eth][outerIPv6][innerIPv4][L4]` frame at
/// `inner_off` (= the offset of the inner IPv4 header, i.e. `ETH_LEN + IPV6_LEN`). Verifies IHL==5,
/// reads the L4 proto / TTL / inner v4 addrs / total-len / L4 checksum, reconstructs the IPv6 src
/// (`64:ff9b::inner_src_v4`), and returns the [`Nat64InXlate`] the writer needs. `None` => the glue
/// falls through (short frame / IHL≠5 / unsupported L4 / all-zero guest IPv6). Faithful to the eBPF
/// `nat64_ingress` pre-resize logic.
///
/// `guest_ipv6` / `guest_mac` / `orig_sport` come from the caller (PORT_META + the reverse CT entry
/// the dispatch already resolved); the core does not re-read them from maps.
#[inline(always)]
pub fn nat64_ingress_parse<P: Pkt>(
    pkt: &P,
    inner_off: usize,
    guest_ipv6: [u8; 16],
    guest_mac: [u8; 6],
    orig_sport: u16,
) -> Option<Nat64InXlate> {
    // Eth(14) + outer IPv6(40) + inner IPv4(20) + min L4(8). Faithful to the eBPF bound
    // `data + ETH_LEN + IPV6_LEN + 20 + 8 > data_end`.
    let inner: [u8; 20] = pkt.read_array::<20>(inner_off)?;
    // Inner IPv4 IHL == 5 (no options; constant L4 offset).
    if inner[0] & 0x0f != 5 {
        return None;
    }
    let l4_proto = inner[9];
    match l4_proto {
        IPPROTO_ICMP | IPPROTO_TCP | IPPROTO_UDP => {}
        _ => return None,
    }
    let ttl = inner[8];
    // The inner IPv4 src (= the external server) → NAT64-prefix IPv6 src.
    let inner_src_v4: [u8; 4] = [inner[12], inner[13], inner[14], inner[15]];
    // The inner IPv4 dst = the restored guest IPv4 (ct_apply already applied CT_REWRITE_DST).
    let inner_dst_v4: [u8; 4] = [inner[16], inner[17], inner[18], inner[19]];
    let inner_total_len = u16::from_be_bytes([inner[2], inner[3]]) as usize;
    let l4_len = if inner_total_len >= 20 {
        inner_total_len - 20
    } else {
        return None;
    };

    // Existing L4 checksum (big-endian, from the packet POST-`ct_apply`). Incremental v4→v6 update
    // for TCP/UDP; ICMP is recomputed fully. Each read reproduces the eBPF's proto-specific bound.
    let l4_off = inner_off + 20;
    let old_l4_cksum_be: u16 = match l4_proto {
        IPPROTO_TCP => u16::from_be(pkt.read_u16_be(l4_off + 16)?),
        IPPROTO_UDP => u16::from_be(pkt.read_u16_be(l4_off + 6)?),
        IPPROTO_ICMP => u16::from_be(pkt.read_u16_be(l4_off + 2)?),
        _ => return None,
    };

    if guest_ipv6 == [0u8; 16] {
        return None;
    }
    let ipv6_src = nat64_embed(inner_src_v4);

    Some(Nat64InXlate {
        l4_proto,
        ttl,
        inner_src_v4,
        inner_dst_v4,
        l4_len: l4_len as u16,
        old_l4_cksum_be,
        ipv6_src,
        guest_ipv6,
        guest_mac,
        orig_sport,
    })
}

/// INGRESS write phase — runs on the POST-resize `[Eth][innerIPv6][L4]` frame. `ip6_off` is the
/// offset of the (freshly created) inner IPv6 header (= `ETH_LEN`); the L4 header is at
/// `ip6_off + IPV6_LEN`. Writes the guest-facing Ethernet (dst=guest_mac, src=`gw_mac`, IPv6
/// ethertype), the 40-byte IPv6 header (src=`64:ff9b::server`, dst=guest_ipv6, TTL from the inner
/// v4), and translates the L4 in place. Returns `false` on a bounds failure. Byte-identical to the
/// deleted inline eBPF rewrite.
///
/// `gw_mac` is the dataplane gateway MAC (eBPF: `arp_nd::GW_MAC`; sim: `uplink::GW_MAC`) — passed in
/// rather than referenced so the core stays free of the eBPF map/const layer.
#[inline(always)]
pub fn nat64_ingress_write<P: Pkt>(
    pkt: &mut P,
    ip6_off: usize,
    gw_mac: [u8; 6],
    x: &Nat64InXlate,
) -> bool {
    // Ethernet header directly in front of the IPv6 header: dst=guest_mac, src=gw_mac, ethertype IPv6.
    let eth_off = ip6_off - ETH_LEN;
    let mut eth = [0u8; 14];
    eth[0..6].copy_from_slice(&x.guest_mac);
    eth[6..12].copy_from_slice(&gw_mac);
    eth[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
    if !pkt.write_array(eth_off, &eth) {
        return false;
    }

    // Build the 40-byte IPv6 header in a stack buffer, then a single write.
    let l4_proto_v6 = if x.l4_proto == IPPROTO_ICMP {
        IPPROTO_ICMPV6
    } else {
        x.l4_proto
    };
    let mut ip6 = [0u8; 40];
    ip6[0] = 0x60; // version 6, TC/flow = 0.
                   // [1..4] flow label = 0 (already 0).
    ip6[4] = (x.l4_len >> 8) as u8;
    ip6[5] = (x.l4_len & 0xff) as u8;
    ip6[6] = l4_proto_v6;
    ip6[7] = x.ttl;
    ip6[8..24].copy_from_slice(&x.ipv6_src);
    ip6[24..40].copy_from_slice(&x.guest_ipv6);
    if !pkt.write_array(ip6_off, &ip6) {
        return false;
    }

    // Translate the L4 header in place at ip6_off + IPV6_LEN.
    let l4 = ip6_off + IPV6_LEN;
    match x.l4_proto {
        IPPROTO_ICMP => {
            // ICMPv4 echo reply → ICMPv6 echo reply: type 0→129, id → orig_sport, seq unchanged,
            // recompute the ICMPv6 echo checksum. Read the 8-byte window, patch, write it back.
            let h = match pkt.read_array::<8>(l4) {
                Some(h) => h,
                None => return false,
            };
            let icmp6: [u8; 8] = [
                ICMPV6_ECHO_REPLY,           // type 129
                0,                           // code
                0,                           // checksum placeholder hi
                0,                           // checksum placeholder lo
                (x.orig_sport >> 8) as u8,   // id hi (restored)
                (x.orig_sport & 0xff) as u8, // id lo
                h[6],                        // seq hi (unchanged)
                h[7],                        // seq lo (unchanged)
            ];
            let chk = icmpv6_echo_checksum(&x.ipv6_src, &x.guest_ipv6, &icmp6);
            let out: [u8; 8] = [
                ICMPV6_ECHO_REPLY,
                0,
                (chk >> 8) as u8,
                (chk & 0xff) as u8,
                (x.orig_sport >> 8) as u8,
                (x.orig_sport & 0xff) as u8,
                h[6],
                h[7],
            ];
            pkt.write_array(l4, &out)
        }
        IPPROTO_TCP => {
            let new_ck = tcp_udp_v4_to_v6(
                x.old_l4_cksum_be,
                x.inner_src_v4,
                x.inner_dst_v4,
                &x.ipv6_src,
                &x.guest_ipv6,
                IPPROTO_TCP,
                x.l4_len,
            );
            // TCP: checksum at l4[16..18]. Window = 18 bytes, single RMW.
            let mut h = match pkt.read_array::<18>(l4) {
                Some(h) => h,
                None => return false,
            };
            h[16..18].copy_from_slice(&new_ck.to_ne_bytes());
            pkt.write_array(l4, &h)
        }
        IPPROTO_UDP => {
            let new_ck = tcp_udp_v4_to_v6(
                x.old_l4_cksum_be,
                x.inner_src_v4,
                x.inner_dst_v4,
                &x.ipv6_src,
                &x.guest_ipv6,
                IPPROTO_UDP,
                x.l4_len,
            );
            // UDP: checksum at l4[6..8]. Window = 8 bytes, single RMW.
            let mut h = match pkt.read_array::<8>(l4) {
                Some(h) => h,
                None => return false,
            };
            h[6..8].copy_from_slice(&new_ck.to_ne_bytes());
            pkt.write_array(l4, &h)
        }
        _ => false,
    }
}
