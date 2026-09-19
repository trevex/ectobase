//! Guest-egress network SNAT, ported over the `Pkt`/`Maps` traits so the same rewrite runs in eBPF
//! and natively. Faithful port of the eBPF `nat::nat_snat_egress`: same NAT-config lookup, the same
//! forward/reverse conntrack port allocation (hash-start + linear probe, peer-independent reverse
//! key), and the same src-IP + L4-port/ICMP-id rewrites with the exact incremental checksum updates.
//!
//! Time impurity: the eBPF path stamps `last_seen` from `bpf_ktime_get_ns()`. As in
//! `conntrack::ct_create_default`, `snat_egress` takes `now: u64` as a parameter — the eBPF wrapper
//! passes `now()`, the sim passes 0. `last_seen` is a conntrack-map field only; it never touches the
//! packet bytes, so it does not affect byte-parity of the emitted frame.
//!
//! Source-BLOCK allocation (which `(nat_ip, port_range)` a guest gets) is OUT of scope — that is the
//! Go `mesh/allocator`. This is only the datapath port pick WITHIN an already-allocated range.

use flowplane_common::csum::{csum_replace2, csum_replace4};
use flowplane_common::{
    CtEntry, CtEntry6, CtKey, CtKey6, NatKey, NatKey6, NatValue6, CT_F_SRC_NAT, CT_REWRITE_DST,
    CT_REWRITE_SRC,
};

use crate::conntrack::csum_replace16;
use crate::maps::Maps;
use crate::parse::{hash5, hash_v6, l4_ports, l4_ports_v6, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};
use crate::pkt::Pkt;

/// ICMPv6 next-header (l4_ports_v6 returns its echo id as both "ports"). Unlike ICMPv4, the ICMPv6
/// checksum covers the IPv6 pseudo-header, so a src-address change MUST be folded into it.
const IPPROTO_ICMPV6: u8 = 58;

/// Max reverse-key probes when picking a source port. Mirrors the eBPF `nat::PROBE_LIMIT`.
pub const PROBE_LIMIT: u16 = 64;

/// The owning node's underlay for a packet to `dst:dport` that arrived in `vni` — the node-side
/// relay (`uplink_rx` mechanism #3). Blocks are keyed without a VNI (ranges never overlap per
/// nat_ip, in any VNI), so a block of another VNI is not this packet's.
#[inline(always)]
pub fn neighbor_nat_owner<M: Maps>(
    maps: &M,
    vni: u32,
    dst: &[u8; 4],
    dport: u16,
) -> Option<[u8; 16]> {
    maps.nat_owner(dst, dport)
        .filter(|o| o.vni == vni)
        .map(|o| o.underlay)
}

/// IPv6 sibling of [`neighbor_nat_owner`].
#[inline(always)]
pub fn neighbor_nat_owner6<M: Maps>(
    maps: &M,
    vni: u32,
    dst: &[u8; 16],
    dport: u16,
) -> Option<[u8; 16]> {
    maps.nat_owner6(dst, dport)
        .filter(|o| o.vni == vni)
        .map(|o| o.underlay)
}

/// Outcome of an egress SNAT attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SnatOutcome {
    /// SNAT was not applicable (not external / no NAT binding / non-L4) or it completed
    /// successfully — the caller forwards the packet as usual.
    Continue,
    /// External SNAT was required but the `nat_ip` port space is exhausted. The caller
    /// MUST drop: forwarding would leak the guest source IP and, worse, reusing an
    /// already-allocated port would mis-demux that other flow's return traffic.
    Exhausted,
    /// External SNAT was required but the packet has no L4 port field to translate — a NON-FIRST
    /// IPv4 fragment. The caller MUST drop, for the same leak reason as [`Self::Exhausted`]:
    /// forwarding would put the guest's overlay source on the wire un-SNATed. It cannot be
    /// translated either, since the reverse demux is `(nat_ip, port)`-keyed and the fragment has no
    /// port; supporting it would need a fragment-tracking map carrying the first fragment's ports.
    Untranslatable,
}

/// Egress network SNAT. If `is_external` and the guest `(vni, src)` has a NAT config, allocate a
/// source port (reusing the forward-conntrack port if the flow is already tracked), rewrite the
/// inner src IP -> `nat_ip` and the L4 src port / ICMP id -> `nat_port` (+checksums), and pin the
/// forward + reverse conntrack entries. Returns [`SnatOutcome::Exhausted`] (caller drops) if no
/// free port could be allocated; otherwise [`SnatOutcome::Continue`].
///
/// `ip_off` is the offset of the inner IPv4 header (e.g. `ETH_LEN` for a guest Ethernet frame).
/// `now` is the monotonic time (ns) written into the conntrack `last_seen` field (eBPF: `now()`,
/// sim: `0`); `epoch` is the firewall epoch the forward entry records — the one the caller read
/// before its egress firewall check (see `conntrack::ct_create_default`). Byte-identical to the eBPF
/// `nat::nat_snat_egress`.
#[inline(always)]
pub fn snat_egress<P: Pkt, M: Maps>(
    pkt: &mut P,
    maps: &mut M,
    ip_off: usize,
    vni: u32,
    is_external: bool,
    now: u64,
    epoch: u32,
) -> SnatOutcome {
    if !is_external {
        return SnatOutcome::Continue;
    }
    // Faithful to the eBPF bound `data + ip_off + 20 > data_end`.
    let hdr = match pkt.read_array::<20>(ip_off) {
        Some(h) => h,
        None => return SnatOutcome::Continue,
    };
    let src: [u8; 4] = [hdr[12], hdr[13], hdr[14], hdr[15]];
    let dst: [u8; 4] = [hdr[16], hdr[17], hdr[18], hdr[19]];
    let nat = match maps.nat_get(&NatKey { vni, ipv4: src }) {
        Some(v) => v,
        None => return SnatOutcome::Continue,
    };
    let range = nat.port_max.wrapping_sub(nat.port_min);
    if range == 0 {
        return SnatOutcome::Continue;
    }
    // Past this point SNAT is REQUIRED (external route + a NAT binding with a live port range), so
    // an unkeyable packet may not simply be forwarded — see `SnatOutcome::Untranslatable`.
    let (proto, sport, dport) = match l4_ports(pkt, ip_off) {
        Some(v) => v,
        None => return SnatOutcome::Untranslatable,
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
    let nat_port = match maps.conntrack_get(&fwd_key) {
        // Fast path: established SNAT flow. Reuse the allocated port with no re-derivation.
        Some(v) if v.flags & CT_F_SRC_NAT != 0 => v.xlate_port,
        // No established SNAT flow (or the cached entry doesn't have one): allocate a fresh port
        // from the current `nat` binding (already re-fetched at the top of this fn via `nat_get`;
        // a withdrawn binding returned `None` and we never reached here).
        _ => {
            // Allocate: hash the flow to a start slot, linear-probe for a free reverse key.
            let start = (hash5(&src, &dst, sport, dport, proto) % range as u32) as u16;
            let mut chosen = nat.port_min.wrapping_add(start);
            let mut allocated = false;
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
                if maps.conntrack_get(&rev_key).is_none() {
                    chosen = cand;
                    allocated = true;
                    maps.conntrack_insert(
                        rev_key,
                        CtEntry {
                            last_seen: now,
                            xlate_ip: src,
                            xlate_port: sport,
                            flags: CT_REWRITE_DST | CT_F_SRC_NAT,
                            tcp_state: 0,
                            fwall_action: 0,
                            _pad: [0; 3],
                            // A reply entry: never re-evaluated, so its epoch is never read.
                            policy_epoch: 0,
                        },
                    );
                    break;
                }
                i += 1;
            }
            // Port space exhausted: every probed reverse key is live. `chosen` still holds the
            // initial hash slot, whose reverse entry belongs to ANOTHER flow — emitting it would
            // mis-demux that flow's return traffic. Drop instead of poisoning the table (no fwd
            // entry inserted, no packet rewrite).
            if !allocated {
                return SnatOutcome::Exhausted;
            }
            maps.conntrack_insert(
                fwd_key,
                CtEntry {
                    last_seen: now,
                    xlate_ip: nat.nat_ipv4,
                    xlate_port: chosen,
                    flags: CT_REWRITE_SRC | CT_F_SRC_NAT,
                    tcp_state: 0,
                    fwall_action: 0,
                    _pad: [0; 3],
                    policy_epoch: epoch,
                },
            );
            chosen
        }
    };

    // Rewrite src IP guest -> nat_ip (+ IP checksum), then the L4 src port / ICMP id -> nat_port.
    // All packet writes use fixed-size `write_array` (single stores) to keep the eBPF bytecode small
    // enough for the XDP verifier's single-function budget on the tc_guest_tx path.
    let ihl = (hdr[0] & 0x0f) as usize * 4;
    // src IP at ip_off + 12.
    if !pkt.write_array(ip_off + 12, &nat.nat_ipv4) {
        return SnatOutcome::Continue;
    }
    // IP header checksum at ip_off + 10.
    if let Some(ipc) = pkt.read_u16_be(ip_off + 10) {
        let new = csum_replace4(ipc, &src, &nat.nat_ipv4);
        pkt.write_array(ip_off + 10, &new.to_be_bytes());
    }
    let l4 = ip_off + ihl;
    // eBPF-verifier seam (wall #3 — variable-offset provenance). `l4 = ip_off + ihl` is a VARIABLE
    // packet offset, so EACH independent `Pkt` read/write re-derives a fresh `data + l4[+k]` packet
    // pointer whose proven range only comes from ITS OWN dominating `start + N > end` check; the
    // verifier cannot correlate a read's proof at `l4` with a separate write's pointer at `l4 + 16`,
    // and rejects the split derivation (`invalid access to packet, R2 off=16 r=0`). The old inline
    // eBPF path avoided this by proving `data + l4 + 18 <= data_end` ONCE and doing every sub-field
    // access against that single wide-range `p + l4` pointer.
    //
    // We reproduce that single-bound shape trait-portably with a READ-MODIFY-WRITE of the whole L4
    // header window: ONE `read_array::<N>(l4)` proves `[l4, l4+N)`, we fold the checksum + patch the
    // port INSIDE the stack-local array, then ONE `write_array::<N>(l4)` re-checks the SAME `[l4,
    // l4+N)` and stores it back. Two accesses, both at base `l4`, each with a single dominating
    // bound — byte-identical to the former inline rewrite (same fields, same checksum ops).
    if proto == IPPROTO_TCP {
        // TCP: sport at l4[0..2], checksum at l4[16..18]. Window = 18 bytes.
        if let Some(mut h) = pkt.read_array::<18>(l4) {
            let c0 = u16::from_be_bytes([h[16], h[17]]);
            let c1 = csum_replace4(c0, &src, &nat.nat_ipv4);
            let c2 = csum_replace2(c1, sport, nat_port);
            h[16..18].copy_from_slice(&c2.to_be_bytes());
            h[0..2].copy_from_slice(&nat_port.to_be_bytes());
            pkt.write_array(l4, &h);
        }
    } else if proto == IPPROTO_UDP {
        // UDP: sport at l4[0..2], checksum at l4[6..8]. A zero UDP checksum stays zero. Window = 8.
        if let Some(mut h) = pkt.read_array::<8>(l4) {
            let c0 = u16::from_be_bytes([h[6], h[7]]);
            if c0 != 0 {
                let c1 = csum_replace4(c0, &src, &nat.nat_ipv4);
                let c2 = csum_replace2(c1, sport, nat_port);
                h[6..8].copy_from_slice(&c2.to_be_bytes());
            }
            h[0..2].copy_from_slice(&nat_port.to_be_bytes());
            pkt.write_array(l4, &h);
        }
    } else if proto == IPPROTO_ICMP {
        // ICMP: checksum at l4[2..4], identifier at l4[4..6]. Address change does not affect it.
        if let Some(mut h) = pkt.read_array::<8>(l4) {
            let c0 = u16::from_be_bytes([h[2], h[3]]);
            let c1 = csum_replace2(c0, sport, nat_port);
            h[2..4].copy_from_slice(&c1.to_be_bytes());
            h[4..6].copy_from_slice(&nat_port.to_be_bytes());
            pkt.write_array(l4, &h);
        }
    }
    SnatOutcome::Continue
}

/// ICMP error types that quote the packet that provoked them: Destination Unreachable (3, which
/// carries the PMTUD Fragmentation-Needed case), Time Exceeded (11), Parameter Problem (12).
const fn is_icmp_error_type(t: u8) -> bool {
    t == 3 || t == 11 || t == 12
}

/// Identify the SNAT flow an inbound IPv4 ICMP **error** belongs to, from the packet it quotes.
///
/// Returns `(nat_ip, nat_port, quoted_proto)` — the public identity the guest's original packet
/// left with — or `None` if this is not a relayable ICMP error.
///
/// The outer header of such an error is `router -> nat_ip` with proto ICMP, so it carries no port:
/// the bytes the plain return path reads as a "port" are the ICMP unused/next-hop-MTU field. The
/// port that identifies the flow is the SOURCE port of the quoted packet, which is the guest's
/// original outbound packet as it appeared post-SNAT. Both the edge's `(nat_ip, port) -> owner`
/// relay and the owner's `(vni, 0, nat_ip, 0, nat_port)` reverse conntrack key must be built from
/// that instead. Callers MUST check the returned `nat_ip` against the outer destination before
/// trusting it — an error quoting somebody else's packet is not evidence about this flow.
///
/// Only TCP/UDP quotes are relayable (a quoted ICMP has no port to demux on), and both the outer and
/// quoted IPv4 headers must be option-free so every offset here is constant. RFC 792 guarantees the
/// 8 ICMP + 20 quoted-IP + 8 quoted-L4 bytes this reads.
///
/// `#[inline(always)]`: reads the packet — out-of-lining a packet-reading subprogram loses the eBPF
/// verifier's pkt-pointer range tracking across the call boundary (same rationale as
/// [`crate::lb::lb_select_forward_icmp_error`]).
#[inline(always)]
pub fn nat_icmp_error_origin<P: Pkt>(pkt: &P, ip_off: usize) -> Option<([u8; 4], u16, u8)> {
    if pkt.read_u8(ip_off)? & 0x0f != 5 || pkt.read_u8(ip_off + 9)? != IPPROTO_ICMP {
        return None;
    }
    let icmp_off = ip_off + 20;
    if !is_icmp_error_type(pkt.read_u8(icmp_off)?) {
        return None;
    }
    // Quoted packet starts after the 8-byte ICMP error header.
    let q = icmp_off + 8;
    if pkt.read_u8(q)? & 0x0f != 5 {
        return None;
    }
    let quoted_proto = pkt.read_u8(q + 9)?;
    if quoted_proto != IPPROTO_TCP && quoted_proto != IPPROTO_UDP {
        return None;
    }
    let quoted_src = pkt.read_array::<4>(q + 12)?;
    let quoted_sport = u16::from_be_bytes(pkt.read_array::<2>(q + 20)?);
    Some((quoted_src, quoted_sport, quoted_proto))
}

/// The port an inbound ICMP **error** should be relayed on, if it quotes a packet sourced from
/// `expect_src` — i.e. from the very `nat_ip` the error is addressed to. `None` when this is not a
/// relayable error or the quote is about some other flow.
///
/// Narrow variant of [`nat_icmp_error_origin`] for the WAN-edge relay, which needs only the port.
/// `#[inline(always)]`: `wan_rx` cannot call an out-of-lined packet-reading subprogram at all — its
/// glue passes raw `data`/`data_end`, and `pkt_end` may not cross a bpf-to-bpf boundary.
#[inline(always)]
pub fn nat_icmp_error_relay_port<P: Pkt>(
    pkt: &P,
    ip_off: usize,
    expect_src: &[u8; 4],
) -> Option<u16> {
    let (quoted_src, quoted_sport, _) = nat_icmp_error_origin(pkt, ip_off)?;
    (quoted_src == *expect_src).then_some(quoted_sport)
}

/// v6 sibling of [`nat_icmp_error_relay_port`]. Compares the quoted source a 4-byte word at a time
/// against constant offsets rather than reading it into a `[u8; 16]`, so `wan_rx`'s frame never
/// holds the address — it has no room for one (and cannot out-of-line this; see the v4 fn).
#[inline(always)]
pub fn nat_icmp_error_relay_port6<P: Pkt>(
    pkt: &P,
    ip_off: usize,
    expect_src: &[u8; 16],
) -> Option<u16> {
    if pkt.read_u8(ip_off + 6)? != IPPROTO_ICMPV6 {
        return None;
    }
    let icmp_off = ip_off + 40;
    if !is_icmpv6_error_type(pkt.read_u8(icmp_off)?) {
        return None;
    }
    let q = icmp_off + 8;
    let quoted_next_hdr = pkt.read_u8(q + 6)?;
    if quoted_next_hdr != IPPROTO_TCP && quoted_next_hdr != IPPROTO_UDP {
        return None;
    }
    // Unrolled word compare: four constant-offset 4-byte reads, never a 16-byte local.
    let mut i = 0usize;
    while i < 16 {
        let w = pkt.read_array::<4>(q + 8 + i)?;
        if w[0] != expect_src[i]
            || w[1] != expect_src[i + 1]
            || w[2] != expect_src[i + 2]
            || w[3] != expect_src[i + 3]
        {
            return None;
        }
        i += 4;
    }
    Some(u16::from_be_bytes(pkt.read_array::<2>(q + 40)?))
}

/// Reverse-translate an inbound IPv4 ICMP **error** for a SNATed flow, in place, so the guest that
/// owns the flow can act on it (RFC 5508 §3.2). Returns false (caller drops) if the packet is not
/// shaped as [`nat_icmp_error_origin`] requires.
///
/// Two copies of the public address have to change, not one:
///   - the OUTER destination (`nat_ip` -> the guest's overlay IP), or the frame cannot be delivered;
///   - the QUOTED source and source port (`nat_ip:nat_port` -> the guest's real address:port),
///     because the guest's stack matches an ICMP error to a socket by the quoted 4-tuple. Leaving
///     the quoted copy public makes the guest discard the error, which is the PMTUD black hole.
///
/// Checksums, all folded incrementally: the outer IPv4 header's own; the quoted IPv4 header's own;
/// and the ICMP checksum, which covers the entire quoted packet — so it absorbs the quoted address
/// delta, the quoted port delta, AND the delta of the quoted header checksum that itself just
/// changed. A quoted UDP checksum is updated too (it sits inside the guaranteed 8 quoted L4 bytes
/// and covers the src address via its pseudo-header); a quoted TCP checksum lives at quoted-L4 +16,
/// beyond the guaranteed quote, and is left alone — receivers do not verify a quoted checksum.
///
/// One 36-byte read-modify-write window over `[ICMP(8)][quoted IP(20)][quoted L4(8)]` keeps every
/// access at a constant offset off a single proven bound, the same idiom as [`snat_egress`].
#[inline(always)]
pub fn nat_icmp_error_return_rewrite<P: Pkt>(pkt: &mut P, ip_off: usize, e: &CtEntry) -> bool {
    let (_, _, quoted_proto) = match nat_icmp_error_origin(&*pkt, ip_off) {
        Some(v) => v,
        None => return false,
    };
    let new_ip = e.xlate_ip;
    let new_port = e.xlate_port;

    // --- outer IPv4 header: dst nat_ip -> guest, folded into its own checksum.
    let mut outer = match pkt.read_array::<20>(ip_off) {
        Some(h) => h,
        None => return false,
    };
    let old_dst: [u8; 4] = [outer[16], outer[17], outer[18], outer[19]];
    let outer_c = u16::from_be_bytes([outer[10], outer[11]]);
    outer[10..12].copy_from_slice(&csum_replace4(outer_c, &old_dst, &new_ip).to_be_bytes());
    outer[16..20].copy_from_slice(&new_ip);
    if !pkt.write_array(ip_off, &outer) {
        return false;
    }

    // --- ICMP header + quoted packet, as one window. Offsets within it:
    //     [0..8] ICMP error header (checksum @ 2), [8..28] quoted IPv4 (checksum @ 18, src @ 20),
    //     [28..36] quoted L4 (sport @ 28, UDP checksum @ 34).
    let icmp_off = ip_off + 20;
    let mut w = match pkt.read_array::<36>(icmp_off) {
        Some(h) => h,
        None => return false,
    };
    let old_src: [u8; 4] = [w[20], w[21], w[22], w[23]];
    let old_sport = u16::from_be_bytes([w[28], w[29]]);
    let mut icmp_c = u16::from_be_bytes([w[2], w[3]]);

    // The quoted IPv4 header's own checksum, and that change folded into the ICMP checksum since
    // those two bytes are themselves part of the ICMP-covered region.
    let q_old_c = u16::from_be_bytes([w[18], w[19]]);
    let q_new_c = csum_replace4(q_old_c, &old_src, &new_ip);
    icmp_c = csum_replace2(icmp_c, q_old_c, q_new_c);
    // The quoted address and port changes themselves.
    icmp_c = csum_replace4(icmp_c, &old_src, &new_ip);
    icmp_c = csum_replace2(icmp_c, old_sport, new_port);
    // A quoted UDP checksum covers the quoted src (pseudo-header) and sport; zero means "not
    // computed" and must stay zero.
    if quoted_proto == IPPROTO_UDP {
        let u_old = u16::from_be_bytes([w[34], w[35]]);
        if u_old != 0 {
            let u_new = csum_replace2(csum_replace4(u_old, &old_src, &new_ip), old_sport, new_port);
            icmp_c = csum_replace2(icmp_c, u_old, u_new);
            w[34..36].copy_from_slice(&u_new.to_be_bytes());
        }
    }

    w[2..4].copy_from_slice(&icmp_c.to_be_bytes());
    w[18..20].copy_from_slice(&q_new_c.to_be_bytes());
    w[20..24].copy_from_slice(&new_ip);
    w[28..30].copy_from_slice(&new_port.to_be_bytes());
    pkt.write_array(icmp_off, &w)
}

/// ICMPv6 error types that quote the packet that provoked them: Destination Unreachable (1),
/// Packet Too Big (2, the PMTUD case), Time Exceeded (3), Parameter Problem (4).
const fn is_icmpv6_error_type(t: u8) -> bool {
    t == 1 || t == 2 || t == 3 || t == 4
}

/// Identify the NAT66 flow an inbound ICMPv6 **error** belongs to, from the packet it quotes.
/// v6 sibling of [`nat_icmp_error_origin`] — see that for why the outer header cannot supply the
/// port (here `l4_ports_v6`' ICMPv6 arm reads what is really the Packet-Too-Big MTU as an "id").
/// Returns `(nat_ip6, nat_port, quoted_next_hdr)`; callers MUST check the returned address against
/// the outer destination before trusting it.
///
/// No IPv6 extension headers are assumed on either the outer or the quoted header, matching the
/// rest of the v6 datapath, so every offset here is constant.
#[inline(always)]
pub fn nat_icmp_error_origin6<P: Pkt>(pkt: &P, ip_off: usize) -> Option<([u8; 16], u16, u8)> {
    if pkt.read_u8(ip_off + 6)? != IPPROTO_ICMPV6 {
        return None;
    }
    let icmp_off = ip_off + 40;
    if !is_icmpv6_error_type(pkt.read_u8(icmp_off)?) {
        return None;
    }
    // Quoted packet starts after the 8-byte ICMPv6 error header.
    let q = icmp_off + 8;
    let quoted_next_hdr = pkt.read_u8(q + 6)?;
    if quoted_next_hdr != IPPROTO_TCP && quoted_next_hdr != IPPROTO_UDP {
        return None;
    }
    let quoted_src = pkt.read_array::<16>(q + 8)?;
    let quoted_sport = u16::from_be_bytes(pkt.read_array::<2>(q + 40)?);
    Some((quoted_src, quoted_sport, quoted_next_hdr))
}

/// Reverse-translate an inbound ICMPv6 **error** for a NAT66 flow, in place, so the guest that owns
/// the flow can act on it. v6 sibling of [`nat_icmp_error_return_rewrite`]: the outer destination
/// AND the quoted source/source-port all have to change, for the same reasons.
///
/// The checksum work differs from v4 in both directions. An IPv6 header has no checksum of its own,
/// so neither the outer nor the quoted header needs one fixed — but the ICMPv6 checksum covers a
/// PSEUDO-HEADER that includes the outer source and destination, so rewriting the outer dst changes
/// it, where the v4 ICMP checksum was indifferent to the addresses. Net: fold the outer-dst delta,
/// the quoted-src delta, and the quoted-port delta, plus a quoted UDP checksum if one is present.
///
/// `#[inline(never)]`: the v6 uplink path is the one under real pressure against the verifier's
/// 512-byte combined-stack limit (see [`snat_egress6`] and `nat_return_rewrite6`). Packet access
/// goes through the `Pkt` re-derive-bounds seam, so an out-of-lined frame costs no pkt-pointer
/// provenance.
///
/// Deliberately does NOT use the one-big-window read-modify-write idiom the v4 sibling and
/// [`snat_egress6`] use. A 56-byte window covering `[ICMPv6][quoted IPv6][quoted L4]`, live at the
/// same time as the two 16-byte addresses the checksum folds need, put `xdp_uplink_v6` 64 bytes
/// over the limit (`combined stack size of 3 calls is 576`). Instead each field is read, folded and
/// written in turn so only ONE old address is live at a time; the extra bounds checks are cheap
/// next to the frame budget. Consequently the ORDER below is load-bearing: the quoted UDP checksum
/// is folded first, while the quoted address and port it depends on are still live.
#[inline(never)]
pub fn nat_icmp_error_return_rewrite6<P: Pkt>(pkt: &mut P, ip_off: usize, e: &CtEntry6) -> bool {
    let (_, _, quoted_next_hdr) = match nat_icmp_error_origin6(&*pkt, ip_off) {
        Some(v) => v,
        None => return false,
    };
    let new_port = e.xlate_port;
    let icmp_off = ip_off + 40;
    let q = icmp_off + 8;

    let mut icmp_c = match pkt.read_u16_be(icmp_off + 2) {
        Some(c) => c,
        None => return false,
    };
    let old_sport = match pkt.read_u16_be(q + 40) {
        Some(p) => p,
        None => return false,
    };

    {
        // Quoted source: fold it (and anything that depends on it) before it goes out of scope.
        let old_src = match pkt.read_array::<16>(q + 8) {
            Some(a) => a,
            None => return false,
        };
        // A quoted UDP checksum covers the quoted src (via its pseudo-header) and sport; zero
        // means "not computed" and must stay zero. Folded FIRST — it needs both old values.
        if quoted_next_hdr == IPPROTO_UDP {
            if let Some(u_old) = pkt.read_u16_be(q + 46) {
                if u_old != 0 {
                    let u_new = csum_replace2(
                        csum_replace16(u_old, &old_src, &e.xlate_ip6),
                        old_sport,
                        new_port,
                    );
                    icmp_c = csum_replace2(icmp_c, u_old, u_new);
                    if !pkt.write_array(q + 46, &u_new.to_be_bytes()) {
                        return false;
                    }
                }
            }
        }
        icmp_c = csum_replace16(icmp_c, &old_src, &e.xlate_ip6);
        if !pkt.write_array(q + 8, &e.xlate_ip6) {
            return false;
        }
    }

    icmp_c = csum_replace2(icmp_c, old_sport, new_port);
    if !pkt.write_array(q + 40, &new_port.to_be_bytes()) {
        return false;
    }

    {
        // The outer dst is not part of the ICMPv6 message, but it IS part of the pseudo-header the
        // ICMPv6 checksum covers — so its delta has to be folded too (no v4 analogue).
        let old_dst = match pkt.read_array::<16>(ip_off + 24) {
            Some(a) => a,
            None => return false,
        };
        icmp_c = csum_replace16(icmp_c, &old_dst, &e.xlate_ip6);
        if !pkt.write_array(ip_off + 24, &e.xlate_ip6) {
            return false;
        }
    }

    pkt.write_array(icmp_off + 2, &icmp_c.to_be_bytes())
}

/// Reverse-DNAT a NAT66 return packet in place: inner DST IPv6 (the public `nat_ip6`) -> the reverse
/// entry's `xlate_ip6` (the guest's overlay IP) and the L4 DST port (`nat_port`) -> `xlate_port`,
/// folding BOTH the 16-byte address delta ([`csum_replace16`]) and the port delta (`csum_replace2`)
/// into the L4 checksum. The v6 sibling of `conntrack::ct_apply`'s `CT_REWRITE_DST` arm; same
/// single-bound read-modify-write window shape as [`snat_egress6`], on DST offsets (addr @ ip_off+24,
/// TCP/UDP dport @ l4+2, ICMPv6 echo id @ l4+4). `e` is the matched reverse `NAT_CT6` entry.
// #[inline(never)]: its own BPF frame (old_dst[16] + the L4 window) so the caller `nat_return_dnat6`'s
// dead `CtKey6`/`CtEntry6` slots free before this runs — trimming the v6 uplink combined stack under
// the 512B verifier limit. v6-only (only `nat_return_dnat6` calls it). pkt via the RawPkt
// re-derive-bounds seam → no `R2 pkt_end` wall.
#[inline(never)]
pub fn nat_return_rewrite6<P: Pkt>(pkt: &mut P, ip_off: usize, e: &CtEntry6) {
    let old_dst = match pkt.read_array::<16>(ip_off + 24) {
        Some(a) => a,
        None => return,
    };
    let proto = pkt.read_u8(ip_off + 6).unwrap_or(0);
    if !pkt.write_array(ip_off + 24, &e.xlate_ip6) {
        return;
    }
    let l4 = ip_off + 40;
    if proto == IPPROTO_TCP {
        if let Some(mut h) = pkt.read_array::<18>(l4) {
            let c0 = u16::from_be_bytes([h[16], h[17]]);
            let dport = u16::from_be_bytes([h[2], h[3]]);
            let c1 = csum_replace16(c0, &old_dst, &e.xlate_ip6);
            let c2 = csum_replace2(c1, dport, e.xlate_port);
            h[16..18].copy_from_slice(&c2.to_be_bytes());
            h[2..4].copy_from_slice(&e.xlate_port.to_be_bytes());
            pkt.write_array(l4, &h);
        }
    } else if proto == IPPROTO_UDP {
        if let Some(mut h) = pkt.read_array::<8>(l4) {
            let c0 = u16::from_be_bytes([h[6], h[7]]);
            let dport = u16::from_be_bytes([h[2], h[3]]);
            if c0 != 0 {
                let c1 = csum_replace16(c0, &old_dst, &e.xlate_ip6);
                let c2 = csum_replace2(c1, dport, e.xlate_port);
                h[6..8].copy_from_slice(&c2.to_be_bytes());
            }
            h[2..4].copy_from_slice(&e.xlate_port.to_be_bytes());
            pkt.write_array(l4, &h);
        }
    } else if proto == IPPROTO_ICMPV6 {
        if let Some(mut h) = pkt.read_array::<8>(l4) {
            let c0 = u16::from_be_bytes([h[2], h[3]]);
            let id = u16::from_be_bytes([h[4], h[5]]);
            let c1 = csum_replace16(c0, &old_dst, &e.xlate_ip6);
            let c2 = csum_replace2(c1, id, e.xlate_port);
            h[2..4].copy_from_slice(&c2.to_be_bytes());
            h[4..6].copy_from_slice(&e.xlate_port.to_be_bytes());
            pkt.write_array(l4, &h);
        }
    }
}

/// Pick the NAT66 source port for a flow: reuse the established forward `NAT_CT6` entry, else
/// hash-start + linear-probe a free peer-independent reverse key and pin both entries. Returns the
/// chosen port, or `None` when the block is exhausted. `#[inline(never)]` + pkt-FREE (all inputs by
/// value) so its `CtKey6`/`CtEntry6` stack locals get their OWN BPF frame — see `snat_egress6`'s call
/// site for why (512B per-frame verifier limit). Not called by the sim directly; exercised via
/// `snat_egress6`.
#[inline(never)]
fn snat6_pick_port<M: Maps>(maps: &mut M, fwd: &CtKey6, nat: &NatValue6, now: u64) -> Option<u16> {
    if let Some(v) = maps.nat_ct6_get(fwd) {
        if v.flags & CT_F_SRC_NAT != 0 {
            return Some(v.xlate_port);
        }
    }
    let range = nat.port_max.wrapping_sub(nat.port_min);
    // A zero-width block has no ports to hand out. Return early BEFORE the `% range` below: it both
    // handles the degenerate config AND proves `range != 0` to the compiler, so the modulo emits no
    // divide-by-zero panic branch. A cold `panic` block (a call to a `-> !` handler, no `exit`) laid
    // out last would make the appended `.text` subprogram end on a non-exit insn — the BPF verifier
    // rejects that with "last insn is not an exit or jmp".
    if range == 0 {
        return None;
    }
    let start = (hash_v6(
        &fwd.src_ip,
        &fwd.dst_ip,
        fwd.src_port,
        fwd.dst_port,
        fwd.proto,
    ) % range as u32) as u16;
    let mut i: u16 = 0;
    while i < PROBE_LIMIT {
        let cand = nat.port_min.wrapping_add((start.wrapping_add(i)) % range);
        let rev_key = CtKey6 {
            vni: fwd.vni,
            src_ip: [0; 16],
            dst_ip: nat.nat_ipv6,
            src_port: 0,
            dst_port: cand,
            proto: fwd.proto,
            _pad: [0; 3],
        };
        if maps.nat_ct6_get(&rev_key).is_none() {
            // ONE `CtEntry6` buffer, mutated between the two inserts (reverse then forward), so only a
            // single 32B entry lives on this frame instead of two — trimming the v6 combined stack.
            let mut ent = CtEntry6 {
                last_seen: now,
                xlate_ip6: fwd.src_ip,
                xlate_port: fwd.src_port,
                flags: CT_REWRITE_DST | CT_F_SRC_NAT,
                tcp_state: 0,
                _pad: [0; 4],
            };
            maps.nat_ct6_insert(rev_key, ent);
            ent.xlate_ip6 = nat.nat_ipv6;
            ent.xlate_port = cand;
            ent.flags = CT_REWRITE_SRC | CT_F_SRC_NAT;
            maps.nat_ct6_insert(*fwd, ent);
            return Some(cand);
        }
        i = i.wrapping_add(1);
    }
    None
}

/// NAT66 egress SNAT — the v6 sibling of [`snat_egress`]. If `is_external` and the guest
/// `(vni, src-ipv6)` has a NAT66 config (`nat_get6`), allocate a source port (reusing the forward
/// `NAT_CT6` entry for an established flow), rewrite the inner src IPv6 -> `nat_ipv6` and the L4 src
/// port / ICMPv6 id -> `nat_port`, and pin the forward + peer-independent reverse conntrack. Returns
/// [`SnatOutcome::Exhausted`] (caller drops) if no free port. v6 deltas vs the v4 twin: fixed 40-byte
/// header (no IHL, no IP checksum — IPv6 has none), the src-address delta is folded into the L4
/// checksum via [`csum_replace16`] (the v6 pseudo-header includes the src addr — for TCP, UDP AND
/// ICMPv6), and the conntrack lives in the dedicated `NAT_CT6` map (`CtKey6`->`CtEntry6`).
#[inline(always)]
pub fn snat_egress6<P: Pkt, M: Maps>(
    pkt: &mut P,
    maps: &mut M,
    ip_off: usize,
    vni: u32,
    is_external: bool,
    now: u64,
) -> SnatOutcome {
    if !is_external {
        return SnatOutcome::Continue;
    }
    // Read src/dst as two 16-byte fields (NOT a 40-byte header buffer) to keep this frame's stack
    // small — the eBPF verifier's 512B per-frame limit is tight for v6 (see snat6_pick_port).
    let src = match pkt.read_array::<16>(ip_off + 8) {
        Some(s) => s,
        None => return SnatOutcome::Continue,
    };
    let nat = match maps.nat_get6(&NatKey6 { vni, ipv6: src }) {
        Some(v) => v,
        None => return SnatOutcome::Continue,
    };
    let range = nat.port_max.wrapping_sub(nat.port_min);
    if range == 0 {
        return SnatOutcome::Continue;
    }
    let (proto, sport, dport) = match l4_ports_v6(pkt, ip_off) {
        Some(v) => v,
        None => return SnatOutcome::Continue,
    };

    // Port pick + conntrack in a SEPARATE #[inline(never)], pkt-FREE subprogram: its `CtKey6`
    // (44B) rev-key + `CtEntry6` (32B) locals live in their own BPF frame, freed before the rewrite
    // below — without this the combined footprint (v6 is ~2x v4's) blows the 512B per-frame limit
    // (LLVM `bpf-stack-size` error). The whole flow tuple is bundled into the forward `CtKey6` so the
    // helper takes only 4 register args (BPF passes ≤5 args in regs, no stack args). pkt-free (all
    // inputs by value/ref) → no `R2 pkt_end` provenance wall across the call boundary.
    // Read the inner dst directly into the key (no standalone `dst` local — its 16B would otherwise
    // sit on this frame alongside `fwd_key.dst_ip`, and this frame's combined stack with
    // `snat6_pick_port` is right at the 512B verifier limit).
    let dst = match pkt.read_array::<16>(ip_off + 24) {
        Some(d) => d,
        None => return SnatOutcome::Continue,
    };
    let fwd_key = CtKey6 {
        vni,
        src_ip: src,
        dst_ip: dst,
        src_port: sport,
        dst_port: dport,
        proto,
        _pad: [0; 3],
    };
    let nat_port = match snat6_pick_port(maps, &fwd_key, &nat, now) {
        Some(p) => p,
        None => return SnatOutcome::Exhausted,
    };

    // Rewrite in a SEPARATE #[inline(never)] pkt frame (its L4 read-modify-write window lives there,
    // not here) — sequential with snat6_pick_port, so it does not stack ON it. Together the two splits
    // keep the v6 SNAT combined stack under the 512B verifier limit.
    snat6_apply_rewrite(pkt, ip_off, &fwd_key, &nat, nat_port);
    SnatOutcome::Continue
}

/// The src-IPv6 + L4 rewrite tail of [`snat_egress6`], out-of-lined into its OWN `#[inline(never)]`
/// BPF frame (holds the L4 read-modify-write window). Runs AFTER `snat6_pick_port` returns, so the two
/// heavy frames are sequential (not nested) on the verifier's combined-stack accounting. Args are
/// bundled into `&fwd_key` (carries the original src/sport/proto) + `&nat` (nat_ipv6) so the helper
/// takes ≤5 register args (BPF passes no stack args). pkt via the RawPkt re-derive-bounds seam → no
/// `R2 pkt_end` wall across the call.
#[inline(never)]
fn snat6_apply_rewrite<P: Pkt>(
    pkt: &mut P,
    ip_off: usize,
    fwd: &CtKey6,
    nat: &NatValue6,
    nat_port: u16,
) {
    let src = fwd.src_ip;
    let sport = fwd.src_port;
    let proto = fwd.proto;
    // Rewrite src IPv6 -> nat_ipv6 (no IP checksum in v6), then the L4 src port -> nat_port, folding
    // BOTH the 16-byte address delta (csum_replace16) and the port delta (csum_replace2) into the L4
    // checksum. Single-bound read-modify-write windows, like the v4 twin.
    if !pkt.write_array(ip_off + 8, &nat.nat_ipv6) {
        return;
    }
    let l4 = ip_off + 40;
    if proto == IPPROTO_TCP {
        // TCP: sport at l4[0..2], checksum at l4[16..18], 16 bytes apart. Two 2-byte windows (not one
        // 18-byte buffer) to keep this frame small — the checksum fold needs only the old cksum word.
        if let Some(c) = pkt.read_array::<2>(l4 + 16) {
            let c0 = u16::from_be_bytes(c);
            let c1 = csum_replace16(c0, &src, &nat.nat_ipv6);
            let c2 = csum_replace2(c1, sport, nat_port);
            pkt.write_array(l4 + 16, &c2.to_be_bytes());
            pkt.write_array(l4, &nat_port.to_be_bytes());
        }
    } else if proto == IPPROTO_UDP {
        // UDP: sport at l4[0..2], checksum at l4[6..8] (mandatory/non-zero in v6). Window = 8.
        if let Some(mut h) = pkt.read_array::<8>(l4) {
            let c0 = u16::from_be_bytes([h[6], h[7]]);
            if c0 != 0 {
                let c1 = csum_replace16(c0, &src, &nat.nat_ipv6);
                let c2 = csum_replace2(c1, sport, nat_port);
                h[6..8].copy_from_slice(&c2.to_be_bytes());
            }
            h[0..2].copy_from_slice(&nat_port.to_be_bytes());
            pkt.write_array(l4, &h);
        }
    } else if proto == IPPROTO_ICMPV6 {
        // ICMPv6: checksum at l4[2..4], echo id at l4[4..6]. The ICMPv6 checksum COVERS the v6
        // pseudo-header, so the src-address change must be folded in (unlike ICMPv4). sport == the id.
        if let Some(mut h) = pkt.read_array::<8>(l4) {
            let c0 = u16::from_be_bytes([h[2], h[3]]);
            let c1 = csum_replace16(c0, &src, &nat.nat_ipv6);
            let c2 = csum_replace2(c1, sport, nat_port);
            h[2..4].copy_from_slice(&c2.to_be_bytes());
            h[4..6].copy_from_slice(&nat_port.to_be_bytes());
            pkt.write_array(l4, &h);
        }
    }
}
