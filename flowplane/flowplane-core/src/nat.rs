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
}

/// Egress network SNAT. If `is_external` and the guest `(vni, src)` has a NAT config, allocate a
/// source port (reusing the forward-conntrack port if the flow is already tracked), rewrite the
/// inner src IP -> `nat_ip` and the L4 src port / ICMP id -> `nat_port` (+checksums), and pin the
/// forward + reverse conntrack entries. Returns [`SnatOutcome::Exhausted`] (caller drops) if no
/// free port could be allocated; otherwise [`SnatOutcome::Continue`].
///
/// `ip_off` is the offset of the inner IPv4 header (e.g. `ETH_LEN` for a guest Ethernet frame).
/// `now` is the monotonic time (ns) written into the conntrack `last_seen` field (eBPF: `now()`,
/// sim: `0`). Byte-identical to the eBPF `nat::nat_snat_egress`.
#[inline(always)]
pub fn snat_egress<P: Pkt, M: Maps>(
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
    let (proto, sport, dport) = match l4_ports(pkt, ip_off) {
        Some(v) => v,
        None => return SnatOutcome::Continue,
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
                            _pad: [0; 7],
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
                    _pad: [0; 7],
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
