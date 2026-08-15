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
use flowplane_common::{CtEntry, CtKey, NatKey, CT_F_SRC_NAT, CT_REWRITE_DST, CT_REWRITE_SRC};

use crate::maps::Maps;
use crate::parse::{hash5, l4_ports, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};
use crate::pkt::Pkt;

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
    // §5a generation-tag invalidation: the config generation the CURRENT nat binding was resolved
    // under. eBPF + sim return 0 (Maps trait default) → every stamped `gen` is 0 and the recheck
    // below is a no-op, so their datapath is byte-identical. For the DPDK serve binary the writer
    // bumps this on any NAT/LB/route withdrawal (conntrack_flush); a cached SNAT entry stamped under
    // an older generation must NOT be reused blindly (the underlying binding may have changed).
    // `CtEntry`'s generation stamp is a `[u8; 4]` accessed as a `u32` via `gen()`/`set_gen()` (stored
    // byte-wise to keep the eBPF map value ABI at 24 bytes / align 8); the shared generation counter
    // is a `u64`. Truncating to `u32` is sound — stamp and compare use the SAME low 32 bits, so a
    // change is always detected (it only wraps after 2^32 withdrawals).
    let cur_gen = maps.config_generation() as u32;
    let nat_port = match maps.conntrack_get(&fwd_key) {
        // Fast path: established SNAT flow whose cached allocation is still valid under the CURRENT
        // generation. Reuse the allocated port with no re-derivation.
        Some(v) if v.flags & CT_F_SRC_NAT != 0 && v.gen() == cur_gen => v.xlate_port,
        // Stale-generation SNAT entry: the config moved since this port was allocated. Fall through
        // to RE-DERIVE the allocation from the current `nat` binding (already re-fetched at the top of
        // this fn via `nat_get`; a withdrawn binding returned `None` and we never reached here). This
        // re-stamps the fwd/rev entries with `cur_gen`, so a changed nat_ipv4/port-range is picked up
        // and the flow can never emit under the withdrawn/old binding.
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
                            gen_bytes: cur_gen.to_ne_bytes(),
                            _pad: [0; 3],
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
                    gen_bytes: cur_gen.to_ne_bytes(),
                    _pad: [0; 3],
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
