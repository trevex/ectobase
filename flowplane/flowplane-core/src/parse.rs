//! Pure IPv4 parse helpers rewritten over the `Pkt` trait (no raw pointers). Faithful ports of the
//! eBPF `parse::l4_ports` / `firewall::icmp_type_code`. `PacketSelectors` and `fw_rule_matches` are
//! single-sourced in `flowplane-common` and re-exported here for the core firewall evaluator.

use crate::pkt::Pkt;

pub use flowplane_common::{fw_rule_matches, PacketSelectors};

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Read the L4 "ports" for a parsed IPv4 packet at `ip_off`. For TCP/UDP returns (proto,sport,dport)
/// with ports in host order; for ICMP returns (proto,id,id). Returns None if out of bounds /
/// unsupported. Faithful port of the eBPF `parse::l4_ports`.
#[inline(always)]
pub fn l4_ports<P: Pkt>(pkt: &P, ip_off: usize) -> Option<(u8, u16, u16)> {
    // Faithful to the eBPF bound `data + ip_off + 20 > data_end`: the full 20-byte IPv4 header
    // must be present before we read IHL/proto.
    let hdr = pkt.read_array::<20>(ip_off)?;
    let ihl = (hdr[0] & 0x0f) as usize * 4;
    let proto = hdr[9];
    let l4 = ip_off + ihl;
    match proto {
        IPPROTO_TCP | IPPROTO_UDP => {
            let sp = pkt.read_u16_be(l4)?;
            let dp = pkt.read_u16_be(l4 + 2)?;
            Some((proto, sp, dp))
        }
        IPPROTO_ICMP => {
            let id = pkt.read_u16_be(l4 + 4)?;
            Some((proto, id, id))
        }
        _ => None,
    }
}

/// FNV-1a offset basis and prime, single-sourced so the array-based [`hash5`]/[`hash_v6`] and the
/// streaming [`inner_flow_label`] fold produce byte-identical results (see `flow_label_test.rs`).
const FNV_OFFSET: u32 = 2166136261;
const FNV_PRIME: u32 = 16777619;

/// One FNV-1a-ish fold step. `#[inline(always)]` — costs no stack frame of its own.
#[inline(always)]
fn fnv_step(h: u32, b: u8) -> u32 {
    (h ^ b as u32).wrapping_mul(FNV_PRIME)
}

/// Fold the 16-bit `v` (host order) low-then-high byte, matching how [`hash5`]/[`hash_v6`] absorb
/// L4 ports.
#[inline(always)]
fn fnv_u16(h: u32, v: u16) -> u32 {
    fnv_step(fnv_step(h, v as u8), (v >> 8) as u8)
}

/// Stable 5-tuple hash (FNV-1a-ish) for Maglev slot selection.
/// Loops are fully unrolled to satisfy the BPF verifier (no iterator-based loops).
#[inline(always)]
pub fn hash5(src: &[u8; 4], dst: &[u8; 4], sport: u16, dport: u16, proto: u8) -> u32 {
    let mut h = FNV_OFFSET;
    // Unroll src[0..4] and dst[0..4] explicitly — iterator-based loops over slices
    // confuse the BPF verifier into thinking the loop may be unbounded.
    h = fnv_step(h, src[0]);
    h = fnv_step(h, src[1]);
    h = fnv_step(h, src[2]);
    h = fnv_step(h, src[3]);
    h = fnv_step(h, dst[0]);
    h = fnv_step(h, dst[1]);
    h = fnv_step(h, dst[2]);
    h = fnv_step(h, dst[3]);
    h = fnv_u16(h, sport);
    h = fnv_u16(h, dport);
    fnv_step(h, proto)
}

/// Stable 5-tuple hash for an IPv6 inner flow (FNV-1a-ish), mirroring [`hash5`] over 16-byte
/// addresses. Fully unrolled to satisfy the BPF verifier.
#[inline(always)]
pub fn hash_v6(src: &[u8; 16], dst: &[u8; 16], sport: u16, dport: u16, proto: u8) -> u32 {
    let mut h = FNV_OFFSET;
    let mut i = 0;
    // 16 iterations is a fixed, verifier-provable bound (not slice-iterator based).
    while i < 16 {
        h = fnv_step(h, src[i]);
        h = fnv_step(h, dst[i]);
        i += 1;
    }
    h = fnv_u16(h, sport);
    h = fnv_u16(h, dport);
    fnv_step(h, proto)
}

/// Fold one 4-byte source-address word interleaved with the matching destination word — matching
/// [`hash_v6`]'s `src[i], dst[i]` absorption order — without ever holding a 16-byte address array on
/// the stack. Constant `soff`/`doff` (one bounds check each), so no variable-offset packet read.
#[inline(always)]
fn fold_addr_word<P: Pkt>(h: u32, pkt: &P, soff: usize, doff: usize) -> Option<u32> {
    let s = pkt.read_array::<4>(soff)?;
    let d = pkt.read_array::<4>(doff)?;
    let mut h = h;
    h = fnv_step(h, s[0]);
    h = fnv_step(h, d[0]);
    h = fnv_step(h, s[1]);
    h = fnv_step(h, d[1]);
    h = fnv_step(h, s[2]);
    h = fnv_step(h, d[2]);
    h = fnv_step(h, s[3]);
    h = fnv_step(h, d[3]);
    Some(h)
}

/// Streaming equivalent of `flow_label20(hash_v6(..))` for an inner IPv6 packet. `None` on OOB.
#[inline(always)]
fn inner_flow_hash_v6<P: Pkt>(pkt: &P, ip_off: usize) -> Option<u32> {
    let mut h = FNV_OFFSET;
    // src[i], dst[i] interleaved for i in 0..16, streamed a word at a time (constant offsets). The
    // four src reads span ip_off+8..24 and the four dst reads span ip_off+24..40 — the SAME bytes
    // and bounds as the original `read_array::<16>` pair, so OOB behaviour is identical.
    h = fold_addr_word(h, pkt, ip_off + 8, ip_off + 24)?;
    h = fold_addr_word(h, pkt, ip_off + 12, ip_off + 28)?;
    h = fold_addr_word(h, pkt, ip_off + 16, ip_off + 32)?;
    h = fold_addr_word(h, pkt, ip_off + 20, ip_off + 36)?;
    let nexthdr = pkt.read_u8(ip_off + 6)?;
    let (sport, dport) = match nexthdr {
        IPPROTO_TCP | IPPROTO_UDP => (
            pkt.read_u16_be(ip_off + 40).unwrap_or(0),
            pkt.read_u16_be(ip_off + 42).unwrap_or(0),
        ),
        _ => (0, 0),
    };
    h = fnv_u16(h, sport);
    h = fnv_u16(h, dport);
    Some(fnv_step(h, nexthdr))
}

/// Streaming equivalent of `flow_label20(hash5(..))` for an inner IPv4 packet. `None` on OOB.
#[inline(always)]
fn inner_flow_hash_v4<P: Pkt>(pkt: &P, ip_off: usize) -> Option<u32> {
    let mut h = FNV_OFFSET;
    // hash5 order: src[0..4] then dst[0..4] (NOT interleaved), then ports + proto.
    let src = pkt.read_array::<4>(ip_off + 12)?;
    h = fnv_step(h, src[0]);
    h = fnv_step(h, src[1]);
    h = fnv_step(h, src[2]);
    h = fnv_step(h, src[3]);
    let dst = pkt.read_array::<4>(ip_off + 16)?;
    h = fnv_step(h, dst[0]);
    h = fnv_step(h, dst[1]);
    h = fnv_step(h, dst[2]);
    h = fnv_step(h, dst[3]);
    // l4_ports handles IHL/proto; fall back to (proto,0,0) for non-TCP/UDP or OOB L4.
    let proto = pkt.read_u8(ip_off + 9).unwrap_or(0);
    let (proto, sport, dport) = l4_ports(pkt, ip_off).unwrap_or((proto, 0, 0));
    h = fnv_u16(h, sport);
    h = fnv_u16(h, dport);
    Some(fnv_step(h, proto))
}

/// Compute the 20-bit outer IPv6 flow label from an inner IP packet at `ip_off` (RFC 6438 fabric
/// ECMP entropy). `is_v6` selects inner IPv6 vs IPv4 parsing. Returns 0 on out-of-bounds so a
/// short/unparseable inner just yields "no ECMP hint" rather than dropping. Read via the `Pkt`
/// trait so the eBPF datapath and the native sim compute an identical label for the same bytes.
///
/// The 5-tuple is streamed word-by-word (see [`inner_flow_hash_v6`]/[`inner_flow_hash_v4`]) instead
/// of materializing address arrays: this runs in a subprogram called from the stack-heavy
/// `tc_guest_tx`, and the combined call-chain frame must stay under the 512B BPF limit.
#[inline(always)]
pub fn inner_flow_label<P: Pkt>(pkt: &P, ip_off: usize, is_v6: bool) -> u32 {
    let hash = if is_v6 {
        inner_flow_hash_v6(pkt, ip_off)
    } else {
        inner_flow_hash_v4(pkt, ip_off)
    };
    match hash {
        Some(h) => flow_label20(h),
        None => 0,
    }
}

/// Fold a 32-bit flow hash into a 20-bit IPv6 flow label (RFC 6437/6438 tunnel entropy). XOR-folds
/// the high 12 bits back in so high-entropy hashes don't collide on their low 20 bits, then masks
/// to 20 bits so the value never bleeds into the IPv6 version/traffic-class nibble.
#[inline(always)]
pub fn flow_label20(h: u32) -> u32 {
    (h ^ (h >> 20)) & 0x000F_FFFF
}

/// Extract ICMP (type, code) for an IPv4 packet at `ip_off` (0,0 if not ICMP / OOB / has options).
/// Faithful port of the eBPF `firewall::icmp_type_code`.
#[inline(always)]
pub fn icmp_type_code<P: Pkt>(pkt: &P, ip_off: usize) -> (u16, u16) {
    // Faithful to the eBPF bound `data + ip_off + 20 > data_end`.
    let hdr = match pkt.read_array::<20>(ip_off) {
        Some(h) => h,
        None => return (0, 0),
    };
    if hdr[0] & 0x0f != 5 || hdr[9] != IPPROTO_ICMP {
        return (0, 0);
    }
    let l4 = ip_off + 20;
    match pkt.read_array::<2>(l4) {
        Some(b) => (b[0] as u16, b[1] as u16),
        None => (0, 0),
    }
}
