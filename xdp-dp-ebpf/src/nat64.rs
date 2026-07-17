/// NAT64: bidirectional translation between IPv6 (64:ff9b::/96 prefix) guests and IPv4 external.
///
/// Egress (guest_tx): an IPv6 frame whose dst is in 64:ff9b::/96 is translated to IPv4 + SNAT'd
/// via the guest's NAT config, then encap'd and forwarded like a normal IPv4 NAT flow.
///
/// Ingress (uplink_rx): an IPv4 reply that was reverse-NAT'd back to the guest IPv4 and carries
/// CT_F_NAT64 in the conntrack entry is translated back to IPv6 and delivered to the VM's tap.
use aya_ebpf::{
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
    programs::XdpContext,
};
use xdp_dp_common::{
    CtEntry, CtKey, NatKey, CT_F_NAT64, CT_F_SRC_NAT, CT_REWRITE_DST, CT_REWRITE_SRC,
};
use xdp_dp_core::err::DpErr;

use crate::maps::{LOCAL, NAT, PORT_META};
use crate::parse::{
    write16, write6, ETH_LEN, ETH_P_IPV6, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, IPV6_LEN,
};

/// Re-export PROBE_LIMIT for port allocation.
use crate::nat::PROBE_LIMIT;

/// ICMPv6 type constants.
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
/// ICMPv4 type constants.
const ICMP_ECHO_REQUEST: u8 = 8;
const IPPROTO_ICMP: u8 = 1;

/// The NAT64 well-known prefix 64:ff9b::/96 — first 12 bytes.
/// Full 16-byte form: [0x00,0x64,0xff,0x9b, 0,0,0,0, 0,0,0,0, v4[0..3]]
const NAT64_PFX: [u8; 12] = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

/// Check if a 16-byte IPv6 address is in the NAT64 well-known prefix 64:ff9b::/96.
/// Fully unrolled for BPF verifier (no loops over slice references).
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

/// Build a 64:ff9b:: IPv6 address embedding a 4-byte IPv4 address.
#[inline(always)]
fn nat64_embed(ipv4: [u8; 4]) -> [u8; 16] {
    [
        0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, ipv4[0], ipv4[1], ipv4[2], ipv4[3],
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Checksum helpers — all operate on fixed-size stack arrays, never on packet
// memory with variable offsets (BPF verifier rejects variable packet offsets).
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

/// Checksum over an 8-byte ICMPv6 echo header with an IPv6 pseudo-header.
/// pseudo-header: src(16) + dst(16) + upper-layer length (4 BE) + zeros(3) + next-header(1).
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
    // fold but don't invert — caller uses this as a partial sum.
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

/// Translate a TCP/UDP checksum from IPv6 pseudo-header to IPv4 pseudo-header using
/// incremental update.  All arguments in network byte order.
///
/// The checksum in the packet was computed with `pseudo_v6(src6, dst6, proto, l4_len)`.
/// After translation the checksum must use `pseudo_v4(src4, dst4, proto, l4_len)`.
///
/// Because ones-complement is commutative, removing the v6 pseudo contribution and adding
/// the v4 pseudo contribution yields the correct new checksum:
///   new_hc = fold( ~old_hc - pseudo_v6 + pseudo_v4 )
/// Using ~(~hc + ~pseudo_v6 + pseudo_v4) = standard RFC 1624 trick applied to 32-bit blocks.
#[inline(always)]
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
    // new_cksum = ~(~HC_old + ~pseudo_v6 + pseudo_v4 + ~old_sport + new_sport)
    let s0 = !u16::from_be(cksum_be) as u32; // ~HC in 16-bit (folded, host order)
    let pv6 = pseudo_v6(src6, dst6, proto, l4_len); // folded to 16-bit
    let pv4 = pseudo_v4(src4, dst4, proto, l4_len); // folded to 16-bit
    let old_sp = !u16::from_be(old_sport_be) as u32;
    let new_sp = u16::from_be(new_sport_be) as u32;
    let mut sum = s0
        .wrapping_add(!pv6 as u16 as u32) // remove v6 pseudo contribution
        .wrapping_add(pv4) // add v4 pseudo contribution
        .wrapping_add(old_sp) // remove old sport
        .wrapping_add(new_sp); // add new sport
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    (!(sum as u16)).to_be()
}

/// Translate a TCP/UDP checksum from IPv4 pseudo-header to IPv6 pseudo-header.
/// The port fields are assumed unchanged (already handled by ct_apply before calling this).
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
// EGRESS: IPv6→IPv4 translation + SNAT
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt NAT64 egress translation for the packet in `ctx`.
///
/// Packet layout on entry: `Eth(14) + IPv6(40) + L4(...)` — the raw guest TX frame.
/// `vni`: guest VNI. `meta_guest_ipv4`: guest's IPv4 from PORT_META (NAT map key).
/// `meta_underlay_ipv6`: guest's underlay IPv6 (used as outer src on encap).
///
/// Returns `Ok(Some(action))` if the packet was fully handled, `Ok(None)` to fall through,
/// `Err(DpErr)` on a non-recoverable error.
#[inline(always)]
pub fn nat64_egress(
    ctx: &XdpContext,
    vni: u32,
    meta_guest_ipv4: [u8; 4],
    meta_underlay_ipv6: &[u8; 16],
) -> Result<Option<u32>, DpErr> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    // Eth(14) + IPv6(40) + min L4(8).
    if data + ETH_LEN + IPV6_LEN + 8 > data_end {
        return Ok(None);
    }
    let p = data as *const u8;

    // Inner IPv6 dst: ETH_LEN + 24 (dst is at offset 24 inside the IPv6 header).
    let ip6_dst: [u8; 16] =
        unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 24) as *const [u8; 16]) };
    if !is_nat64_addr(&ip6_dst) {
        return Ok(None);
    }
    // Embedded IPv4 dst.
    let ipv4_dst: [u8; 4] = [ip6_dst[12], ip6_dst[13], ip6_dst[14], ip6_dst[15]];

    // NAT config for this guest.
    let nat = match unsafe {
        NAT.get(&NatKey {
            vni,
            ipv4: meta_guest_ipv4,
        })
    } {
        Some(v) => *v,
        None => return Ok(None),
    };
    let range = nat.port_max.wrapping_sub(nat.port_min);
    if range == 0 {
        return Ok(None);
    }

    // IPv6 src (the guest IPv6 address).
    let ip6_src: [u8; 16] =
        unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 8) as *const [u8; 16]) };

    // L4 protocol (IPv6 next-header).
    let nh = unsafe { *p.add(ETH_LEN + 6) };
    // IPv6 payload length = l4_len.
    let ip6_plen =
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 4) as *const u16) });
    let l4_len = ip6_plen as usize;
    // `ip6_plen` is attacker-controlled. It feeds the translated IPv4 `total_len` and the L4
    // pseudo-header checksum length, so a frame that overstates it would produce a malformed,
    // mis-checksummed packet. Reject anything whose claimed payload overruns the actual buffer.
    if data + ETH_LEN + IPV6_LEN + l4_len > data_end {
        return Ok(None);
    }

    // Existing L4 checksum (big-endian, from packet) — used for incremental update.
    // For TCP: offset 16 in L4; for UDP: offset 6; for ICMPv6: offset 2.
    let (l4_proto_v4, sport, dport, old_l4_cksum_be): (u8, u16, u16, u16) = match nh {
        IPPROTO_ICMPV6 => {
            if data + ETH_LEN + IPV6_LEN + 8 > data_end {
                return Ok(None);
            }
            if unsafe { *p.add(ETH_LEN + IPV6_LEN) } != ICMPV6_ECHO_REQUEST {
                return Ok(None); // only echo for now
            }
            let id = u16::from_be(unsafe {
                core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 4) as *const u16)
            });
            let cksum =
                unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 2) as *const u16) };
            (IPPROTO_ICMP, id, id, cksum)
        }
        IPPROTO_TCP => {
            if data + ETH_LEN + IPV6_LEN + 20 > data_end {
                return Ok(None);
            }
            let sp = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN) as *const u16) };
            let dp =
                unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 2) as *const u16) };
            let ck =
                unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 16) as *const u16) };
            (IPPROTO_TCP, u16::from_be(sp), u16::from_be(dp), ck)
        }
        IPPROTO_UDP => {
            if data + ETH_LEN + IPV6_LEN + 8 > data_end {
                return Ok(None);
            }
            let sp = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN) as *const u16) };
            let dp =
                unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 2) as *const u16) };
            let ck =
                unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 6) as *const u16) };
            (IPPROTO_UDP, u16::from_be(sp), u16::from_be(dp), ck)
        }
        _ => return Ok(None),
    };

    // Forward conntrack key (keyed on IPv4 5-tuple after translation).
    let fwd_key = CtKey {
        vni,
        src_ip: meta_guest_ipv4,
        dst_ip: ipv4_dst,
        src_port: sport,
        dst_port: dport,
        proto: l4_proto_v4,
        _pad: [0; 3],
    };
    let nat_port = match unsafe { crate::maps::CONNTRACK.get(&fwd_key) } {
        Some(v) if v.flags & CT_F_SRC_NAT != 0 => v.xlate_port,
        _ => {
            let start =
                (crate::parse::hash5(&meta_guest_ipv4, &ipv4_dst, sport, dport, l4_proto_v4)
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
                if unsafe { crate::maps::CONNTRACK.get(&rev_key) }.is_none() {
                    chosen = cand;
                    // Reverse entry: guest xlate_ip + original sport/id in xlate_port.
                    // CT_F_NAT64 tells the ingress path to do IPv4→IPv6 expansion on reply.
                    let _ = crate::maps::CONNTRACK.insert(
                        &rev_key,
                        &CtEntry {
                            last_seen: crate::conntrack::now(),
                            xlate_ip: meta_guest_ipv4,
                            xlate_port: sport,
                            flags: CT_REWRITE_DST | CT_F_SRC_NAT | CT_F_NAT64,
                            tcp_state: 0,
                            fwall_action: 0,
                            _pad: [0; 7],
                        },
                        0,
                    );
                    break;
                }
                i += 1;
            }
            let _ = crate::maps::CONNTRACK.insert(
                &fwd_key,
                &CtEntry {
                    last_seen: crate::conntrack::now(),
                    xlate_ip: nat.nat_ipv4,
                    xlate_port: chosen,
                    flags: CT_REWRITE_SRC | CT_F_SRC_NAT | CT_F_NAT64,
                    tcp_state: 0,
                    fwall_action: 0,
                    _pad: [0; 7],
                },
                0,
            );
            chosen
        }
    };

    // ── Packet resize: shrink IPv6(40) → IPv4(20), i.e. drop 20 bytes ──
    // Total L4 bytes (= ip6_plen).
    // Save Ethernet header and IPv6 TTL before the adjust.
    let eth_dst: [u8; 6] = unsafe { core::ptr::read_unaligned(p as *const [u8; 6]) };
    let eth_src: [u8; 6] = unsafe { core::ptr::read_unaligned(p.add(6) as *const [u8; 6]) };
    let hop_limit = unsafe { *p.add(ETH_LEN + 7) };

    // adjust_head(+20): move data pointer forward 20 bytes (shrinks packet by 20).
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, 20) } != 0 {
        return Err(DpErr::Bounds);
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + 20 + 8 > data_end {
        return Err(DpErr::Bounds);
    }
    let q = data as *mut u8;

    // New layout: [Eth(14)][IPv4(20)][L4(l4_len)] with L4 at data+34.
    // Write Ethernet header.
    unsafe {
        core::ptr::write_unaligned(q as *mut [u8; 6], eth_dst);
        core::ptr::write_unaligned(q.add(6) as *mut [u8; 6], eth_src);
        core::ptr::write_unaligned(q.add(12) as *mut u16, crate::parse::ETH_P_IP.to_be());
    }

    // Build and write IPv4 header (20 bytes, IHL=5) into a stack buffer first.
    let total_len = (20u16).wrapping_add(l4_len as u16);
    let mut ip4hdr = [0u8; 20];
    ip4hdr[0] = 0x45;
    ip4hdr[1] = 0;
    ip4hdr[2] = (total_len >> 8) as u8;
    ip4hdr[3] = (total_len & 0xff) as u8;
    // id = 0, flags/frag = 0 (already 0 from init).
    ip4hdr[8] = hop_limit;
    ip4hdr[9] = l4_proto_v4;
    // checksum placeholder at [10..12] = 0 (already 0).
    ip4hdr[12] = nat.nat_ipv4[0];
    ip4hdr[13] = nat.nat_ipv4[1];
    ip4hdr[14] = nat.nat_ipv4[2];
    ip4hdr[15] = nat.nat_ipv4[3];
    ip4hdr[16] = ipv4_dst[0];
    ip4hdr[17] = ipv4_dst[1];
    ip4hdr[18] = ipv4_dst[2];
    ip4hdr[19] = ipv4_dst[3];
    let ip4_chk = ipv4_hdr_checksum(&ip4hdr);
    ip4hdr[10] = (ip4_chk >> 8) as u8;
    ip4hdr[11] = (ip4_chk & 0xff) as u8;
    unsafe {
        core::ptr::copy_nonoverlapping(ip4hdr.as_ptr(), q.add(ETH_LEN), 20);
    }

    // Fix L4 header (L4 is at data + ETH_LEN + 20 = data + 34).
    let l4_off = ETH_LEN + 20;
    if data + l4_off + 8 > data_end {
        return Err(DpErr::Bounds);
    }
    let lp = unsafe { q.add(l4_off) };
    match l4_proto_v4 {
        IPPROTO_ICMP => {
            // ICMPv6→ICMPv4: type 128→8, rewrite id to nat_port, recompute ICMPv4 checksum.
            // Read the 8-byte ICMPv6 header into a stack array (fixed offsets → verifier happy).
            let seq_be = unsafe { core::ptr::read_unaligned(lp.add(6) as *const u16) };
            let icmp4: [u8; 8] = [
                ICMP_ECHO_REQUEST, // type
                0,                 // code
                0,
                0,                       // checksum placeholder
                (nat_port >> 8) as u8,   // id hi
                (nat_port & 0xff) as u8, // id lo
                (u16::from_be(seq_be) >> 8) as u8,
                (u16::from_be(seq_be) & 0xff) as u8,
            ];
            let chk = icmpv4_echo_checksum(&icmp4);
            unsafe {
                *lp.add(0) = ICMP_ECHO_REQUEST;
                *lp.add(1) = 0;
                core::ptr::write_unaligned(lp.add(2) as *mut u16, chk.to_be());
                core::ptr::write_unaligned(lp.add(4) as *mut u16, nat_port.to_be());
                // seq unchanged (lp+6,7 still has the correct bytes)
            }
        }
        IPPROTO_TCP => {
            if data + l4_off + 20 > data_end {
                return Err(DpErr::Bounds);
            }
            // Translate checksum: v6 pseudo → v4 pseudo, old sport → nat_port.
            let new_ck = tcp_udp_v6_to_v4(
                old_l4_cksum_be,
                &ip6_src,
                &ip6_dst,
                nat.nat_ipv4,
                ipv4_dst,
                IPPROTO_TCP,
                l4_len as u16,
                sport.to_be(),
                nat_port.to_be(),
            );
            unsafe {
                core::ptr::write_unaligned(lp as *mut u16, nat_port.to_be()); // src port
                core::ptr::write_unaligned(lp.add(16) as *mut u16, new_ck); // checksum
            }
        }
        IPPROTO_UDP => {
            if data + l4_off + 8 > data_end {
                return Err(DpErr::Bounds);
            }
            let new_ck = tcp_udp_v6_to_v4(
                old_l4_cksum_be,
                &ip6_src,
                &ip6_dst,
                nat.nat_ipv4,
                ipv4_dst,
                IPPROTO_UDP,
                l4_len as u16,
                sport.to_be(),
                nat_port.to_be(),
            );
            unsafe {
                core::ptr::write_unaligned(lp as *mut u16, nat_port.to_be()); // src port
                core::ptr::write_unaligned(lp.add(6) as *mut u16, new_ck); // checksum
            }
        }
        _ => return Ok(None),
    }

    // Look up the external route for the IPv4 dst.
    let route = match crate::maps::ROUTES.get(&aya_ebpf::maps::lpm_trie::Key::new(
        64,
        xdp_dp_common::RouteLpmData {
            vni: vni.to_be_bytes(),
            ipv4: ipv4_dst,
        },
    )) {
        Some(r) => r,
        None => return Ok(None),
    };

    let local = LOCAL.get(0).ok_or(DpErr::NoRoute)?;
    let act = crate::encap::encap_and_redirect(
        ctx,
        local,
        meta_underlay_ipv6,
        route,
        crate::parse::IPPROTO_IPIP,
    )?;
    Ok(Some(act))
}

/// Allocate a SNAT port for a new NAT64 flow and install the forward + reverse conntrack entries.
/// Pure map work (no packet access). Inlined into `tc_nat64_egress`: keeping it a separate
/// sub-program added a 144-byte frame on top of tc_nat64_egress's, pushing the call chain over the
/// BPF 512-byte combined-stack budget; inlined, the CtKey/CtEntry temporaries reuse the parent's
/// frame slots (they're dead before the packet rewrite begins).
#[inline(always)]
fn tc_nat64_alloc_port(fwd_key: &CtKey, nat_ipv4: [u8; 4], port_min: u16, range: u16) -> u16 {
    // All other inputs are recoverable from the forward key (≤5-arg BPF calling convention).
    let vni = fwd_key.vni;
    let meta_guest_ipv4 = fwd_key.src_ip;
    let ipv4_dst = fwd_key.dst_ip;
    let sport = fwd_key.src_port;
    let dport = fwd_key.dst_port;
    let l4_proto_v4 = fwd_key.proto;
    let start = (crate::parse::hash5(&meta_guest_ipv4, &ipv4_dst, sport, dport, l4_proto_v4)
        % range as u32) as u16;
    let mut chosen = port_min.wrapping_add(start);
    let mut i: u16 = 0;
    while i < PROBE_LIMIT {
        let cand = port_min.wrapping_add((start.wrapping_add(i)) % range);
        let rev_key = CtKey {
            vni,
            src_ip: [0; 4],
            dst_ip: nat_ipv4,
            src_port: 0,
            dst_port: cand,
            proto: l4_proto_v4,
            _pad: [0; 3],
        };
        if unsafe { crate::maps::CONNTRACK.get(&rev_key) }.is_none() {
            chosen = cand;
            let _ = crate::maps::CONNTRACK.insert(
                &rev_key,
                &CtEntry {
                    last_seen: crate::conntrack::now(),
                    xlate_ip: meta_guest_ipv4,
                    xlate_port: sport,
                    flags: CT_REWRITE_DST | CT_F_SRC_NAT | CT_F_NAT64,
                    tcp_state: 0,
                    fwall_action: 0,
                    _pad: [0; 7],
                },
                0,
            );
            break;
        }
        i += 1;
    }
    let _ = crate::maps::CONNTRACK.insert(
        fwd_key,
        &CtEntry {
            last_seen: crate::conntrack::now(),
            xlate_ip: nat_ipv4,
            xlate_port: chosen,
            flags: CT_REWRITE_SRC | CT_F_SRC_NAT | CT_F_NAT64,
            tcp_state: 0,
            fwall_action: 0,
            _pad: [0; 7],
        },
        0,
    );
    chosen
}

/// tc variant of `nat64_egress`. Same logic (NAT lookup, conntrack/port allocation, v6→v4 header
/// + L4 translation, encap+redirect out the uplink), but built on skb primitives:
///   - shrink IPv6(40)→IPv4(20): `adjust_room(-20, BPF_ADJ_ROOM_MAC, 0)` (removes 20 bytes after
///     the MAC header) instead of `bpf_xdp_adjust_head(+20)`.
///   - encap: `adjust_room(+IPV6_LEN, BPF_ADJ_ROOM_MAC, 0)` + `pull_data` + `write_outer_v6` +
///     `bpf_redirect`, the same glue `tc_guest_tx` already uses for the IPv4/IPv6 Encap verdicts.
/// Each resize is followed by `pull_data` so the fixed-offset rewrite region is writable/linear and
/// the verifier sees a fresh packet range. Does NOT touch the verifier-tuned XDP `nat64_egress`.
///
/// Returns `Ok(Some(action))` if handled, `Ok(None)` to fall through, `Err(DpErr)` on error.
///
/// Deliberately NOT `#[inline(always)]`: `tc_guest_tx` is one large function carrying the IPv4
/// egress + DHCP stack frames, and inlining this body on top blows the 512-byte BPF stack limit.
/// Emitting it as a separate BPF sub-program gives it its own frame.
#[inline(never)]
pub fn tc_nat64_egress(
    ctx: &aya_ebpf::programs::TcContext,
    vni: u32,
    meta_guest_ipv4: [u8; 4],
    meta_underlay_ipv6: &[u8; 16],
) -> Result<Option<i32>, DpErr> {
    use aya_ebpf::bindings::bpf_adj_room_mode::BPF_ADJ_ROOM_MAC;

    // Make the inner IPv6 header + min L4 range writable/linear for the in-place rewrite.
    let _ = ctx.pull_data((ETH_LEN + IPV6_LEN + 8) as u32);
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN + 8 > data_end {
        return Ok(None);
    }
    let p = data as *const u8;

    // Inner IPv6 dst: ETH_LEN + 24.
    let ip6_dst: [u8; 16] =
        unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 24) as *const [u8; 16]) };
    if !is_nat64_addr(&ip6_dst) {
        return Ok(None);
    }
    let ipv4_dst: [u8; 4] = [ip6_dst[12], ip6_dst[13], ip6_dst[14], ip6_dst[15]];

    // NAT config for this guest.
    let nat = match unsafe {
        NAT.get(&NatKey {
            vni,
            ipv4: meta_guest_ipv4,
        })
    } {
        Some(v) => *v,
        None => return Ok(None),
    };
    let range = nat.port_max.wrapping_sub(nat.port_min);
    if range == 0 {
        return Ok(None);
    }

    let ip6_src: [u8; 16] =
        unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 8) as *const [u8; 16]) };
    let nh = unsafe { *p.add(ETH_LEN + 6) };
    let ip6_plen =
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 4) as *const u16) });
    let l4_len = ip6_plen as usize;
    // See the XDP path: `ip6_plen` is attacker-controlled and feeds the translated IPv4
    // `total_len`/`inner_len` and the L4 checksum length. Reject claimed payloads that overrun.
    if data + ETH_LEN + IPV6_LEN + l4_len > data_end {
        return Ok(None);
    }

    let (l4_proto_v4, sport, dport, old_l4_cksum_be): (u8, u16, u16, u16) = match nh {
        IPPROTO_ICMPV6 => {
            if data + ETH_LEN + IPV6_LEN + 8 > data_end {
                return Ok(None);
            }
            if unsafe { *p.add(ETH_LEN + IPV6_LEN) } != ICMPV6_ECHO_REQUEST {
                return Ok(None);
            }
            let id = u16::from_be(unsafe {
                core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 4) as *const u16)
            });
            let cksum =
                unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 2) as *const u16) };
            (IPPROTO_ICMP, id, id, cksum)
        }
        IPPROTO_TCP => {
            if data + ETH_LEN + IPV6_LEN + 20 > data_end {
                return Ok(None);
            }
            let sp = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN) as *const u16) };
            let dp =
                unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 2) as *const u16) };
            let ck =
                unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 16) as *const u16) };
            (IPPROTO_TCP, u16::from_be(sp), u16::from_be(dp), ck)
        }
        IPPROTO_UDP => {
            if data + ETH_LEN + IPV6_LEN + 8 > data_end {
                return Ok(None);
            }
            let sp = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN) as *const u16) };
            let dp =
                unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 2) as *const u16) };
            let ck =
                unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 6) as *const u16) };
            (IPPROTO_UDP, u16::from_be(sp), u16::from_be(dp), ck)
        }
        _ => return Ok(None),
    };

    // Forward conntrack key (keyed on IPv4 5-tuple after translation).
    let fwd_key = CtKey {
        vni,
        src_ip: meta_guest_ipv4,
        dst_ip: ipv4_dst,
        src_port: sport,
        dst_port: dport,
        proto: l4_proto_v4,
        _pad: [0; 3],
    };
    let nat_port = match unsafe { crate::maps::CONNTRACK.get(&fwd_key) } {
        Some(v) if v.flags & CT_F_SRC_NAT != 0 => v.xlate_port,
        // The port allocation + conntrack inserts build large CtKey/CtEntry stack temporaries;
        // emitting them in a separate sub-program keeps tc_nat64_egress's own frame under the BPF
        // stack limit (it already carries ip6_src/ip6_dst/ip4hdr/EncapParams).
        _ => tc_nat64_alloc_port(&fwd_key, nat.nat_ipv4, nat.port_min, range),
    };

    // IPv6 hop-limit (becomes the inner IPv4 TTL) — read before the resize.
    let hop_limit = unsafe { *p.add(ETH_LEN + 7) };

    // ── Single +20 grow (no minimal-frame shrink). ──
    // NAT64 egress net size change is -20 (v6→v4 inner) + 40 (outer encap) = +20. Growing has no
    // minimal-frame restriction (unlike the in-place -20 MAC-mode shrink, which returns -ENOTSUPP
    // on a near-minimum 62-byte ICMPv6 echo frame). Insert 20 bytes right after the MAC header:
    //   Before: [Eth 0..14][inner IPv6 14..54][L4 54..(54+l4_len)]
    //   After:  [Eth 0..14][NEW 14..34][inner-IPv6(shifted) 34..74][L4(shifted) 74..]
    // Then overwrite [0..74] with the final outer Eth + outer IPv6 + inner IPv4, leaving L4 in place
    // at offset 74 (= ETH_LEN + IPV6_LEN + 20).
    if ctx.adjust_room(20, BPF_ADJ_ROOM_MAC, 0).is_err() {
        return Err(DpErr::Bounds);
    }
    // inner IPv4 at ETH_LEN+IPV6_LEN, L4 at ETH_LEN+IPV6_LEN+20.
    if ctx.pull_data((ETH_LEN + IPV6_LEN + 20 + 8) as u32).is_err() {
        return Err(DpErr::Bounds);
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN + 20 + 8 > data_end {
        return Err(DpErr::Bounds);
    }
    let q = data as *mut u8;

    // ── Build + write the inner IPv4 header into [54..74]. ──
    let total_len = (20u16).wrapping_add(l4_len as u16);
    let mut ip4hdr = [0u8; 20];
    ip4hdr[0] = 0x45;
    ip4hdr[1] = 0;
    ip4hdr[2] = (total_len >> 8) as u8;
    ip4hdr[3] = (total_len & 0xff) as u8;
    ip4hdr[8] = hop_limit;
    ip4hdr[9] = l4_proto_v4;
    ip4hdr[12] = nat.nat_ipv4[0];
    ip4hdr[13] = nat.nat_ipv4[1];
    ip4hdr[14] = nat.nat_ipv4[2];
    ip4hdr[15] = nat.nat_ipv4[3];
    ip4hdr[16] = ipv4_dst[0];
    ip4hdr[17] = ipv4_dst[1];
    ip4hdr[18] = ipv4_dst[2];
    ip4hdr[19] = ipv4_dst[3];
    let ip4_chk = ipv4_hdr_checksum(&ip4hdr);
    ip4hdr[10] = (ip4_chk >> 8) as u8;
    ip4hdr[11] = (ip4_chk & 0xff) as u8;
    unsafe {
        core::ptr::copy_nonoverlapping(ip4hdr.as_ptr(), q.add(ETH_LEN + IPV6_LEN), 20);
    }

    // ── Translate the L4 header in place at [74..] (= ETH_LEN + IPV6_LEN + 20). ──
    let l4_off = ETH_LEN + IPV6_LEN + 20;
    if data + l4_off + 8 > data_end {
        return Err(DpErr::Bounds);
    }
    let lp = unsafe { q.add(l4_off) };
    match l4_proto_v4 {
        IPPROTO_ICMP => {
            let seq_be = unsafe { core::ptr::read_unaligned(lp.add(6) as *const u16) };
            let icmp4: [u8; 8] = [
                ICMP_ECHO_REQUEST,
                0,
                0,
                0,
                (nat_port >> 8) as u8,
                (nat_port & 0xff) as u8,
                (u16::from_be(seq_be) >> 8) as u8,
                (u16::from_be(seq_be) & 0xff) as u8,
            ];
            let chk = icmpv4_echo_checksum(&icmp4);
            unsafe {
                *lp.add(0) = ICMP_ECHO_REQUEST;
                *lp.add(1) = 0;
                core::ptr::write_unaligned(lp.add(2) as *mut u16, chk.to_be());
                core::ptr::write_unaligned(lp.add(4) as *mut u16, nat_port.to_be());
            }
        }
        IPPROTO_TCP => {
            if data + l4_off + 20 > data_end {
                return Err(DpErr::Bounds);
            }
            let new_ck = tcp_udp_v6_to_v4(
                old_l4_cksum_be,
                &ip6_src,
                &ip6_dst,
                nat.nat_ipv4,
                ipv4_dst,
                IPPROTO_TCP,
                l4_len as u16,
                sport.to_be(),
                nat_port.to_be(),
            );
            unsafe {
                core::ptr::write_unaligned(lp as *mut u16, nat_port.to_be());
                core::ptr::write_unaligned(lp.add(16) as *mut u16, new_ck);
            }
        }
        IPPROTO_UDP => {
            if data + l4_off + 8 > data_end {
                return Err(DpErr::Bounds);
            }
            let new_ck = tcp_udp_v6_to_v4(
                old_l4_cksum_be,
                &ip6_src,
                &ip6_dst,
                nat.nat_ipv4,
                ipv4_dst,
                IPPROTO_UDP,
                l4_len as u16,
                sport.to_be(),
                nat_port.to_be(),
            );
            unsafe {
                core::ptr::write_unaligned(lp as *mut u16, nat_port.to_be());
                core::ptr::write_unaligned(lp.add(6) as *mut u16, new_ck);
            }
        }
        _ => return Ok(None),
    }

    // ── Write outer Eth + outer IPv6 into [0..54], inline + straight-line. ──
    // Written HERE (after the L4 translation), once ip6_src/ip6_dst are dead, keeping the live-stack
    // set small. Folded inline (no EncapParams struct, no write_outer_v6 call): passing a stack
    // pointer into a helper this close to the return made the verifier track R0 as a frame pointer
    // ("cannot return stack pointer to the caller"). Straight-line packet writes avoid that.
    // The route/local map reads are valid at any time (no packet access).
    // outer IPv6 payload (inner_len) = inner IPv4(20) + L4(l4_len).
    let nexthop_ipv6 = match crate::maps::ROUTES.get(&aya_ebpf::maps::lpm_trie::Key::new(
        64,
        xdp_dp_common::RouteLpmData {
            vni: vni.to_be_bytes(),
            ipv4: ipv4_dst,
        },
    )) {
        Some(r) => r.nexthop_ipv6,
        None => return Ok(None),
    };
    let local = LOCAL.get(0).ok_or(DpErr::NoRoute)?;
    let gateway_mac = local.gateway_mac;
    let uplink_mac = local.uplink_mac;
    let uplink_ifindex = local.uplink_ifindex;
    let inner_len = (20u16).wrapping_add(l4_len as u16);
    // Re-check the [0..54] write window is in-bounds (verifier needs this against data_end).
    if data + ETH_LEN + IPV6_LEN > data_end {
        return Err(DpErr::Bounds);
    }
    unsafe {
        // Outer Ethernet: dst=gateway_mac, src=uplink_mac, ethertype IPv6.
        write6(q, &gateway_mac);
        write6(q.add(6), &uplink_mac);
        core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IPV6.to_be());
        // Outer IPv6: version 6, plen=inner_len, next-header IPIP, hops 64.
        let ip = q.add(ETH_LEN);
        *ip.add(0) = 0x60;
        *ip.add(1) = 0;
        *ip.add(2) = 0;
        *ip.add(3) = 0;
        core::ptr::write_unaligned(ip.add(4) as *mut u16, inner_len.to_be());
        *ip.add(6) = crate::parse::IPPROTO_IPIP;
        *ip.add(7) = 64;
        write16(ip.add(8), meta_underlay_ipv6);
        write16(ip.add(24), &nexthop_ipv6);
    }

    // Outer Eth+IPv6, inner IPv4, and L4 are all written. Redirect out the uplink.
    Ok(Some(unsafe { bpf_redirect(uplink_ifindex, 0) } as i32))
}

// ─────────────────────────────────────────────────────────────────────────────
// INGRESS: IPv4→IPv6 translation for NAT64 replies
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt NAT64 ingress reverse translation.
///
/// Called from `try_uplink_rx` after the standard NAT reverse conntrack detects CT_F_NAT64.
/// Packet on entry: `Eth(14) + outer_IPv6(40) + inner_IPv4(20) + L4(...)` (pre-decap).
/// `nat_guest_ipv4`: the restored guest IPv4 from the CT entry (xlate_ip).
/// `orig_sport`: the original guest L4 port/id from the CT entry (xlate_port).
/// `tap_ifindex` + `guest_mac`: from the UNDERLAY lookup.
///
/// Returns `Ok(Some(action))` if handled, `Ok(None)` to fall through, `Err(DpErr)` on error.
#[inline(always)]
pub fn nat64_ingress(
    ctx: &XdpContext,
    tap_ifindex: u32,
    guest_mac: [u8; 6],
    _nat_guest_ipv4: [u8; 4],
    orig_sport: u16,
) -> Result<Option<u32>, DpErr> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    // Eth(14) + outer IPv6(40) + inner IPv4(20) + L4(8).
    if data + ETH_LEN + IPV6_LEN + 20 + 8 > data_end {
        return Ok(None);
    }
    let p = data as *const u8;

    let inner_off = ETH_LEN + IPV6_LEN;
    // Check inner IPv4 IHL == 5.
    if unsafe { *p.add(inner_off) } & 0x0f != 5 {
        return Ok(None);
    }
    let l4_proto = unsafe { *p.add(inner_off + 9) };
    match l4_proto {
        IPPROTO_ICMP | IPPROTO_TCP | IPPROTO_UDP => {}
        _ => return Ok(None),
    }
    let inner_ttl = unsafe { *p.add(inner_off + 8) };
    // The inner src IPv4 (= the external server, e.g. 45.86.6.6) → NAT64 prefix src.
    let inner_src_v4: [u8; 4] =
        unsafe { core::ptr::read_unaligned(p.add(inner_off + 12) as *const [u8; 4]) };
    // inner dst IPv4 = the SNAT'd NAT IPv4 (already restored by ct_apply CT_REWRITE_DST).
    let inner_dst_v4: [u8; 4] =
        unsafe { core::ptr::read_unaligned(p.add(inner_off + 16) as *const [u8; 4]) };
    let inner_total_len =
        u16::from_be(unsafe { core::ptr::read_unaligned(p.add(inner_off + 2) as *const u16) })
            as usize;
    let l4_len = if inner_total_len >= 20 {
        inner_total_len - 20
    } else {
        return Ok(None);
    };

    // Existing L4 checksum (big-endian, from packet).
    // We'll use incremental update for TCP/UDP; for ICMP we recompute fully from 8 bytes.
    let l4_off_abs = inner_off + 20; // offset in original (pre-adjust) packet.
    let old_l4_cksum_be: u16 = match l4_proto {
        IPPROTO_TCP => {
            if data + l4_off_abs + 20 > data_end {
                return Ok(None);
            }
            unsafe { core::ptr::read_unaligned(p.add(l4_off_abs + 16) as *const u16) }
        }
        IPPROTO_UDP => {
            if data + l4_off_abs + 8 > data_end {
                return Ok(None);
            }
            unsafe { core::ptr::read_unaligned(p.add(l4_off_abs + 6) as *const u16) }
        }
        IPPROTO_ICMP => {
            if data + l4_off_abs + 8 > data_end {
                return Ok(None);
            }
            unsafe { core::ptr::read_unaligned(p.add(l4_off_abs + 2) as *const u16) }
        }
        _ => return Ok(None),
    };
    // For TCP/UDP: need the old dst port (nat_port, which ct_apply just restored to orig_sport,
    // but we need the SNAT'd one for the checksum delta). Actually ct_apply was called with
    // CT_REWRITE_DST which rewrites the dst port — so the packet's dport is already orig_sport
    // at this point. But the checksum was updated by ct_apply's incremental update from
    // nat_port→orig_sport. So the current packet's TCP/UDP checksum already reflects orig_sport
    // but is still an IPv4 checksum. We need to translate it to IPv6 checksum.
    // We don't need old/new dport because ct_apply already did the dport rewrite + cksum update.
    // The current checksum covers {src4, dst4, proto, len, nat_port→orig_sport, ...payload}.
    // We just need to translate the pseudo-header contribution: v4 → v6.

    // Guest IPv6 from PORT_META.
    let guest_ipv6 = {
        match unsafe { PORT_META.get(&tap_ifindex) } {
            Some(m) => m.guest_ipv6,
            None => return Ok(None),
        }
    };
    if guest_ipv6 == [0u8; 16] {
        return Ok(None);
    }
    let ipv6_src = nat64_embed(inner_src_v4);

    // ── Packet resize: Eth+outer_IPv6+inner_IPv4 → Eth+inner_IPv6 ──
    // Current: Eth(14)+outer_IPv6(40)+inner_IPv4(20)+L4 = 74+L4 bytes
    // Desired: Eth(14)+inner_IPv6(40)+L4 = 54+L4 bytes → shrink by 20.
    // Strategy: adjust_head(+20) to shrink by 20, then rewrite first 54 bytes.

    // After adjust_head(+20), data moves +20. Physical L4 is at old_data+74 = new_data+54. ✓

    if unsafe { bpf_xdp_adjust_head(ctx.ctx, 20) } != 0 {
        return Err(DpErr::Bounds);
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN + 8 > data_end {
        return Err(DpErr::Bounds);
    }
    let q = data as *mut u8;

    // Write Ethernet header (IPv6 ethertype, dst=guest_mac, src=GW_MAC).
    unsafe {
        write6(q, &guest_mac);
        write6(q.add(6), &crate::arp_nd::GW_MAC);
        core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IPV6.to_be());
    }

    // Write inner IPv6 header.
    let l4_proto_v6 = if l4_proto == IPPROTO_ICMP {
        IPPROTO_ICMPV6
    } else {
        l4_proto
    };
    let payload_len = l4_len as u16;
    unsafe {
        let ip6 = q.add(ETH_LEN);
        // Version=6, TC=0, Flow=0.
        *ip6.add(0) = 0x60;
        *ip6.add(1) = 0;
        *ip6.add(2) = 0;
        *ip6.add(3) = 0;
        core::ptr::write_unaligned(ip6.add(4) as *mut u16, payload_len.to_be());
        *ip6.add(6) = l4_proto_v6;
        *ip6.add(7) = inner_ttl;
        write16(ip6.add(8), &ipv6_src);
        write16(ip6.add(24), &guest_ipv6);
    }

    // Fix L4 header (L4 is at data + ETH_LEN + IPV6_LEN = data + 54).
    let l4_off = ETH_LEN + IPV6_LEN;
    if data + l4_off + 8 > data_end {
        return Err(DpErr::Bounds);
    }
    let lp = unsafe { q.add(l4_off) };
    match l4_proto {
        IPPROTO_ICMP => {
            // ICMP echo reply → ICMPv6 echo reply.
            // Read 8-byte ICMP header into stack buffer via fixed offsets.
            let seq_be = unsafe { core::ptr::read_unaligned(lp.add(6) as *const u16) };
            // Build the new ICMPv6 header in a stack array for checksum computation.
            let icmp6: [u8; 8] = [
                ICMPV6_ECHO_REPLY, // type 129
                0,                 // code
                0,
                0,                         // checksum placeholder
                (orig_sport >> 8) as u8,   // id hi (restored)
                (orig_sport & 0xff) as u8, // id lo
                (u16::from_be(seq_be) >> 8) as u8,
                (u16::from_be(seq_be) & 0xff) as u8,
            ];
            let chk = icmpv6_echo_checksum(&ipv6_src, &guest_ipv6, &icmp6);
            unsafe {
                *lp.add(0) = ICMPV6_ECHO_REPLY;
                *lp.add(1) = 0;
                core::ptr::write_unaligned(lp.add(2) as *mut u16, chk.to_be());
                core::ptr::write_unaligned(lp.add(4) as *mut u16, orig_sport.to_be());
                // seq unchanged (lp+6,7 already correct)
            }
        }
        IPPROTO_TCP => {
            // ct_apply already rewrote dst port (nat_port → orig_sport) and updated the
            // IPv4 checksum incrementally.  We need to translate to IPv6 pseudo-header.
            // Since ct_apply updated the checksum after the dport change, the current
            // checksum reflects orig_sport dport in an IPv4 pseudo-header context.
            // Use incremental update: v4 pseudo → v6 pseudo, no port change needed here.
            if data + l4_off + 20 > data_end {
                return Err(DpErr::Bounds);
            }
            let new_ck = tcp_udp_v4_to_v6(
                old_l4_cksum_be,
                inner_src_v4,
                inner_dst_v4,
                &ipv6_src,
                &guest_ipv6,
                IPPROTO_TCP,
                l4_len as u16,
            );
            unsafe {
                core::ptr::write_unaligned(lp.add(16) as *mut u16, new_ck);
            }
        }
        IPPROTO_UDP => {
            if data + l4_off + 8 > data_end {
                return Err(DpErr::Bounds);
            }
            let new_ck = tcp_udp_v4_to_v6(
                old_l4_cksum_be,
                inner_src_v4,
                inner_dst_v4,
                &ipv6_src,
                &guest_ipv6,
                IPPROTO_UDP,
                l4_len as u16,
            );
            unsafe {
                core::ptr::write_unaligned(lp.add(6) as *mut u16, new_ck);
            }
        }
        _ => return Ok(None),
    }

    Ok(Some(unsafe { bpf_redirect(tap_ifindex, 0) } as u32))
}
