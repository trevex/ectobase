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
use flowplane_core::err::DpErr;

use crate::maps::{LOCAL, PORT_META};
use crate::parse::{
    write16, write6, ETH_LEN, ETH_P_IPV6, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, IPV6_LEN,
};

/// ICMPv6 echo-reply type (ingress reply). The egress `ICMPV6_ECHO_REQUEST` / `ICMP_ECHO_REQUEST`
/// consts moved into `flowplane_core::nat64` with the egress translation.
const ICMPV6_ECHO_REPLY: u8 = 129;
const IPPROTO_ICMP: u8 = 1;

// The NAT64 well-known-prefix check `is_nat64_addr` (+ the `64:ff9b::/96` prefix const) now lives in
// `flowplane_core::nat64` (the shared seam); the tc classifier and the egress parse both call it
// there. `nat64_embed` stays here — only `nat64_ingress` uses it.

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

// NOTE: the egress-only pure helpers `ipv4_hdr_checksum` / `icmpv4_echo_checksum` /
// `tcp_udp_v6_to_v4` moved into `flowplane_core::nat64` (the shared Pkt/Maps seam the XDP + tc egress
// paths, the native SimNode, and the BPF_PROG_TEST_RUN anchor all run). The helpers below
// (`icmpv6_echo_checksum` / `tcp_udp_v4_to_v6` + their `pseudo_*` / `csum_*` deps) stay because
// `nat64_ingress` (the IPv4→IPv6 reply path — a SEPARATE task) still uses them inline.

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
    // Parse phase over the shared core seam (the SAME code the native SimNode + the BPF_PROG_TEST_RUN
    // byte-parity anchor run): verify the dst is in 64:ff9b::/96, read the guest NAT config, allocate
    // the source port, and pin the forward + reverse CT_F_NAT64 conntrack entries. Runs on the
    // PRE-resize [Eth][IPv6][L4] frame; `None` => not a NAT64 frame, fall through to the v6 path.
    let xlate = match flowplane_core::nat64::nat64_egress_parse(
        &crate::coreimpl::RawPkt::new(ctx.data(), ctx.data_end()),
        &mut crate::coreimpl::GlobalMaps,
        ETH_LEN,
        vni,
        meta_guest_ipv4,
        crate::conntrack::now(),
    ) {
        Some(x) => x,
        None => return Ok(None),
    };

    // ── Packet resize: shrink IPv6(40) → IPv4(20) via adjust_head(+20) (drops 20 bytes off the
    // front). The old Ethernet header is shifted off; the core writer restores it in front of the
    // new IPv4 header. The resize stays in the glue (the core is a pure Pkt reader/writer). ──
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, 20) } != 0 {
        return Err(DpErr::Bounds);
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + 20 + 8 > data_end {
        return Err(DpErr::Bounds);
    }

    // Write phase over the shared core seam: restore the Ethernet header (IPv4 ethertype), build the
    // 20-byte IPv4 header, and translate the L4 (TCP/UDP checksum v6→v4 + src-port rewrite; ICMPv6
    // echo → ICMPv4). Re-wrap the resized frame in a fresh RawPkt (adjust_head invalidated the prior
    // bounds). Byte-identical to the deleted inline translation.
    if !flowplane_core::nat64::nat64_egress_write(
        &mut crate::coreimpl::RawPkt::new(data, data_end),
        ETH_LEN,
        true, // XDP in-place path: writer restores the Ethernet header.
        &xlate,
    ) {
        return Err(DpErr::Bounds);
    }

    // Look up the external route for the IPv4 dst and encap+redirect toward the nexthop.
    let route = match crate::maps::ROUTES.get(&aya_ebpf::maps::lpm_trie::Key::new(
        64,
        flowplane_common::RouteLpmData {
            vni: vni.to_be_bytes(),
            ipv4: xlate.ipv4_dst,
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

/// tc variant of `nat64_egress`. Same translation (v6→v4 header + L4 + SNAT), delegated to the shared
/// `flowplane_core::nat64` core (the SAME code the XDP path, native SimNode, and BPF_PROG_TEST_RUN
/// anchor run), but built on skb primitives for the resize + outer encap:
///   - the v6→v4 shrink is folded into the outer encap: a single `adjust_room(+20, BPF_ADJ_ROOM_MAC)`
///     grow (net -20 inner + 40 outer = +20) makes room; the inner IPv4 lands at ETH_LEN+IPV6_LEN,
///     the L4 at ETH_LEN+IPV6_LEN+20.
///   - the core `nat64_egress_write` (with `write_eth = false`) builds the inner IPv4 header + the L4
///     translation at that offset; the outer Eth+IPv6 is then written straight-line here (folding it
///     into a helper this close to the return trips the verifier's "return stack pointer" check).
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

    // Make the inner IPv6 header + min L4 range writable/linear for the parse read.
    let _ = ctx.pull_data((ETH_LEN + IPV6_LEN + 8) as u32);
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN + 8 > data_end {
        return Ok(None);
    }

    // Parse phase over the shared core seam (PRE-resize [Eth][IPv6][L4] frame): dst-prefix check, NAT
    // config, port allocation + forward/reverse CT_F_NAT64 conntrack inserts. `None` => fall through.
    let xlate = match flowplane_core::nat64::nat64_egress_parse(
        &crate::coreimpl::RawPkt::new(data, data_end),
        &mut crate::coreimpl::GlobalMaps,
        ETH_LEN,
        vni,
        meta_guest_ipv4,
        crate::conntrack::now(),
    ) {
        Some(x) => x,
        None => return Ok(None),
    };
    let ipv4_dst = xlate.ipv4_dst;
    let l4_len = xlate.l4_len as usize;

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

    // ── Write phase over the shared core seam: build the inner IPv4 header at [54..74] + translate
    // the L4 header at [74..], via the SAME core writer the XDP path uses. `write_eth = false`: the
    // outer Eth+IPv6 is written straight-line below (the writer only does the inner IPv4 + L4). ──
    if !flowplane_core::nat64::nat64_egress_write(
        &mut crate::coreimpl::RawPkt::new(data, data_end),
        ETH_LEN + IPV6_LEN,
        false,
        &xlate,
    ) {
        return Err(DpErr::Bounds);
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
        flowplane_common::RouteLpmData {
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
