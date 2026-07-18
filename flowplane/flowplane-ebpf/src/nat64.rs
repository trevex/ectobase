/// NAT64: bidirectional translation between IPv6 (64:ff9b::/96 prefix) guests and IPv4 external.
///
/// Egress (tc_guest_tx): an IPv6 frame whose dst is in 64:ff9b::/96 is translated to IPv4 + SNAT'd
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
use crate::parse::{write16, write6, ETH_LEN, ETH_P_IPV6, IPV6_LEN};

// The NAT64 well-known-prefix check `is_nat64_addr` (+ the `64:ff9b::/96` prefix const) lives in
// `flowplane_core::nat64` (the shared seam). The egress translation (`nat64_egress_parse` /
// `nat64_egress_write`) AND the ingress translation (`nat64_ingress_parse` / `nat64_ingress_write` +
// the ingress pure helpers `nat64_embed` / `icmpv6_echo_checksum` / `tcp_udp_v4_to_v6`) now live
// there too — the SAME code the native SimNode + the BPF_PROG_TEST_RUN byte-parity anchor run. Only
// the resize primitive + map/redirect glue stays here.

// ─────────────────────────────────────────────────────────────────────────────
// EGRESS: IPv6→IPv4 translation + SNAT
// ─────────────────────────────────────────────────────────────────────────────

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
    // Guest IPv6 from PORT_META (used as the reconstructed inner IPv6 dst). Read here in the glue —
    // PORT_META is not part of the core `Maps` seam — and passed into the parse.
    let guest_ipv6 = match unsafe { PORT_META.get(&tap_ifindex) } {
        Some(m) => m.guest_ipv6,
        None => return Ok(None),
    };

    // Parse phase over the shared core seam (the SAME code the native SimNode + the BPF_PROG_TEST_RUN
    // byte-parity anchor run): IHL==5, L4 proto/TTL/inner-v4-addrs/total-len/L4-checksum, and the
    // reconstructed 64:ff9b:: IPv6 src. Runs on the PRE-resize [Eth][outerIPv6][innerIPv4][L4] frame;
    // `None` => short frame / IHL≠5 / unsupported L4 / all-zero guest IPv6 → fall through.
    let xlate = match flowplane_core::nat64::nat64_ingress_parse(
        &crate::coreimpl::RawPkt::new(ctx.data(), ctx.data_end()),
        ETH_LEN + IPV6_LEN,
        guest_ipv6,
        guest_mac,
        orig_sport,
    ) {
        Some(x) => x,
        None => return Ok(None),
    };

    // ── Packet resize: [Eth][outerIPv6(40)][innerIPv4(20)][L4] (74+L4) → [Eth][innerIPv6(40)][L4]
    // (54+L4) — a net 20-byte shrink via adjust_head(+20) (drop 20 bytes off the front). After the
    // shift, the physical L4 at old_data+74 lands at new_data+54. The resize stays in the glue (the
    // core is a pure Pkt reader/writer). ──
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, 20) } != 0 {
        return Err(DpErr::Bounds);
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN + 8 > data_end {
        return Err(DpErr::Bounds);
    }

    // Write phase over the shared core seam: guest-facing Ethernet (dst=guest_mac, src=GW_MAC, IPv6),
    // the inner IPv6 header (src=64:ff9b::server, dst=guest_ipv6, TTL from the inner v4), and the L4
    // translation (TCP/UDP checksum v4→v6; ICMPv4 echo-reply → ICMPv6 echo-reply). Re-wrap the resized
    // frame in a fresh RawPkt (adjust_head invalidated the prior bounds). Byte-identical to the
    // deleted inline rewrite.
    if !flowplane_core::nat64::nat64_ingress_write(
        &mut crate::coreimpl::RawPkt::new(data, data_end),
        ETH_LEN,
        crate::arp_nd::GW_MAC,
        &xlate,
    ) {
        return Err(DpErr::Bounds);
    }

    Ok(Some(unsafe { bpf_redirect(tap_ifindex, 0) } as u32))
}
