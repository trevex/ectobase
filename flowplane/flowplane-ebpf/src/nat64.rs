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

use crate::maps::PORT_META;
use crate::parse::{ETH_LEN, IPV6_LEN};

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
/// anchor run), but built on skb primitives for the resize:
///   - the v6→v4 shrink is a single `adjust_room(-20, BPF_ADJ_ROOM_MAC)` (net -20: IPv6(40)→IPv4(20)
///     inner header only — there is no outer encap to grow room for any more; see below) right after
///     the MAC header: the inner IPv4 lands at ETH_LEN, the L4 at ETH_LEN+20.
///   - the core `nat64_egress_write` (with `write_eth = true`) builds the guest-facing Ethernet +
///     inner IPv4 header + the L4 translation at that offset.
///   - the resolved [`flowplane_core::encap::TunnelEncap`] decision is stamped as the skb's Geneve
///     tunnel key (`crate::tunnel::set_tunnel_key`) and the skb redirected to the geneve device — NO
///     outer bytes are written here any more (the kernel `collect_md` device builds them). This is
///     the same replacement `tc.rs`'s guest-egress Encap arms made; see `crate::tunnel` docs.
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

    // ── v6→v4 shrink (-20), right after the MAC header. ──
    //   Before: [Eth 0..14][inner IPv6 14..54][L4 54..(54+l4_len)]
    //   After:  [Eth 0..14][inner IPv4(will be overwritten) 14..34][L4(shifted) 34..]
    if ctx.adjust_room(-20, BPF_ADJ_ROOM_MAC, 0).is_err() {
        return Err(DpErr::Bounds);
    }
    // inner IPv4 at ETH_LEN, L4 at ETH_LEN+20.
    if ctx.pull_data((ETH_LEN + 20 + 8) as u32).is_err() {
        return Err(DpErr::Bounds);
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + 20 + 8 > data_end {
        return Err(DpErr::Bounds);
    }

    // Write phase over the shared core seam: guest-facing Ethernet + the inner IPv4 header at
    // [0..34) + translate the L4 header at [34..), via the SAME core writer the XDP path uses.
    if !flowplane_core::nat64::nat64_egress_write(
        &mut crate::coreimpl::RawPkt::new(data, data_end),
        ETH_LEN,
        true,
        &xlate,
    ) {
        return Err(DpErr::Bounds);
    }

    // Route lookup on the embedded IPv4 dst → the Geneve tunnel-key decision toward the nexthop (no
    // byte write — see `crate::tunnel`).
    let route = match crate::maps::ROUTES.get(&aya_ebpf::maps::lpm_trie::Key::new(
        64,
        flowplane_common::RouteLpmData {
            vni: vni.to_be_bytes(),
            ipv4: ipv4_dst,
        },
    )) {
        Some(r) => *r,
        None => return Ok(None),
    };
    let tunnel = flowplane_core::encap::tunnel_encap(&route);
    if !crate::tunnel::set_tunnel_key(ctx.skb.skb, &tunnel) {
        return Err(DpErr::Bounds);
    }
    Ok(Some(crate::tunnel::redirect()))
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
