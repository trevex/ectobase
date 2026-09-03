/// NAT64: bidirectional translation between IPv6 (64:ff9b::/96 prefix) guests and IPv4 external.
///
/// Egress (tc_guest_tx): an IPv6 frame whose dst is in 64:ff9b::/96 is translated to IPv4 + SNAT'd
/// via the guest's NAT config, then encap'd and forwarded like a normal IPv4 NAT flow.
///
/// Ingress (uplink_rx): an IPv4 reply that was reverse-NAT'd back to the guest IPv4 and carries
/// CT_F_NAT64 in the conntrack entry is translated back to IPv6 by
/// `flowplane_core::datapath::process_uplink_nat64_ingress` (reached from `process_uplink_rx`) and
/// delivered to the VM's tap — see the header comment on the (removed) ingress half below for why
/// this module no longer owns that translation.
use flowplane_core::err::DpErr;

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
//
// A tc-converted, resize-direction-corrected `nat64_ingress` (post-decap the growth is +20 —
// [InnerEth][InnerIPv4][L4] (34+L4) -> [InnerEth][InnerIPv6][L4] (54+L4) via `adjust_room(20,
// BPF_ADJ_ROOM_MAC)` — the mirror image of `tc_nat64_egress`'s `-20` shrink, reversed) was written
// and wired up here for P2 Task 4b, called from a hand-inlined `ingress.rs::try_nat64_ingress` peek
// ahead of `process_uplink_rx`. It was REVERTED: `try_nat64_ingress` + this fn's combined BPF stack
// frames pushed `uplink_rx`'s combined-call-stack over the verifier's 512B limit ("combined stack
// size of 2 calls is 608. Too large" — see the P2 Task 4b report). `uplink_rx` now delegates the
// whole CT_F_NAT64 ingress-return case to `flowplane_core::datapath::process_uplink_nat64_ingress`
// (reached internally by `process_uplink_rx`), whose `pkt.shrink_head(20)` still models the OLD
// pre-decap 74->54 shrink (frozen since 4a) — a disclosed, Task-5-owned staleness, same category as
// `flowplane_core::uplink::decap_and_rewrite`'s `shrink_head(IPV6_LEN)`. Fixing that AND restoring a
// verifier-safe (out-of-line, low-stack) hand-inlined fast path here are both follow-up work.
