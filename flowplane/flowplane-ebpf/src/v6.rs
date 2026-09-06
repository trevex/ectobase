use aya_ebpf::{bindings::TC_ACT_OK, programs::TcContext};
use flowplane_common::Local;
use flowplane_core::datapath::{process_uplink_v6, UplinkIn};
use flowplane_core::err::DpErr;

use crate::coreimpl::{GlobalMaps, RawPkt};
use crate::ingress::{execute, resolve_dsr_opt};
use crate::maps::LOCAL;
use crate::tunnel::get_tunnel_key;

/// tcx ingress for an inner-IPv6 frame, tail-called from `uplink_rx` (via `UPLINK_PROGS`) when the
/// decapped inner ethertype is IPv6 — see `ingress.rs::try_uplink_rx`'s dispatch. VNI comes from
/// `get_tunnel_key` (the kernel's `collect_md` decap stamped it as the skb's tunnel-key metadata —
/// NOT from an outer address, which no longer exists by the time this program runs).
///
/// P2 Task 4c: this now delegates ENTIRELY to the shared `flowplane_core::datapath::process_uplink_v6`
/// orchestrator — the SAME code the native sim exercises (closing the pre-existing v6-ingress
/// core/sim coverage gap) — instead of hand-inlining its own LB/firewall/conntrack/decap logic. Two
/// things this closes relative to the pre-4c hand-inlined version:
///   - reads the inner v6 header at `ETH_LEN` (post-decap), not the stale pre-decap
///     `ETH_LEN + IPV6_LEN` offset (that offset modeled the inner sitting BEHIND a still-present
///     outer header, which `collect_md` decap already stripped before this program ever runs — see
///     `process_uplink_v6`'s own doc comment);
///   - a `ROUTES6` miss that is not the WAN-edge sentinel now DROPS (fail-closed), not `TC_ACT_OK`
///     (fail-open) — closing the disclosed security gap where a genuine miss leaked decapped overlay
///     v6 bytes into this node's own kernel netns.
///
/// The ICMPv6-echo-to-VIP intercept the pre-4b inline path had is intentionally NOT ported (deferred
/// to its own M2+ feature spec, same as v4's dropped ICMP-echo/ICMP-error features — see the P2
/// Task-4c brief); v6 has no NAT/NAT64-return dispatch either (v4-only — those translate a v4 inner).
///
/// Uses [`RawPkt`] (scalar `data`/`data_end`), NOT `TcPkt` (the `&TcContext`-backed impl `ingress.rs`
/// uses for the v4 orchestrator), as the `Pkt` impl handed to `process_uplink_v6`: empirically, the
/// v6 firewall evaluator (`fw_eval_dir6`, which — unlike the v4 one — additionally calls
/// `icmp_type_code_v6`) compiled through `TcPkt`'s `&TcContext`-recomputing accessors in THIS calling
/// shape produced a kernel-verifier-rejected program (`R8 bitwise operator &= on pointer prohibited`
/// — an LLVM block-merging artifact, not a stack-budget issue: two unrelated source-level operations
/// landed at the same instruction address with conflicting register typing across their predecessors).
/// `RawPkt` captures `data`/`data_end` as plain `usize`s ONCE up front (no live context reference,
/// safe here since this path never resizes the frame) — the exact technique the pre-4c hand-inlined
/// version of this file already used for the same `fw_eval_dir6` call, and it eliminates the
/// miscompilation. `fw_eval_dir6` itself verifies fine through `TcPkt` on the EGRESS side
/// (`tc_guest_egress_v6`, `verify_tc_guest`), so this is scoped to `RawPkt` for the v6 INGRESS
/// program specifically, not a claim that `TcPkt` is broken in general (`uplink_rx`/`wan_rx`, and the
/// entire v4 orchestrator, use it without issue).
pub fn v6_uplink_rx(ctx: &TcContext) -> Result<i32, DpErr> {
    let vni = match get_tunnel_key(ctx.skb.skb) {
        Some((vni, _remote)) => vni,
        None => return Ok(TC_ACT_OK),
    };
    let local: &Local = LOCAL.get(0).ok_or(DpErr::NoRoute)?;
    // B7: recover the DSR Geneve option the edge dispatched (if any) off the SAME tunnel metadata
    // `get_tunnel_key` just read above — shared helper with `ingress.rs::try_uplink_rx`'s v4 mirror.
    let dsr = resolve_dsr_opt(ctx.skb.skb);
    let in_ = UplinkIn {
        vni,
        local,
        now: crate::conntrack::now(),
        dsr,
    };
    let mut pkt = RawPkt::new(ctx.data(), ctx.data_end());
    let mut maps = GlobalMaps;
    let out = process_uplink_v6(&mut pkt, &mut maps, &in_);
    Ok(execute(ctx, out.action, out.tunnel))
}
