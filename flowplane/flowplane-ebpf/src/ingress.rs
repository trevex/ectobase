//! tcx ingress on the geneve `collect_md` device (`uplink_dsr_note` + `uplink_rx`) + the WAN-edge
//! return path (`wan_rx`). The kernel decaps the outer Eth/IPv6/UDP/Geneve header before any of these
//! programs run (`collect_md` metadata dst), so the packet they see is exactly the inner frame the
//! sender's `tc_guest_tx`/`nat64_egress`/`wan_rx`-relay handed to the geneve device — VNI comes from
//! `get_tunnel_key` (the tunnel-key metadata the decap stamped), not from an outer address.
//!
//! `uplink_dsr_note` and `uplink_rx` are TWO SEPARATE tcx programs attached to the SAME geneve
//! ingress hook (`uplink_dsr_note` ordered to run FIRST — see `flowplane::loader`/`control::bring_up`'s
//! `LinkOrder::first()` attach), not one combined program (B7c). See `try_uplink_dsr_note`'s doc
//! comment for why: the DSR-map note cannot live on `uplink_rx`'s own call graph without either
//! inlining it (blows the verifier's combined-stack budget) or out-of-lining it (rejected — "R2
//! pointer arithmetic on pkt_end prohibited").
//!
//! Delivery-target resolution (four mechanisms — see the P2 Task-4 design doc) is owned by the
//! shared `flowplane_core::datapath` orchestrators (`process_uplink_rx`/`process_wan_rx`, the SAME
//! code the sim exercises); this module is just the tcx glue: source the VNI, dispatch v4 vs v6,
//! call the orchestrator, execute its verdict (plain redirect / tunnel-key re-stamp + geneve
//! redirect / pass-to-kernel / drop).

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT, TC_ACT_UNSPEC},
    helpers::{bpf_redirect, bpf_redirect_peer},
    programs::TcContext,
};
use flowplane_common::Local;
use flowplane_core::conntrack::{dsr_note, dsr_note6};
use flowplane_core::datapath::{process_uplink_rx, process_wan_rx, UplinkIn, WanRxIn};
use flowplane_core::encap::TunnelEncap;
use flowplane_core::err::DpErr;
use flowplane_core::pkt::Action;

use aya_ebpf::bindings::__sk_buff;
use flowplane_common::DsrOpt;

use crate::coreimpl::{GlobalMaps, TcPkt};
use crate::maps::LOCAL;
use crate::parse::{ETH_LEN, ETH_P_IP, ETH_P_IPV6};
use crate::tunnel::{
    apply_encap, get_tunnel_key, get_tunnel_opt, redirect as tunnel_redirect, DSR_OPT_BUF_LEN,
};

/// B7: recover the DSR Geneve option the edge dispatched (if any) off `skb`'s tunnel metadata —
/// counterpart to `get_tunnel_key` for the option TLV. `>= 0` means the option was present; a
/// negative return (no option / not a DSR flow) yields `None`, a byte-for-byte no-op downstream.
///
/// `#[inline(never)]`: keeps the 24-byte option buffer off the CALLER's own BPF stack frame — same
/// out-of-lining discipline the core `process_uplink`/`process_uplink_rx` call chain uses throughout
/// (see `flowplane_core::datapath`'s `#[inline(never)]` helpers) to stay under the verifier's
/// combined call-stack budget. B7c: the only caller is now `try_uplink_dsr_note` below — `try_uplink_rx`
/// / `v6::v6_uplink_rx` no longer call it (the DSR option is read/noted entirely in the separate
/// `uplink_dsr_note` tcx program, before either of those programs ever runs).
#[inline(never)]
pub(crate) fn resolve_dsr_opt(skb: *mut __sk_buff) -> Option<DsrOpt> {
    let mut opt_buf = [0u8; DSR_OPT_BUF_LEN as usize];
    if get_tunnel_opt(skb, &mut opt_buf) >= 0 {
        flowplane_core::dsr::decode(&opt_buf)
    } else {
        None
    }
}

/// B7c: tcx ingress "pre-program" on the geneve `collect_md` device (see `main.rs::uplink_dsr_note`),
/// attached to run BEFORE `uplink_rx` on the SAME hook. Its ONLY job is the DSR reverse-VIP note
/// (`flowplane_core::conntrack::dsr_note`/`dsr_note6`) that used to live inside
/// `process_uplink`/`process_uplink_v6` (via the now-removed `UplinkIn::dsr`) — moved out because:
///   - inlining the DSR `ct_key` build (~48B) into `uplink_rx`'s own frame pushed its combined
///     call-stack over the eBPF verifier's 512-byte budget (`uplink_rx`(288) ->
///     `uplink_ingress_firewall_drop`(280) -> leaf(8) = 576 > 512, and `main` was already at the
///     ceiling on this shared path before B7 added the note);
///   - out-of-lining the note instead (a `#[inline(never)]` helper taking `pkt` + calling into `Maps`)
///     hit "R2 pointer arithmetic on pkt_end prohibited": a pkt-taking + map-calling subprogram can't
///     survive a call boundary once `pkt` has crossed it.
///
/// A SEPARATE tcx program gets its OWN fresh 512B stack, so the inline `ct_key` is free here. This
/// program is deliberately tiny: `get_tunnel_key` + `resolve_dsr_opt` + (on `Some`) one `dsr_note`/
/// `dsr_note6` call — nothing else.
///
/// ALWAYS returns `TC_ACT_UNSPEC`: the kernel's tcx multi-prog dispatcher treats a `SchedClassifier`
/// program's `-1` return as `TCX_NEXT` (the two share the same numeric value; see
/// `aya_ebpf::bindings::{TC_ACT_UNSPEC, tcx_action_base::TCX_NEXT}`) — "continue to the next program
/// in the chain" — so `uplink_rx` always runs next, unconditionally. This program NEVER drops and
/// NEVER short-circuits delivery, even when the tunnel metadata / DSR option is absent or malformed
/// (returning `TC_ACT_OK`/0 here instead would be `TCX_PASS` — a FINAL verdict that would skip
/// `uplink_rx` entirely, silently breaking every uplink packet).
///
/// NOTE (scope, flagged for review): unlike the pre-B7c inline note, this does NOT re-run
/// `uplink_rx`'s own LB selection to confirm this node is actually the chosen local backend before
/// noting the VIP — it notes unconditionally whenever the DSR option is present on this node's
/// uplink. In practice `wan_rx` only ever stamps the option on a frame it is ALSO tunnel-keying
/// toward this exact backend's node_vtep, so arriving here with the option set already implies this
/// node is the intended backend; this program does not (cannot, cheaply, on its own stack) re-verify
/// that independently. See the B7c commit message.
pub fn try_uplink_dsr_note(ctx: &TcContext) -> i32 {
    let vni = match get_tunnel_key(ctx.skb.skb) {
        Some((vni, _remote)) => vni,
        None => return TC_ACT_UNSPEC,
    };
    let opt = match resolve_dsr_opt(ctx.skb.skb) {
        Some(opt) => opt,
        None => return TC_ACT_UNSPEC,
    };
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN > data_end {
        return TC_ACT_UNSPEC;
    }
    // Same post-decap inner-ethertype dispatch as `try_uplink_rx` (offset 12 of the inner frame).
    let ethertype = u16::from_be(unsafe {
        core::ptr::read_unaligned((data as *const u8).add(12) as *const u16)
    });
    let pkt = TcPkt { ctx };
    let mut maps = GlobalMaps;
    let now = crate::conntrack::now();
    if ethertype == ETH_P_IPV6 {
        dsr_note6(&pkt, &mut maps, ETH_LEN, vni, &opt.vip, now);
    } else if ethertype == ETH_P_IP {
        let vip = [opt.vip[0], opt.vip[1], opt.vip[2], opt.vip[3]];
        dsr_note(&pkt, &mut maps, ETH_LEN, vni, &vip, now);
    }
    TC_ACT_UNSPEC
}

/// Execute an `Action` + optional `TunnelEncap` decision from a `flowplane_core::datapath`
/// orchestrator. An LB-remote-backend reforward / neighbor-NAT relay hit (`Some(tunnel)`) re-stamps
/// the Geneve tunnel key toward the new remote and redirects to the geneve device — no byte write:
/// the packet is still exactly the decapped inner frame the kernel handed us, and the geneve device
/// re-encaps it on transmit. Otherwise the `Action` alone decides: `Redirect` is a plain tc redirect
/// (guest tap delivery), `Pass` hands the frame to the local kernel (WAN-edge local-deliver), `Drop`
/// shoots it.
///
/// `pub(crate)` (P2 Task 4c): shared with `v6::v6_uplink_rx`, now that it also dispatches to a
/// `flowplane_core::datapath` orchestrator's `Action`/`TunnelEncap` pair instead of hand-executing
/// its own redirect/pass/drop. Still `#[inline(always)]` — this crosses a MODULE boundary, not a
/// bpf-to-bpf CALL boundary, so it inlines directly into each program's own function body at compile
/// time either way; no verifier stack cost from being shared.
#[inline(always)]
pub(crate) fn execute(ctx: &TcContext, action: Action, tunnel: Option<TunnelEncap>) -> i32 {
    if let Some(tunnel) = tunnel {
        if !apply_encap(ctx.skb.skb, &tunnel) {
            return TC_ACT_SHOT;
        }
        return tunnel_redirect();
    }
    match action {
        Action::Redirect(ifindex) => unsafe { bpf_redirect(ifindex, 0) as i32 },
        // Local delivery to a veth/netkit guest: inject at the pod-netns peer's ingress in the same
        // softirq (skips the primary's xmit + host-stack re-entry). Only produced for peer_capable
        // targets (see flowplane_core::uplink::decap_and_rewrite).
        Action::RedirectPeer(ifindex) => unsafe { bpf_redirect_peer(ifindex, 0) as i32 },
        Action::Pass => TC_ACT_OK,
        Action::Drop => TC_ACT_SHOT,
    }
}

/// tcx ingress on the geneve device. Dispatches on the DECAPPED inner frame's own ethertype (offset
/// 12 — the guest's original inner Ethernet header, preserved verbatim through the tunnel since the
/// egress encap arm never rewrites it): IPv6 tail-calls the dedicated v6 program (fresh BPF stack —
/// mirrors the pre-4b split, still hand-inlined pending Task 4c's v6 core orchestrator); IPv4 goes
/// through the shared core `process_uplink_rx` orchestrator (base / NAT-return / NAT64-return / LB
/// dispatch all happen INSIDE it). Anything else passes through.
pub fn try_uplink_rx(ctx: &TcContext) -> Result<i32, DpErr> {
    let vni = match get_tunnel_key(ctx.skb.skb) {
        Some((vni, _remote)) => vni,
        None => return Ok(TC_ACT_OK),
    };
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN > data_end {
        return Ok(TC_ACT_OK);
    }
    let ethertype = u16::from_be(unsafe {
        core::ptr::read_unaligned((data as *const u8).add(12) as *const u16)
    });
    if ethertype == ETH_P_IPV6 {
        // TAIL-CALL the dedicated v6 program (fresh 512B stack) — the v6 firewall + conntrack
        // structures overflow this program's own frame when run inline (same reasoning as the
        // pre-4b XDP split). tail_call only returns on failure (slot empty) → passthrough.
        let _ =
            unsafe { crate::maps::UPLINK_PROGS.tail_call(ctx, flowplane_common::UPLINK_PROG_V6) };
        return Ok(TC_ACT_OK);
    }
    if ethertype != ETH_P_IP {
        return Ok(TC_ACT_OK);
    }
    let local: &Local = LOCAL.get(0).ok_or(DpErr::NoRoute)?;
    // The CT_F_NAT64 ingress-return guest_ipv6 gap (P2 Task 4b) is fixed (P2 Task 5): `UplinkIn` no
    // longer carries a `guest_ipv6` placeholder at all — `process_uplink_rx` reads
    // `PORT_META[tap_ifindex].guest_ipv6` itself, AFTER resolving the delivery tap internally, which
    // is the only point that value is actually knowable.
    //
    // B7c: the DSR Geneve option is no longer read/threaded here — `UplinkIn` is back to its
    // DSR-free (main-equivalent) shape. The DSR reverse-VIP note now runs entirely in the separate
    // `uplink_dsr_note` tcx pre-program (see `try_uplink_dsr_note` below), which runs BEFORE this
    // program on the same geneve ingress hook: inlining the DSR note's `ct_key` build into `uplink_rx`
    // pushed its combined call-stack over the verifier's 512-byte budget (`resolve_uplink_target`'s
    // out-of-lining alone was not enough headroom), and out-of-lining the note itself hit "R2 pointer
    // arithmetic on pkt_end prohibited" (a pkt-taking + map-calling subprogram can't survive a call
    // boundary once `pkt` crosses it). A separate tcx program gets its own fresh 512B stack instead.
    let in_ = UplinkIn {
        vni,
        local,
        now: crate::conntrack::now(),
    };
    let mut pkt = TcPkt { ctx };
    let mut maps = GlobalMaps;
    let out = process_uplink_rx(&mut pkt, &mut maps, &in_);
    Ok(execute(ctx, out.action, out.tunnel))
}

/// WAN-edge return path (`wan_rx`, tcx on the WAN uplink): delegates entirely to
/// `flowplane_core::datapath::process_wan_rx` (VIP ingress + the neighbor-NAT relay carrying the
/// real owner VNI — see its doc comment for the bug that fixed), then executes its verdict.
///
/// On a VIP hit `out.dsr` is `Some` (B7b: the DSR option lives on `WanRxOut`, not `TunnelEncap` —
/// only this program's edge encode ever sets it). This is handled here, NOT via the shared
/// `execute()` (which stays key-only, shared with `try_uplink_rx`/`v6_uplink_rx` — neither of which
/// ever carries a DSR option): stamp the tunnel key via `apply_encap`, then — only when `dsr` is
/// present — attach the Geneve DSR TLV via `set_tunnel_opt` (MUST come after the key; see its doc),
/// before redirecting to the geneve device.
pub fn try_wan_rx(ctx: &TcContext) -> Result<i32, DpErr> {
    let local: &Local = LOCAL.get(0).ok_or(DpErr::NoRoute)?;
    let in_ = WanRxIn { local };
    let mut pkt = TcPkt { ctx };
    let maps = GlobalMaps;
    let out = process_wan_rx(&mut pkt, &maps, &in_);
    if let Some(tunnel) = out.tunnel {
        if !apply_encap(ctx.skb.skb, &tunnel) {
            return Ok(TC_ACT_SHOT);
        }
        if let Some(opt) = out.dsr {
            let buf = flowplane_core::dsr::encode(&opt);
            if !crate::tunnel::set_tunnel_opt(ctx.skb.skb, &buf) {
                return Ok(TC_ACT_SHOT);
            }
        }
        return Ok(tunnel_redirect());
    }
    Ok(execute(ctx, out.action, None))
}
