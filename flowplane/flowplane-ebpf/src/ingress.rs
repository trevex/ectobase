//! tcx ingress on the geneve `collect_md` device (`uplink_rx`) + the WAN-edge return path
//! (`wan_rx`). The kernel decaps the outer Eth/IPv6/UDP/Geneve header before either program runs
//! (`collect_md` metadata dst), so the packet these programs see is exactly the inner frame the
//! sender's `tc_guest_tx`/`nat64_egress`/`wan_rx`-relay handed to the geneve device — VNI comes from
//! `get_tunnel_key` (the tunnel-key metadata the decap stamped), not from an outer address.
//!
//! Delivery-target resolution (four mechanisms — see the P2 Task-4 design doc) is owned by the
//! shared `flowplane_core::datapath` orchestrators (`process_uplink_rx`/`process_wan_rx`, the SAME
//! code the sim exercises); this module is just the tcx glue: source the VNI, dispatch v4 vs v6,
//! call the orchestrator, execute its verdict (plain redirect / tunnel-key re-stamp + geneve
//! redirect / pass-to-kernel / drop).

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_redirect, bpf_redirect_peer},
    programs::TcContext,
};
use flowplane_common::Local;
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
/// `#[inline(never)]`: shared by both `try_uplink_rx` (v4) and `v6::v6_uplink_rx`. Keeps the 24-byte
/// option buffer off the CALLER's own BPF stack frame — same out-of-lining discipline the core
/// `process_uplink`/`process_uplink_rx` call chain uses throughout (see
/// `flowplane_core::datapath`'s `#[inline(never)]` helpers) to stay under the verifier's combined
/// call-stack budget.
#[inline(never)]
pub(crate) fn resolve_dsr_opt(skb: *mut __sk_buff) -> Option<DsrOpt> {
    let mut opt_buf = [0u8; DSR_OPT_BUF_LEN as usize];
    if get_tunnel_opt(skb, &mut opt_buf) >= 0 {
        flowplane_core::dsr::decode(&opt_buf)
    } else {
        None
    }
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
    // B7: recover the DSR Geneve option the edge dispatched (if any) off the SAME tunnel metadata
    // `get_tunnel_key` just read above.
    let dsr = resolve_dsr_opt(ctx.skb.skb);
    let in_ = UplinkIn {
        vni,
        local,
        now: crate::conntrack::now(),
        dsr,
    };
    let mut pkt = TcPkt { ctx };
    let mut maps = GlobalMaps;
    let out = process_uplink_rx(&mut pkt, &mut maps, &in_);
    Ok(execute(ctx, out.action, out.tunnel))
}

/// WAN-edge return path (`wan_rx`, tcx on the WAN uplink): delegates entirely to
/// `flowplane_core::datapath::process_wan_rx` (VIP ingress + the neighbor-NAT relay carrying the
/// real owner VNI — see its doc comment for the bug that fixed), then executes its verdict.
pub fn try_wan_rx(ctx: &TcContext) -> Result<i32, DpErr> {
    let local: &Local = LOCAL.get(0).ok_or(DpErr::NoRoute)?;
    let in_ = WanRxIn { local };
    let mut pkt = TcPkt { ctx };
    let maps = GlobalMaps;
    let out = process_wan_rx(&mut pkt, &maps, &in_);
    Ok(execute(ctx, out.action, out.tunnel))
}
