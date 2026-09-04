//! Host-side uplink base-delivery seam. The non-LB/non-NAT tail of the eBPF `try_uplink_rx` after
//! the firewall + conntrack steps: rewrite the inner Ethernet for the guest. Kept byte-identical to
//! the eBPF wrapper so the SAME code runs in eBPF and in the native `SimNode`.
//!
//! Design note (option A): the firewall + conntrack steps stay in the eBPF wrapper as-is (they
//! already delegate to `flowplane_core::firewall::fw_eval_dir` / `conntrack::ct_create_default`, and
//! the hit path calls `ct_touch` which has no `Pkt`/`Maps` port yet). This seam covers ONLY the
//! inner-Ethernet rewrite (the part the wrapper reimplemented inline). The sim composes the real
//! core fns — `fw_eval_dir`, `ct_create_default`, `decap_and_rewrite` — in the wrapper's order.
//!
//! P2 Task 5: under Geneve `collect_md` the kernel decaps the outer Eth/IPv6/UDP/Geneve header
//! BEFORE either tcx ingress program runs — what used to be an outer-strip here (`shrink_head`)
//! is gone; only the inner-Ethernet rewrite (set the destination guest MAC for tap delivery)
//! remains. `decap_and_rewrite` keeps its name for continuity with the eBPF/anchor call sites, but
//! it no longer decaps anything — the kernel already did.

use crate::encap::ETH_LEN;
use crate::err::DpErr;
use crate::pkt::{Action, Pkt};

// `GW_MAC` (inner-eth src on host delivery) + `ETH_P_IP`/`ETH_P_IPV6` are single-sourced in
// `flowplane_common::proto`; re-exported so `flowplane_core::uplink::{GW_MAC, ETH_P_IP, ETH_P_IPV6}`
// keeps resolving.
pub use flowplane_common::proto::{ETH_P_IP, ETH_P_IPV6, GW_MAC};

/// Rewrite the inner Ethernet header for guest tap delivery, returning the delivery `Action`. Byte-
/// identical to the inner-Eth-rewrite tail of the eBPF `try_uplink_rx` (the outer-strip that used to
/// precede it is gone — the kernel `collect_md` geneve device already decapped before this program
/// runs). Does NOT perform DNAT or execute the redirect — the caller does those.
///
/// On entry the frame is already the decapped inner frame `[InnerEth(14)][InnerIPv4/v6 ...]` (exactly
/// what `get_tunnel_key` + the geneve device hand the tcx program). The inner Ethernet header is
/// rewritten in place (dst = delivery MAC, src=GW_MAC, ethertype=`ethertype`); the frame is NOT
/// resized. `ethertype` is `ETH_P_IP` for the v4 ingress path, `ETH_P_IPV6` for the v6 one (P2 Task
/// 4c) — the rewrite itself is protocol-agnostic, only the wire ethertype it stamps differs.
///
/// `l3` picks the inner dst MAC. For an L2 delivery tap (veth/tap, `l3 == false`) the dst is
/// `guest_mac`, as always. For an L3 netkit pod (`l3 == true`) the dst is the all-zero MAC:
/// SPIKE-PROVEN (Task B.5) — netkit is ETH-framed at the BPF hook, and the NOARP L3 pod device does
/// dst-MAC filtering, accepting only its own device MAC (`00:00:00:00:00:00`) or bcast/mcast; an
/// arbitrary unicast like `guest_mac` is dropped as `PACKET_OTHERHOST`. src MAC (`GW_MAC`) and the
/// ethertype are identical in both cases. No frame push/pop — the eth header is already present.
///
/// Returns `Ok(Action::Redirect(tap_ifindex))` after a successful rewrite; `Err(DpErr::Bounds)` if
/// the frame is too short (matches the eBPF `Err` path).
#[inline(always)]
pub fn decap_and_rewrite<P: Pkt>(
    pkt: &mut P,
    tap_ifindex: u32,
    guest_mac: [u8; 6],
    ethertype: u16,
    l3: bool,
) -> Result<Action, DpErr> {
    if pkt.len() < ETH_LEN {
        return Err(DpErr::Bounds);
    }
    // L3 netkit pod: deliver to the pod's zero device MAC (unicast guest_mac would be dropped as
    // PACKET_OTHERHOST by the NOARP pod). L2 tap: the guest MAC as always.
    let dst_mac = if l3 { [0u8; 6] } else { guest_mac };
    let mut ok = true;
    ok &= pkt.write_bytes(0, &dst_mac); // dst = delivery MAC (guest MAC on L2; zero MAC on L3)
    ok &= pkt.write_bytes(6, &GW_MAC); // src = gateway MAC
    ok &= pkt.write_bytes(12, &ethertype.to_be_bytes());
    if !ok {
        return Err(DpErr::Bounds);
    }
    Ok(Action::Redirect(tap_ifindex))
}

/// WAN-edge local-deliver (mechanism #4 of the ingress delivery-target reconstruction — see
/// `datapath::resolve_uplink_target`): on a `ROUTES` miss, if THIS node is registered as the WAN
/// edge (`UNDERLAY[LOCAL.underlay_ipv6]` carries the `UNDERLAY_LOCAL_DELIVER` sentinel — programmed
/// once by `Control::attach_edge`), rewrite the already-decapped inner Ethernet (the kernel
/// `collect_md` geneve device stripped the outer Eth/IPv6/UDP/Geneve header before this program
/// ran — same as [`decap_and_rewrite`]) so the LOCAL KERNEL (VyOS) accepts + routes/masquerades it
/// to the real WAN. Byte-identical to the eBPF `ingress::edge_local_deliver` tail, ported over `Pkt`
/// so the sim exercises the SAME mechanism.
///
/// `ethertype` is the INNER protocol being exposed (`ETH_P_IP` for a v4 inner — the only case wired
/// up here; a v6 inner is Task 4c). Returns `Action::Pass` on success (hand off to the kernel) or
/// `Action::Drop` on a bounds failure. Does NOT resize the frame.
#[inline(always)]
pub fn edge_local_deliver<P: Pkt>(pkt: &mut P, uplink_mac: [u8; 6], ethertype: u16) -> Action {
    if pkt.len() < ETH_LEN {
        return Action::Drop;
    }
    let mut ok = true;
    ok &= pkt.write_bytes(0, &uplink_mac); // dst = our uplink MAC
    ok &= pkt.write_bytes(6, &GW_MAC); // src = gateway MAC (locally-generated placeholder)
    ok &= pkt.write_bytes(12, &ethertype.to_be_bytes());
    if !ok {
        return Action::Drop;
    }
    Action::Pass
}
