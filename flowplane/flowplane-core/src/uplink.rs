//! Host-side uplink base-delivery seam. The non-LB/non-NAT tail of the eBPF `try_uplink_rx` after
//! the firewall + conntrack steps: strip the outer Eth+IPv6 (decap) and rewrite the inner Ethernet
//! for the guest. Kept byte-identical to the eBPF wrapper so the SAME code runs in eBPF and in the
//! native `SimNode`.
//!
//! Design note (option A): the firewall + conntrack steps stay in the eBPF wrapper as-is (they
//! already delegate to `flowplane_core::firewall::fw_eval_dir` / `conntrack::ct_create_default`, and
//! the hit path calls `ct_touch` which has no `Pkt`/`Maps` port yet). This seam covers ONLY the
//! decap + inner-Ethernet rewrite (the part the wrapper reimplemented inline). The sim composes the
//! real core fns — `fw_eval_dir`, `ct_create_default`, `decap_and_rewrite` — in the wrapper's order.

use crate::encap::{ETH_LEN, IPV6_LEN};
use crate::err::DpErr;
use crate::pkt::{Action, Pkt};

// `GW_MAC` (inner-eth src on host delivery) + `ETH_P_IP` are single-sourced in
// `flowplane_common::proto`; re-exported so `flowplane_core::uplink::{GW_MAC, ETH_P_IP}` keeps resolving.
pub use flowplane_common::proto::{ETH_P_IP, GW_MAC};

/// Strip the outer Eth+IPv6 tunnel header and rewrite the inner Ethernet for the guest, returning
/// the delivery `Action`. Byte-identical to the decap + inner-Eth-rewrite block of the eBPF
/// `try_uplink_rx` tail (lines ~290-304). Does NOT perform DNAT or execute the redirect — the
/// caller does those.
///
/// On entry the frame is `[OuterEth(14)][OuterIPv6(40)][inner IPv4 ...]`. `shrink_head(IPV6_LEN)`
/// strips 40 bytes from the front, leaving 14 bytes of room + the inner IPv4, which is then
/// rewritten into the inner Ethernet header (dst=guest_mac, src=GW_MAC, ethertype=IPv4).
///
/// Returns `Ok(Action::Redirect(tap_ifindex))` after successful decap+rewrite; `Err(DpErr::Bounds)`
/// if decap or bounds fail (matches the eBPF `Err` path).
#[inline(always)]
pub fn decap_and_rewrite<P: Pkt>(
    pkt: &mut P,
    tap_ifindex: u32,
    guest_mac: [u8; 6],
) -> Result<Action, DpErr> {
    // Strip outer Eth+IPv6, leaving room to write the inner Ethernet.
    if !pkt.shrink_head(IPV6_LEN) {
        return Err(DpErr::Bounds);
    }
    if pkt.len() < ETH_LEN {
        return Err(DpErr::Bounds);
    }
    let mut ok = true;
    ok &= pkt.write_bytes(0, &guest_mac); // dst = guest MAC
    ok &= pkt.write_bytes(6, &GW_MAC); // src = gateway MAC
    ok &= pkt.write_bytes(12, &ETH_P_IP.to_be_bytes()); // ethertype = IPv4
    if !ok {
        return Err(DpErr::Bounds);
    }
    Ok(Action::Redirect(tap_ifindex))
}

/// WAN-edge local-deliver (mechanism #4 of the ingress delivery-target reconstruction — see
/// `datapath::resolve_uplink_target`): on a `ROUTES` miss, if THIS node is registered as the WAN
/// edge (`UNDERLAY[LOCAL.underlay_ipv6]` carries the `UNDERLAY_LOCAL_DELIVER` sentinel — programmed
/// once by `Control::attach_edge`), strip the outer Eth+IPv6 tunnel header (same shape
/// [`decap_and_rewrite`] strips) and rewrite the exposed inner Ethernet so the LOCAL KERNEL (VyOS)
/// accepts + routes/masquerades it to the real WAN. Byte-identical to the eBPF
/// `ingress::edge_local_deliver` tail, ported over `Pkt` so the sim exercises the SAME mechanism.
///
/// `ethertype` is the INNER protocol being exposed (`ETH_P_IP` for a v4 inner — the only case wired
/// up here; a v6 inner is Task 4c). Returns `Action::Pass` on success (hand off to the kernel) or
/// `Action::Drop` on a bounds failure.
#[inline(always)]
pub fn edge_local_deliver<P: Pkt>(pkt: &mut P, uplink_mac: [u8; 6], ethertype: u16) -> Action {
    if !pkt.shrink_head(IPV6_LEN) {
        return Action::Drop;
    }
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
