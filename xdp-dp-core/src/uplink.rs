//! Host-side uplink base-delivery seam. The non-LB/non-NAT tail of the eBPF `try_uplink_rx` after
//! the firewall + conntrack steps: strip the outer Eth+IPv6 (decap) and rewrite the inner Ethernet
//! for the guest. Kept byte-identical to the eBPF wrapper so the SAME code runs in eBPF and in the
//! native `SimNode`.
//!
//! Design note (option A): the firewall + conntrack steps stay in the eBPF wrapper as-is (they
//! already delegate to `xdp_dp_core::firewall::fw_eval_dir` / `conntrack::ct_create_default`, and
//! the hit path calls `ct_touch` which has no `Pkt`/`Maps` port yet). This seam covers ONLY the
//! decap + inner-Ethernet rewrite (the part the wrapper reimplemented inline). The sim composes the
//! real core fns — `fw_eval_dir`, `ct_create_default`, `decap_and_rewrite` — in the wrapper's order.

use crate::encap::{ETH_LEN, IPV6_LEN};
use crate::pkt::{Action, Pkt};

/// Gateway MAC written as the inner-Ethernet source on host delivery. MUST match the eBPF
/// `arp_nd::GW_MAC` exactly (Task 8 byte-parity anchor).
pub const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Inner-Ethernet ethertype for delivered IPv4 frames.
pub const ETH_P_IP: u16 = 0x0800;

/// Strip the outer Eth+IPv6 tunnel header and rewrite the inner Ethernet for the guest, returning
/// the delivery `Action`. Byte-identical to the decap + inner-Eth-rewrite block of the eBPF
/// `try_uplink_rx` tail (lines ~290-304). Does NOT perform DNAT or execute the redirect — the
/// caller does those.
///
/// On entry the frame is `[OuterEth(14)][OuterIPv6(40)][inner IPv4 ...]`. `shrink_head(IPV6_LEN)`
/// strips 40 bytes from the front, leaving 14 bytes of room + the inner IPv4, which is then
/// rewritten into the inner Ethernet header (dst=guest_mac, src=GW_MAC, ethertype=IPv4).
///
/// Returns `Ok(Action::Redirect(tap_ifindex))` after successful decap+rewrite; `Err(())` if decap
/// or bounds fail (matches the eBPF `Err` path).
#[inline(always)]
pub fn decap_and_rewrite<P: Pkt>(
    pkt: &mut P,
    tap_ifindex: u32,
    guest_mac: [u8; 6],
) -> Result<Action, ()> {
    // Strip outer Eth+IPv6, leaving room to write the inner Ethernet.
    if !pkt.shrink_head(IPV6_LEN) {
        return Err(());
    }
    if pkt.len() < ETH_LEN {
        return Err(());
    }
    let mut ok = true;
    ok &= pkt.write_bytes(0, &guest_mac); // dst = guest MAC
    ok &= pkt.write_bytes(6, &GW_MAC); // src = gateway MAC
    ok &= pkt.write_bytes(12, &ETH_P_IP.to_be_bytes()); // ethertype = IPv4
    if !ok {
        return Err(());
    }
    Ok(Action::Redirect(tap_ifindex))
}
