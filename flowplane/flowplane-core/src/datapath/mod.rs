//! Substrate-agnostic datapath orchestrators shared by the eBPF program and the native `SimNode`
//! harness. These compose the REAL per-step core fns (`lb_select_forward`,
//! `reforward`, `fw_eval_dir`, `ct_create_default`, `decap_and_rewrite`, metering) in the exact order
//! and gates of the eBPF program tails, over any `Pkt` + `Maps` implementation. The SAME code thus
//! runs under the sim and under the `BPF_PROG_TEST_RUN` anchor.
//!
//! The orchestrators are split per hook (review P1.2): [`uplink`] (ingress LB/base + NAT-return),
//! [`guest_tx`] (guest egress v4/v6/NAT64), [`nat64`] (NAT64 ingress reply), [`wan_rx`] (edge WAN-VIP
//! ingress), [`guest_local`] (ARP/ND + DHCPv4 responders). Every previously-`pub` item stays
//! reachable at `datapath::<name>` via the `pub use` re-exports below — the eBPF program, the sim,
//! and the anchor tests call these by those exact paths and must not change.

mod guest_local;
mod guest_tx;
mod nat64;
mod uplink;
mod wan_rx;

pub use guest_local::{process_guest_arp_nd, process_guest_dhcp4, GuestArpNdIn, GuestDhcp4In};
pub use guest_tx::{
    process_guest_tx, process_guest_tx_nat64, process_guest_tx_v6, GuestTxIn, GuestTxNat64In,
    GuestTxNat64Out, GuestTxOut,
};
pub use nat64::{process_uplink_nat64_ingress, UplinkNat64IngressIn};
pub use uplink::{
    process_uplink, process_uplink_nat_return, process_uplink_rx, process_uplink_v6, UplinkIn,
    UplinkNatReturnIn, UplinkOut,
};
pub use wan_rx::{process_wan_rx, WanRxIn, WanRxOut};

use crate::parse::{IPPROTO_TCP, IPPROTO_UDP};
use crate::pkt::Pkt;
use flowplane_common::csum::csum_replace4;

/// Rewrite an inbound frame's inner IPv4 DESTINATION `old` -> `new` (1:1 floating-IP DNAT),
/// fixing the IPv4 header checksum and the TCP/UDP L4 checksum incrementally. ICMP needs no L4
/// fixup (the ICMPv4 checksum does not cover addresses). Mirrors `nat.rs`'s SNAT read-modify-write
/// window pattern for eBPF-verifier friendliness (one dominating bound per access).
///
/// Shared by the ingress uplink DNAT arm ([`uplink::process_uplink`]) AND the edge WAN-VIP DSR
/// rewrite ([`wan_rx::process_wan_rx`]) — hence it lives here in `mod` rather than in either hook
/// module.
///
/// `#[inline(never)]`: keeps this out of `process_uplink`'s already-tight combined call stack (same
/// BPF-stack-relief discipline as `uplink_ingress_firewall_drop`).
#[inline(never)]
pub(crate) fn vip_dnat_rewrite<P: Pkt>(pkt: &mut P, ip_off: usize, old: &[u8; 4], new: &[u8; 4]) {
    // dst IP at ip_off + 16.
    if !pkt.write_array(ip_off + 16, new) {
        return;
    }
    // IP header checksum at ip_off + 10.
    if let Some(ipc) = pkt.read_u16_be(ip_off + 10) {
        let c = csum_replace4(ipc, old, new);
        pkt.write_array(ip_off + 10, &c.to_be_bytes());
    }
    let ihl = match pkt.read_u8(ip_off) {
        Some(b) => (b & 0x0f) as usize * 4,
        None => return,
    };
    let proto = match pkt.read_u8(ip_off + 9) {
        Some(p) => p,
        None => return,
    };
    let l4 = ip_off + ihl;
    if proto == IPPROTO_TCP {
        // TCP checksum at l4[16..18]. Window = 18 (single dominating bound).
        if let Some(mut h) = pkt.read_array::<18>(l4) {
            let c0 = u16::from_be_bytes([h[16], h[17]]);
            let c1 = csum_replace4(c0, old, new);
            h[16..18].copy_from_slice(&c1.to_be_bytes());
            pkt.write_array(l4, &h);
        }
    } else if proto == IPPROTO_UDP {
        // UDP checksum at l4[6..8]; a zero UDP checksum stays zero. Window = 8.
        if let Some(mut h) = pkt.read_array::<8>(l4) {
            let c0 = u16::from_be_bytes([h[6], h[7]]);
            if c0 != 0 {
                let c1 = csum_replace4(c0, old, new);
                h[6..8].copy_from_slice(&c1.to_be_bytes());
            }
            pkt.write_array(l4, &h);
        }
    }
    // ICMP (proto 1): no L4 checksum fixup — the ICMPv4 checksum does not cover the IP addresses.
}
