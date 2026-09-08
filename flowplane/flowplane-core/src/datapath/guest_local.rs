//! Guest-facing local responders that never leave the node: the ARP/ND gateway responder
//! ([`process_guest_arp_nd`]) and the DHCPv4 responder ([`process_guest_dhcp4`]). Split out of the
//! datapath god-file per review P1.2; behavior-preserving.

use crate::arp_nd::{arp_reply, nd_reply};
use crate::decap::GW_MAC;
use crate::dhcp;
use crate::maps::Maps;
use crate::pkt::{Action, Pkt};

/// Inputs for [`process_guest_arp_nd`]. Gateway is advertised at the shared router MAC `GW_MAC`.
pub struct GuestArpNdIn {
    pub gateway_ipv4: [u8; 4],
    pub gateway_ipv6: [u8; 16],
    pub ingress_ifindex: u32,
}

/// Guest-facing ARP/ND gateway responder, in place on `pkt`. Mirrors the eBPF `try_guest_tx` head:
/// ARP request for the gateway → ARP reply, else ICMPv6 NS for the gateway → NA, both from `GW_MAC`;
/// on a hit `Redirect(ingress_ifindex)`, else `Pass`.
pub fn process_guest_arp_nd<P: Pkt>(pkt: &mut P, in_: &GuestArpNdIn) -> Action {
    if arp_reply(pkt, in_.gateway_ipv4, GW_MAC) || nd_reply(pkt, in_.gateway_ipv6, GW_MAC) {
        Action::Redirect(in_.ingress_ifindex)
    } else {
        Action::Pass
    }
}

/// Inputs for [`process_guest_dhcp4`]. The assigned/gateway IPv4 + reply MTU/DNS/host come from
/// `meta` + the node's `DHCP_CONFIG`/`DHCP_META[ingress_ifindex]`.
pub struct GuestDhcp4In {
    pub guest_ipv4: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub ingress_ifindex: u32,
}

/// Guest DHCPv4 responder, in place on `pkt`. Mirrors the eBPF `guest_dhcp` glue: parse the
/// DISCOVER/REQUEST (Pass on non-DHCP), resize to the constant `dhcp::REPLY_LEN` (`adjust_tail`), then
/// write the fixed OFFER/ACK; `Redirect(ingress_ifindex)` on success else `Pass`.
pub fn process_guest_dhcp4<P: Pkt, M: Maps>(pkt: &mut P, maps: &M, in_: &GuestDhcp4In) -> Action {
    let req = match dhcp::parse(&*pkt) {
        Some(r) => r,
        None => return Action::Pass,
    };
    pkt.set_tail(dhcp::REPLY_LEN);
    let ok = dhcp::write(
        pkt,
        &req,
        in_.guest_ipv4,
        in_.gateway_ipv4,
        GW_MAC,
        maps,
        in_.ingress_ifindex,
    );
    if ok {
        Action::Redirect(in_.ingress_ifindex)
    } else {
        Action::Pass
    }
}
