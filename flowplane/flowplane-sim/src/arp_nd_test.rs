//! Conformance for the guest-facing gateway responders (`SimNode::guest_arp_nd`, which runs the REAL
//! `flowplane_core::arp_nd::{arp_reply, nd_reply}` — the same code the eBPF `tc_guest_tx` datapath calls,
//! byte-parity-anchored in `flowplane/tests/anchor_arp_nd.rs`).
//!
//! ARP: a guest ARP request for the virtual gateway IPv4 must be rewritten in place into an ARP reply
//! — op=reply, sender = gateway MAC/IP, target = original requester, Ethernet src/dst swapped.
//! ND: a guest ICMPv6 Neighbor Solicitation for the gateway IPv6 must become a solicited Neighbor
//! Advertisement — type 136, solicited+override flags, target = gateway, target-LL-addr option =
//! gateway MAC, and a correct (non-zero) ICMPv6 checksum over the pseudo-header.

use flowplane_common::PortMeta;
use flowplane_core::pkt::Action;

use crate::{SimNode, VecPkt};

const VNI: u32 = 100;
const GATEWAY_IPV4: [u8; 4] = [10, 0, 0, 1];
const GATEWAY_IPV6: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// The reply MAC (== the port's `guest_mac`; the datapath answers with the guest's own MAC to present
/// a per-port virtual gateway).
const GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const REQUESTER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc];
const REQUESTER_IPV4: [u8; 4] = [10, 0, 0, 42];
const REQUESTER_IPV6: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42];
const INGRESS_IFINDEX: u32 = 7;

const ETH_LEN: usize = 14;
const IPV6_LEN: usize = 40;
const ARP_LEN: usize = 28;
const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_ICMPV6: u8 = 58;

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: REQUESTER_IPV4,
        gateway_ipv4: GATEWAY_IPV4,
        guest_mac: GATEWAY_MAC,
        l3: 0,
        _pad: [0; 1],
        underlay_ipv6: [0; 16],
        gateway_ipv6: GATEWAY_IPV6,
        guest_ipv6: REQUESTER_IPV6,
    }
}

/// A guest ARP REQUEST `who-has GATEWAY_IPV4 tell REQUESTER_IPV4` (broadcast). Ethernet + 28-byte ARP.
fn arp_request_frame() -> Vec<u8> {
    let mut f = vec![0u8; ETH_LEN + ARP_LEN];
    f[0..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&REQUESTER_MAC);
    f[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
    let a = ETH_LEN;
    f[a..a + 2].copy_from_slice(&1u16.to_be_bytes()); // htype = Ethernet
    f[a + 2..a + 4].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype = IPv4
    f[a + 4] = 6; // hlen
    f[a + 5] = 4; // plen
    f[a + 6..a + 8].copy_from_slice(&1u16.to_be_bytes()); // opcode = request
    f[a + 8..a + 14].copy_from_slice(&REQUESTER_MAC); // sha
    f[a + 14..a + 18].copy_from_slice(&REQUESTER_IPV4); // spa
    f[a + 24..a + 28].copy_from_slice(&GATEWAY_IPV4); // tpa = gateway
    f
}

/// A guest ICMPv6 Neighbor Solicitation for GATEWAY_IPV6. Ethernet + 40-byte IPv6 + 32-byte ICMPv6.
fn ns_frame() -> Vec<u8> {
    let mut f = vec![0u8; ETH_LEN + IPV6_LEN + 32];
    f[0..6].copy_from_slice(&[0x33, 0x33, 0xff, 0, 0, 0x42]); // solicited-node multicast dst MAC
    f[6..12].copy_from_slice(&REQUESTER_MAC);
    f[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
    let ip = ETH_LEN;
    f[ip] = 0x60;
    f[ip + 4..ip + 6].copy_from_slice(&32u16.to_be_bytes()); // payload length
    f[ip + 6] = IPPROTO_ICMPV6;
    f[ip + 7] = 255;
    f[ip + 8..ip + 24].copy_from_slice(&REQUESTER_IPV6); // src
    f[ip + 24..ip + 40].copy_from_slice(&[0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0x01]);
    let ic = ETH_LEN + IPV6_LEN;
    f[ic] = 135; // NS
    f[ic + 8..ic + 24].copy_from_slice(&GATEWAY_IPV6); // target
    f[ic + 24] = 1; // source LL addr option
    f[ic + 25] = 1;
    f[ic + 26..ic + 32].copy_from_slice(&REQUESTER_MAC);
    f
}

/// Fold-verify an ICMPv6 checksum: sum the pseudo-header (src+dst, len, next-header) + the 32-byte
/// ICMPv6 message; a correct checksum makes the one's-complement total fold to 0xffff.
fn icmp6_checksum_ok(reply: &[u8]) -> bool {
    let ip = ETH_LEN;
    let icmp = ETH_LEN + IPV6_LEN;
    let mut sum: u32 = 0;
    // pseudo-header: src (16) + dst (16).
    let mut k = 0;
    while k < 32 {
        sum += u16::from_be_bytes([reply[ip + 8 + k], reply[ip + 8 + k + 1]]) as u32;
        k += 2;
    }
    sum += 32; // upper-layer length
    sum += IPPROTO_ICMPV6 as u32; // next header
    let mut j = 0;
    while j < 32 {
        sum += u16::from_be_bytes([reply[icmp + j], reply[icmp + j + 1]]) as u32;
        j += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16 == 0xffff
}

#[test]
fn arp_request_becomes_reply() {
    let node = SimNode::new();
    let out = node.guest_arp_nd(&arp_request_frame(), &port_meta(), INGRESS_IFINDEX);

    // Reflected back to the guest via the ingress ifindex.
    assert_eq!(out.action, Action::Redirect(INGRESS_IFINDEX));
    assert_eq!(out.pkt.len(), ETH_LEN + ARP_LEN, "ARP reply is fixed-size");

    let r = &out.pkt;
    let a = ETH_LEN;
    // Ethernet: dst = original requester, src = gateway MAC.
    assert_eq!(&r[0..6], &REQUESTER_MAC, "eth dst = requester");
    assert_eq!(&r[6..12], &GATEWAY_MAC, "eth src = gateway MAC");
    assert_eq!(&r[12..14], &ETH_P_ARP.to_be_bytes(), "ethertype ARP");
    // ARP: op = reply(2); sender = gateway MAC/IP; target = original requester MAC/IP.
    assert_eq!(&r[a + 6..a + 8], &2u16.to_be_bytes(), "opcode = reply");
    assert_eq!(&r[a + 8..a + 14], &GATEWAY_MAC, "sender MAC = gateway MAC");
    assert_eq!(&r[a + 14..a + 18], &GATEWAY_IPV4, "sender IP = gateway IP");
    assert_eq!(&r[a + 18..a + 24], &REQUESTER_MAC, "target MAC = requester");
    assert_eq!(&r[a + 24..a + 28], &REQUESTER_IPV4, "target IP = requester");
}

#[test]
fn ns_becomes_neighbor_advertisement() {
    let node = SimNode::new();
    let out = node.guest_arp_nd(&ns_frame(), &port_meta(), INGRESS_IFINDEX);

    assert_eq!(out.action, Action::Redirect(INGRESS_IFINDEX));
    assert_eq!(out.pkt.len(), ETH_LEN + IPV6_LEN + 32, "NA is fixed-size");

    let r = &out.pkt;
    let ip = ETH_LEN;
    let ic = ETH_LEN + IPV6_LEN;
    // Ethernet: dst = requester, src = gateway MAC.
    assert_eq!(&r[0..6], &REQUESTER_MAC, "eth dst = requester");
    assert_eq!(&r[6..12], &GATEWAY_MAC, "eth src = gateway MAC");
    assert_eq!(&r[12..14], &ETH_P_IPV6.to_be_bytes(), "ethertype IPv6");
    // IPv6: src = gateway, dst = requester; next-header ICMPv6, hop limit 255, payload length 32.
    assert_eq!(
        &r[ip + 4..ip + 6],
        &32u16.to_be_bytes(),
        "payload length 32"
    );
    assert_eq!(r[ip + 6], IPPROTO_ICMPV6, "next header ICMPv6");
    assert_eq!(r[ip + 7], 255, "hop limit 255");
    assert_eq!(&r[ip + 8..ip + 24], &GATEWAY_IPV6, "IPv6 src = gateway");
    assert_eq!(
        &r[ip + 24..ip + 40],
        &REQUESTER_IPV6,
        "IPv6 dst = requester"
    );
    // ICMPv6 Neighbor Advertisement.
    assert_eq!(r[ic], 136, "ICMPv6 type = Neighbor Advertisement");
    assert_eq!(r[ic + 1], 0, "code 0");
    assert_eq!(r[ic + 4], 0x60, "flags = solicited(0x40) + override(0x20)");
    assert_eq!(&r[ic + 8..ic + 24], &GATEWAY_IPV6, "NA target = gateway");
    // target-link-layer-address option: type=2, len=1, gateway MAC.
    assert_eq!(r[ic + 24], 2, "option type = target LL addr");
    assert_eq!(r[ic + 25], 1, "option len = 1 (8 bytes)");
    assert_eq!(
        &r[ic + 26..ic + 32],
        &GATEWAY_MAC,
        "option addr = gateway MAC"
    );
    // Checksum: non-zero AND correct over the pseudo-header + NA message.
    let cks = u16::from_be_bytes([r[ic + 2], r[ic + 3]]);
    assert_ne!(cks, 0, "ICMPv6 checksum is non-zero");
    assert!(
        icmp6_checksum_ok(r),
        "ICMPv6 checksum verifies (folds to 0xffff)"
    );
}

/// A guest ICMPv6 Router Solicitation, padded to `RA_LEN` (86) to mimic the post-`change_tail`
/// buffer the eBPF glue hands `ra_reply` (the RA is larger than the RS).
fn rs_frame() -> Vec<u8> {
    let mut f = vec![0u8; ETH_LEN + IPV6_LEN + 32];
    f[0..6].copy_from_slice(&[0x33, 0x33, 0, 0, 0, 2]); // all-routers multicast dst MAC
    f[6..12].copy_from_slice(&REQUESTER_MAC);
    f[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
    let ip = ETH_LEN;
    f[ip] = 0x60;
    f[ip + 4..ip + 6].copy_from_slice(&8u16.to_be_bytes()); // RS payload length (pre-grow)
    f[ip + 6] = IPPROTO_ICMPV6;
    f[ip + 7] = 255;
    f[ip + 8..ip + 24].copy_from_slice(&REQUESTER_IPV6); // src = requester link-local
    f[ip + 24..ip + 40].copy_from_slice(&[0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]); // dst ff02::2
    let ic = ETH_LEN + IPV6_LEN;
    f[ic] = 133; // Router Solicitation
    f
}

#[test]
fn rs_becomes_router_advertisement() {
    const MTU: u32 = 1460;
    let mut pkt = VecPkt::from_bytes(&rs_frame());
    let ok = flowplane_core::arp_nd::ra_reply(&mut pkt, GATEWAY_IPV6, GATEWAY_MAC, MTU);
    assert!(ok, "RS is rewritten into an RA");

    let r = pkt.bytes();
    let ip = ETH_LEN;
    let ic = ETH_LEN + IPV6_LEN;
    // Ethernet: dst = requester, src = gateway (router) MAC.
    assert_eq!(&r[0..6], &REQUESTER_MAC, "eth dst = requester");
    assert_eq!(&r[6..12], &GATEWAY_MAC, "eth src = gateway MAC");
    // IPv6: src = gateway (link-local), dst = requester; hop limit 255, payload length 32.
    assert_eq!(&r[ip + 8..ip + 24], &GATEWAY_IPV6, "IPv6 src = gateway");
    assert_eq!(
        &r[ip + 24..ip + 40],
        &REQUESTER_IPV6,
        "IPv6 dst = requester"
    );
    assert_eq!(r[ip + 7], 255, "hop limit 255");
    assert_eq!(
        &r[ip + 4..ip + 6],
        &32u16.to_be_bytes(),
        "payload length 32"
    );
    // ICMPv6 Router Advertisement.
    assert_eq!(r[ic], 134, "ICMPv6 type = Router Advertisement");
    assert_eq!(r[ic + 1], 0, "code 0");
    assert_eq!(
        r[ic + 5] & 0x80,
        0x80,
        "Managed flag set (addressing via DHCPv6)"
    );
    assert_eq!(
        &r[ic + 6..ic + 8],
        &1800u16.to_be_bytes(),
        "router lifetime 1800s (default router)"
    );
    // Source Link-Layer Address option: type 1, len 1, gateway MAC.
    assert_eq!(r[ic + 16], 1, "option type = source LL addr");
    assert_eq!(r[ic + 17], 1, "option len = 1 (8 bytes)");
    assert_eq!(&r[ic + 18..ic + 24], &GATEWAY_MAC, "SLLA = gateway MAC");
    // MTU option: type 5, len 1, reserved(2), MTU(4).
    assert_eq!(r[ic + 24], 5, "option type = MTU");
    assert_eq!(r[ic + 25], 1, "option len = 1 (8 bytes)");
    assert_eq!(&r[ic + 28..ic + 32], &MTU.to_be_bytes(), "advertised MTU");
    // Checksum: non-zero AND correct over the pseudo-header + RA message.
    let cks = u16::from_be_bytes([r[ic + 2], r[ic + 3]]);
    assert_ne!(cks, 0, "ICMPv6 checksum is non-zero");
    assert!(
        icmp6_checksum_ok(r),
        "ICMPv6 checksum verifies (folds to 0xffff)"
    );
}

#[test]
fn non_rs_icmp6_is_not_an_ra() {
    // An NS frame (type 135) is NOT an RS → ra_reply returns false, buffer untouched.
    let mut pkt = VecPkt::from_bytes(&ns_frame());
    let before = pkt.bytes().to_vec();
    let ok = flowplane_core::arp_nd::ra_reply(&mut pkt, GATEWAY_IPV6, GATEWAY_MAC, 1460);
    assert!(!ok, "an NS is not an RS");
    assert_eq!(pkt.bytes(), &before[..], "non-RS frame unchanged");
}

#[test]
fn non_gateway_arp_passes_unchanged() {
    let node = SimNode::new();
    // ARP request for a DIFFERENT IP (not the gateway) → no reply, frame passes unchanged.
    let mut frame = arp_request_frame();
    let a = ETH_LEN;
    frame[a + 24..a + 28].copy_from_slice(&[10, 0, 0, 99]); // tpa != gateway
    let out = node.guest_arp_nd(&frame, &port_meta(), INGRESS_IFINDEX);
    assert_eq!(out.action, Action::Pass, "non-gateway ARP is not answered");
    assert_eq!(out.pkt, frame, "frame unchanged");
}
