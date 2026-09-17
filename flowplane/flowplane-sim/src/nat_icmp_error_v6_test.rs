//! NAT66 ICMPv6-error relay — v6 sibling of `nat_icmp_error_test.rs`.
//!
//! Same defect and same shape as the v4 case: an ICMPv6 error returning from the internet is
//! addressed to the `nat_ip6` and carries no port of its own (`l4_ports_v6`' ICMPv6 arm reads what
//! is really the Packet-Too-Big MTU field as an "id"), so the flow has to be identified from the
//! packet the error quotes.
//!
//! One real difference: an ICMPv6 checksum covers a **pseudo-header that includes the outer source
//! and destination addresses**, so rewriting the outer destination changes it — where the v4 ICMP
//! checksum did not care. Conversely a quoted IPv6 header has no checksum of its own to fix. The
//! tests below recompute the ICMPv6 checksum over its pseudo-header to prove both folds land.

use flowplane_common::{CtEntry6, CtKey6, IfaceValue, Local, NeighborNat6Entry, CT_REWRITE_DST};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::pkt::Action;

use crate::{MemMaps, SimNode, VecPkt};

// ─── topology ─────────────────────────────────────────────────────────────────
const VNI: u32 = 300;
const GUEST_V6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42];
const GUEST_PORT: u16 = 50000;
/// The public NAT66 source identity the guest's traffic left with.
const NAT_IP6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0x07];
const NAT_PORT: u16 = 1500;
/// The external server the guest was talking to.
const EXT_V6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
const EXT_PORT: u16 = 443;
/// The router out on the internet that emitted the error.
const ROUTER_V6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];

const GUEST_TAP: u32 = 88;
const GUEST_MAC: [u8; 6] = [0x66; 6];
const OWNER_UL: [u8; 16] = ul(0xbb);
const EDGE_UL: [u8; 16] = ul(0xee);

const IPPROTO_ICMPV6: u8 = 58;
/// ICMPv6 type 2 = Packet Too Big — the PMTUD case; its 4 header bytes carry the MTU.
const ICMPV6_PACKET_TOO_BIG: u8 = 2;

const fn ul(last: u8) -> [u8; 16] {
    [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last]
}

fn local_for(underlay: [u8; 16]) -> Local {
    Local {
        uplink_ifindex: 7,
        uplink_mac: [2; 6],
        gateway_mac: [3; 6],
        underlay_ipv6: underlay,
    }
}

// ─── frame construction ───────────────────────────────────────────────────────

fn ones_complement_sum(b: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < b.len() {
        sum += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
        i += 2;
    }
    if i < b.len() {
        sum += (b[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn ipv6_hdr(src: [u8; 16], dst: [u8; 16], next_hdr: u8, payload_len: u16) -> [u8; 40] {
    let mut h = [0u8; 40];
    h[0] = 0x60; // version 6
    h[4..6].copy_from_slice(&payload_len.to_be_bytes());
    h[6] = next_hdr;
    h[7] = 64; // hop limit
    h[8..24].copy_from_slice(&src);
    h[24..40].copy_from_slice(&dst);
    h
}

/// The ICMPv6 pseudo-header sum: src(16) + dst(16) + upper-layer length(4) + next header(4, with
/// three zero bytes). RFC 8200 §8.1.
fn icmpv6_pseudo_sum(src: &[u8; 16], dst: &[u8; 16], icmp_len: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(src);
    b.extend_from_slice(dst);
    b.extend_from_slice(&icmp_len.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, IPPROTO_ICMPV6]);
    b
}

/// `[Eth][IPv6 ROUTER->NAT_IP6 nh=ICMPv6][ICMPv6 err][quoted IPv6 NAT_IP6:NAT_PORT->EXT + 8B L4]`,
/// with a correctly computed ICMPv6 checksum (over its pseudo-header + message).
fn icmpv6_error_to_nat_ip(err_type: u8, quoted_next_hdr: u8) -> Vec<u8> {
    let mut quoted = Vec::new();
    quoted.extend_from_slice(&ipv6_hdr(NAT_IP6, EXT_V6, quoted_next_hdr, 8));
    quoted.extend_from_slice(&NAT_PORT.to_be_bytes()); // quoted L4 sport = the NAT port
    quoted.extend_from_slice(&EXT_PORT.to_be_bytes()); // quoted L4 dport
    quoted.extend_from_slice(&[0u8; 4]);

    // ICMPv6: type, code, checksum(2), then 4 bytes — the MTU for Packet Too Big.
    let mut icmp = vec![err_type, 0, 0, 0, 0, 0, 0x05, 0xdc]; // MTU 1500
    icmp.extend_from_slice(&quoted);
    let mut to_sum = icmpv6_pseudo_sum(&ROUTER_V6, &NAT_IP6, icmp.len() as u32);
    to_sum.extend_from_slice(&icmp);
    let csum = !ones_complement_sum(&to_sum);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    let mut frame = vec![
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x86, 0xDD,
    ];
    frame.extend_from_slice(&ipv6_hdr(
        ROUTER_V6,
        NAT_IP6,
        IPPROTO_ICMPV6,
        icmp.len() as u16,
    ));
    frame.extend_from_slice(&icmp);
    frame
}

/// Recompute the ICMPv6 checksum over the pseudo-header the frame now carries and assert it is
/// valid. This is what catches a fold that forgot the outer-address (pseudo-header) delta.
fn assert_icmpv6_checksum_valid(frame: &[u8], what: &str) {
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&frame[ETH_LEN + 8..ETH_LEN + 24]);
    dst.copy_from_slice(&frame[ETH_LEN + 24..ETH_LEN + 40]);
    let icmp = &frame[ETH_LEN + 40..];
    let mut to_sum = icmpv6_pseudo_sum(&src, &dst, icmp.len() as u32);
    to_sum.extend_from_slice(icmp);
    assert_eq!(
        ones_complement_sum(&to_sum),
        0xffff,
        "{what}: ICMPv6 checksum must be valid over its pseudo-header (incl. the rewritten dst)"
    );
}

fn seed_reverse_nat_ct6(maps: &mut MemMaps) {
    maps.nat_ips6.insert((VNI, NAT_IP6));
    maps.nat_ct6.insert(
        CtKey6 {
            vni: VNI,
            src_ip: [0; 16],
            dst_ip: NAT_IP6,
            src_port: 0,
            dst_port: NAT_PORT,
            proto: 6,
            _pad: [0; 3],
        },
        CtEntry6 {
            last_seen: 0,
            xlate_ip6: GUEST_V6,
            xlate_port: GUEST_PORT,
            flags: CT_REWRITE_DST,
            tcp_state: 0,
            _pad: [0; 4],
        },
    );
}

fn owner_node() -> SimNode {
    let mut n = SimNode::with_local(local_for(OWNER_UL));
    n.maps.local = Some(local_for(OWNER_UL));
    n.maps.add_iface6(
        VNI,
        GUEST_V6,
        IfaceValue {
            tap_ifindex: GUEST_TAP,
            is_local: 1,
            underlay_ipv6: OWNER_UL,
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    seed_reverse_nat_ct6(&mut n.maps);
    n
}

// ─── identity comes from the quoted packet ───────────────────────────────────

#[test]
fn nat_icmp_error_origin6_reads_the_quoted_source() {
    let frame = icmpv6_error_to_nat_ip(ICMPV6_PACKET_TOO_BIG, 6);
    assert_eq!(
        flowplane_core::nat::nat_icmp_error_origin6(&VecPkt::from_bytes(&frame), ETH_LEN),
        Some((NAT_IP6, NAT_PORT, 6)),
        "the (nat_ip6, nat_port) identifying the flow comes from the QUOTED packet"
    );
}

#[test]
fn nat_icmp_error_origin6_ignores_non_errors_and_unsupported_quotes() {
    // Echo request (128) is not an error and quotes nothing.
    let echo = icmpv6_error_to_nat_ip(128, 6);
    assert_eq!(
        flowplane_core::nat::nat_icmp_error_origin6(&VecPkt::from_bytes(&echo), ETH_LEN),
        None,
        "only ICMPv6 ERRORS (1-4) quote a packet"
    );
    // A quoted ICMPv6 flow has no port to demux a NAT66 binding on.
    let quoted_icmp = icmpv6_error_to_nat_ip(ICMPV6_PACKET_TOO_BIG, IPPROTO_ICMPV6);
    assert_eq!(
        flowplane_core::nat::nat_icmp_error_origin6(&VecPkt::from_bytes(&quoted_icmp), ETH_LEN),
        None,
        "a quoted non-TCP/UDP flow is not relayable"
    );
}

// ─── the owner restores the guest in both copies ─────────────────────────────

#[test]
fn owner_delivers_the_icmpv6_error_to_the_guest_rewritten_for_its_socket() {
    let mut n = owner_node();
    let frame = icmpv6_error_to_nat_ip(ICMPV6_PACKET_TOO_BIG, 6);

    let out = n.uplink_v6(&frame, VNI, &local_for(OWNER_UL));
    assert_eq!(
        out.action,
        Action::Redirect(GUEST_TAP),
        "an ICMPv6 error for an established NAT66 flow must reach the guest that owns it"
    );

    assert_eq!(
        &out.pkt[ETH_LEN + 24..ETH_LEN + 40],
        &GUEST_V6,
        "outer dst must be rewritten nat_ip6 -> guest"
    );
    // Quoted IPv6 sits after the 40-byte outer header + the 8-byte ICMPv6 header.
    let q = ETH_LEN + 40 + 8;
    assert_eq!(
        &out.pkt[q + 8..q + 24],
        &GUEST_V6,
        "quoted src must be rewritten nat_ip6 -> guest"
    );
    assert_eq!(
        u16::from_be_bytes([out.pkt[q + 40], out.pkt[q + 41]]),
        GUEST_PORT,
        "quoted sport must be rewritten nat_port -> the guest's real port"
    );
    assert_eq!(
        &out.pkt[q + 24..q + 40],
        &EXT_V6,
        "the quoted external peer is what identifies the flow; unchanged"
    );
    assert_eq!(
        u16::from_be_bytes([out.pkt[ETH_LEN + 46], out.pkt[ETH_LEN + 47]]),
        1500,
        "the advertised MTU must survive the relay — it is the point of Packet Too Big"
    );

    assert_icmpv6_checksum_valid(&out.pkt, "after relay");
}

#[test]
fn owner_drops_an_icmpv6_error_for_an_unknown_flow() {
    let mut n = owner_node();
    n.maps.nat_ct6.clear();
    let frame = icmpv6_error_to_nat_ip(ICMPV6_PACKET_TOO_BIG, 6);
    assert_eq!(
        n.uplink_v6(&frame, VNI, &local_for(OWNER_UL)).action,
        Action::Drop,
        "an ICMPv6 error matching no established NAT66 flow has no guest to deliver to"
    );
}

// ─── the edge relays to the port-block owner ─────────────────────────────────

#[test]
fn edge_relays_the_icmpv6_error_to_the_port_block_owner() {
    let mut e = SimNode::with_local(local_for(EDGE_UL));
    e.maps.local = Some(local_for(EDGE_UL));
    e.maps.neighbor_nat6.push(NeighborNat6Entry {
        underlay: OWNER_UL,
        nat_ip6: NAT_IP6,
        vni: VNI,
        port_min: 1024,
        port_max: 2048,
        enabled: 1,
        _pad: [0; 3],
    });

    let frame = icmpv6_error_to_nat_ip(ICMPV6_PACKET_TOO_BIG, 6);
    let out = e.wan_rx(&frame);
    assert_eq!(
        out.tunnel.map(|t| t.remote),
        Some(OWNER_UL),
        "the edge must relay toward the node owning the quoted packet's nat_port"
    );
    assert_eq!(
        out.pkt, frame,
        "the edge relays byte-unchanged; the rewrite happens on the owner"
    );
}
