//! NAT ICMP-error relay (v4) — the SNAT counterpart of the LB relay in `icmp_error_relay_test.rs`.
//!
//! An ICMP error returning from the internet is addressed to the `nat_ip`, and the port that
//! identifies the flow is NOT in the outer header — it is the SOURCE port of the quoted packet the
//! error carries. The plain NAT return demuxes on `(nat_ip, dport)` read from the OUTER header, and
//! for an ICMP error those bytes are the "unused"/next-hop-MTU field, not a port. So the edge's
//! `neighbor_nat_lookup_any` and the owner's reverse conntrack both computed a garbage port and the
//! error was dropped — breaking PMTUD and every unreachable for all SNATed traffic.
//!
//! Relaying it correctly is RFC 5508 §3.2 ICMP translation: the flow is identified from the quoted
//! packet, and BOTH copies of the address have to be rewritten — the outer destination (so it
//! reaches the guest) and the quoted source (so the guest's stack matches it to its own socket) —
//! with every affected checksum folded, including the ICMP checksum, which covers the quoted packet.

use flowplane_common::{
    CtEntry, CtKey, IfaceValue, Local, NeighborNatEntry, CT_F_SRC_NAT, CT_REWRITE_DST,
};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::pkt::Action;

use crate::{MemMaps, SimNode, VecPkt};

// ─── topology ─────────────────────────────────────────────────────────────────
const VNI: u32 = 200;
/// The guest's overlay identity, and the port it really used.
const GUEST_IP: [u8; 4] = [10, 0, 0, 42];
const GUEST_PORT: u16 = 50000;
/// The public SNAT identity the guest's traffic left with.
const NAT_IP: [u8; 4] = [192, 0, 2, 7];
const NAT_PORT: u16 = 1500;
/// The external server the guest was talking to.
const EXT_IP: [u8; 4] = [203, 0, 113, 9];
const EXT_PORT: u16 = 443;
/// The router out on the internet that emitted the ICMP error.
const ROUTER_IP: [u8; 4] = [198, 51, 100, 1];

const GUEST_TAP: u32 = 77;
const GUEST_MAC: [u8; 6] = [0x66; 6];
const OWNER_UL: [u8; 16] = ul(0xbb);
const EDGE_UL: [u8; 16] = ul(0xee);

/// ICMP type 3 = Destination Unreachable; code 4 = Fragmentation Needed (the PMTUD case).
const ICMP_DEST_UNREACH: u8 = 3;
const ICMP_FRAG_NEEDED: u8 = 4;

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

/// Ones-complement sum over `b`, folded to 16 bits. A valid checksummed region sums to 0xffff.
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

fn ipv4_hdr(src: [u8; 4], dst: [u8; 4], proto: u8, total_len: u16) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0] = 0x45; // v4, IHL=5
    h[2..4].copy_from_slice(&total_len.to_be_bytes());
    h[8] = 64; // TTL
    h[9] = proto;
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&dst);
    let csum = !ones_complement_sum(&h);
    h[10..12].copy_from_slice(&csum.to_be_bytes());
    h
}

/// `[Eth][IPv4 ROUTER->NAT_IP proto=ICMP][ICMP err][quoted IPv4 NAT_IP:NAT_PORT->EXT:EXT_PORT + 8B L4]`
///
/// The ICMP checksum is computed for real, so the rewrite's checksum folding is actually verified
/// rather than assumed.
fn icmp_error_to_nat_ip(err_type: u8, err_code: u8, quoted_proto: u8) -> Vec<u8> {
    // The quoted packet: what the guest sent, as it appeared on the wire (post-SNAT).
    let mut quoted = Vec::new();
    quoted.extend_from_slice(&ipv4_hdr(NAT_IP, EXT_IP, quoted_proto, 20 + 8));
    quoted.extend_from_slice(&NAT_PORT.to_be_bytes()); // quoted L4 sport = the NAT port
    quoted.extend_from_slice(&EXT_PORT.to_be_bytes()); // quoted L4 dport
    quoted.extend_from_slice(&[0u8; 4]); // seq/ack bytes of the truncated L4 header

    // ICMP: type, code, csum, then 4 bytes (for frag-needed: unused(2) + next-hop MTU(2)).
    let mut icmp = vec![err_type, err_code, 0, 0, 0, 0, 0x05, 0xdc]; // MTU 1500
    icmp.extend_from_slice(&quoted);
    let csum = !ones_complement_sum(&icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    let mut frame = vec![
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x08, 0x00,
    ];
    frame.extend_from_slice(&ipv4_hdr(ROUTER_IP, NAT_IP, 1, (20 + icmp.len()) as u16));
    frame.extend_from_slice(&icmp);
    frame
}

/// Assert the IPv4 header at `off` and the ICMP message after it both carry valid checksums.
fn assert_checksums_valid(frame: &[u8], off: usize, what: &str) {
    assert_eq!(
        ones_complement_sum(&frame[off..off + 20]),
        0xffff,
        "{what}: outer IPv4 header checksum must be valid"
    );
    let icmp = &frame[off + 20..];
    assert_eq!(
        ones_complement_sum(icmp),
        0xffff,
        "{what}: ICMP checksum (which covers the quoted packet) must be valid"
    );
    // The quoted IPv4 header carries its own checksum too.
    let q = off + 20 + 8;
    assert_eq!(
        ones_complement_sum(&frame[q..q + 20]),
        0xffff,
        "{what}: quoted IPv4 header checksum must be valid"
    );
}

/// The reverse conntrack entry `snat_egress` pins: keyed peer-independently on
/// `(vni, 0, nat_ip, 0, nat_port)`, restoring the guest's real address + port.
fn seed_reverse_ct(maps: &mut MemMaps) {
    maps.nat_ips.insert((VNI, NAT_IP));
    maps.conntrack.insert(
        CtKey {
            vni: VNI,
            src_ip: [0; 4],
            dst_ip: NAT_IP,
            src_port: 0,
            dst_port: NAT_PORT,
            proto: 6,
            _pad: [0; 3],
        },
        CtEntry {
            last_seen: 0,
            xlate_ip: GUEST_IP,
            xlate_port: GUEST_PORT,
            flags: CT_REWRITE_DST | CT_F_SRC_NAT,
            tcp_state: 0,
            fwall_action: 0,
            _pad: [0; 7],
        },
    );
}

fn owner_node() -> SimNode {
    let mut n = SimNode::with_local(local_for(OWNER_UL));
    n.maps.local = Some(local_for(OWNER_UL));
    n.maps.add_iface(
        VNI,
        GUEST_IP,
        IfaceValue {
            tap_ifindex: GUEST_TAP,
            is_local: 1,
            underlay_ipv6: OWNER_UL,
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    seed_reverse_ct(&mut n.maps);
    n
}

// ─── the flow is identified from the quoted packet, not the outer header ──────

#[test]
fn nat_icmp_error_origin_reads_the_quoted_source() {
    let frame = icmp_error_to_nat_ip(ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, 6);
    let pkt = VecPkt::from_bytes(&frame);
    assert_eq!(
        flowplane_core::nat::nat_icmp_error_origin(&pkt, ETH_LEN),
        Some((NAT_IP, NAT_PORT, 6)),
        "the (nat_ip, nat_port) identifying the flow comes from the QUOTED packet's src/sport"
    );
}

#[test]
fn nat_icmp_error_origin_ignores_non_errors_and_unsupported_quotes() {
    // ICMP echo request (type 8) is not an error — it carries no quoted packet.
    let echo = icmp_error_to_nat_ip(8, 0, 6);
    assert_eq!(
        flowplane_core::nat::nat_icmp_error_origin(&VecPkt::from_bytes(&echo), ETH_LEN),
        None,
        "only ICMP ERRORS (3/11/12) quote a packet"
    );
    // A quoted ICMP (not TCP/UDP) has no port to identify a NAT flow with.
    let quoted_icmp = icmp_error_to_nat_ip(ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, 1);
    assert_eq!(
        flowplane_core::nat::nat_icmp_error_origin(&VecPkt::from_bytes(&quoted_icmp), ETH_LEN),
        None,
        "a quoted non-TCP/UDP flow is not relayable"
    );
}

// ─── the owner restores the guest in BOTH copies of the address ──────────────

#[test]
fn owner_delivers_the_icmp_error_to_the_guest_rewritten_for_its_socket() {
    let mut n = owner_node();
    let frame = icmp_error_to_nat_ip(ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, 6);

    let out = n.uplink_rx(&frame, VNI, &local_for(OWNER_UL));
    assert_eq!(
        out.action,
        Action::Redirect(GUEST_TAP),
        "an ICMP error for an established SNAT flow must reach the guest that owns it"
    );

    // Outer destination: the guest, so the frame is deliverable on the overlay.
    assert_eq!(
        &out.pkt[ETH_LEN + 16..ETH_LEN + 20],
        &GUEST_IP,
        "outer dst must be rewritten nat_ip -> guest"
    );
    // Quoted packet: the guest's own address and port, so its stack can match the error to the
    // socket that sent the offending packet. Without this the guest discards the error.
    let q = ETH_LEN + 20 + 8;
    assert_eq!(
        &out.pkt[q + 12..q + 16],
        &GUEST_IP,
        "quoted src must be rewritten nat_ip -> guest"
    );
    assert_eq!(
        u16::from_be_bytes([out.pkt[q + 20], out.pkt[q + 21]]),
        GUEST_PORT,
        "quoted sport must be rewritten nat_port -> the guest's real port"
    );
    // The external peer in the quoted packet is untouched — it is what identifies the flow.
    assert_eq!(&out.pkt[q + 16..q + 20], &EXT_IP, "quoted dst unchanged");
    assert_eq!(
        u16::from_be_bytes([out.pkt[q + 22], out.pkt[q + 23]]),
        EXT_PORT,
        "quoted dport unchanged"
    );
    // The error itself must survive intact — the MTU is the whole point of the PMTUD case.
    assert_eq!(
        (out.pkt[ETH_LEN + 20], out.pkt[ETH_LEN + 21]),
        (ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED),
        "ICMP type/code preserved"
    );
    assert_eq!(
        u16::from_be_bytes([out.pkt[ETH_LEN + 26], out.pkt[ETH_LEN + 27]]),
        1500,
        "the advertised next-hop MTU must survive the relay"
    );

    assert_checksums_valid(&out.pkt, ETH_LEN, "after relay");
}

#[test]
fn owner_drops_an_icmp_error_for_an_unknown_flow() {
    let mut n = owner_node();
    // Same nat_ip, but a port no flow ever allocated.
    n.maps.conntrack.clear();
    let frame = icmp_error_to_nat_ip(ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, 6);
    assert_eq!(
        n.uplink_rx(&frame, VNI, &local_for(OWNER_UL)).action,
        Action::Drop,
        "an ICMP error that matches no established SNAT flow has no guest to deliver to"
    );
}

// ─── the edge relays it to the node owning the port block ─────────────────────

#[test]
fn edge_relays_the_icmp_error_to_the_port_block_owner() {
    let mut e = SimNode::with_local(local_for(EDGE_UL));
    e.maps.local = Some(local_for(EDGE_UL));
    // The owner advertised its (nat_ip, port-block) on the route bus; the edge installed a
    // neighbor-NAT return entry for it.
    e.maps.neighbor_nat.push(NeighborNatEntry {
        underlay: OWNER_UL,
        nat_ip: NAT_IP,
        vni: VNI,
        port_min: 1024,
        port_max: 2048,
        enabled: 1,
        _pad: [0; 3],
    });

    let frame = icmp_error_to_nat_ip(ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, 6);
    let out = e.wan_rx(&frame);

    assert_eq!(
        out.tunnel.map(|t| t.remote),
        Some(OWNER_UL),
        "the edge must relay the error toward the node owning the quoted packet's nat_port"
    );
    assert_eq!(
        out.pkt, frame,
        "the edge relays byte-unchanged; the rewrite happens on the owner"
    );
}

#[test]
fn edge_drops_an_icmp_error_for_an_unowned_port() {
    let mut e = SimNode::with_local(local_for(EDGE_UL));
    e.maps.local = Some(local_for(EDGE_UL));
    // A block that does NOT contain NAT_PORT.
    e.maps.neighbor_nat.push(NeighborNatEntry {
        underlay: OWNER_UL,
        nat_ip: NAT_IP,
        vni: VNI,
        port_min: 40000,
        port_max: 41000,
        enabled: 1,
        _pad: [0; 3],
    });

    let frame = icmp_error_to_nat_ip(ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, 6);
    let out = e.wan_rx(&frame);
    assert_eq!(
        out.tunnel, None,
        "no owner for that port: nothing to relay to"
    );
}
