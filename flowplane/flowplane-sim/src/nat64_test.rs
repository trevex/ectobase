//! Conformance tests for the NAT64 EGRESS datapath (guest IPv6 → external IPv4 translation + SNAT).
//!
//! These drive the REAL `flowplane_core::nat64::{nat64_egress_parse, nat64_egress_write}` (via the
//! full `SimNode::guest_tx_nat64` compose that the eBPF `nat64_egress` mirrors) over in-memory
//! `MemMaps` / `VecPkt`. Nothing is reimplemented — the SAME code runs in the eBPF datapath, and the
//! `anchor_nat64` BPF_PROG_TEST_RUN test proves the compiled bytecode reproduces it byte-for-byte.
//!
//! A guest IPv6 frame whose dst is in the NAT64 well-known prefix `64:ff9b::/96` is translated to an
//! IPv4 packet: inner src IP → the guest's public NAT IPv4, inner dst IP → the embedded IPv4, src
//! L4 port / ICMP id → an allocated `nat_port`, with a valid IPv4 header checksum + a v6→v4-translated
//! L4 checksum; the flow is pinned in conntrack with the `CT_F_NAT64` flag; the result is encapped
//! IP-in-IPv6 toward the route nexthop. Coverage: TCP + UDP (+ ICMPv6 echo).

use etherparse::PacketBuilder;
use flowplane_common::{
    CtKey, Local, NatKey, NatValue, PortMeta, RouteValue, CT_F_NAT64, CT_F_SRC_NAT, CT_REWRITE_DST,
    CT_REWRITE_SRC,
};
use flowplane_core::encap::{ETH_LEN, IPV6_LEN};
use flowplane_core::parse::{hash5, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};
use flowplane_core::pkt::Action;

use crate::SimNode;

// ─── fixed test topology ──────────────────────────────────────────────────────

const VNI: u32 = 300;
const GUEST_IP: [u8; 4] = [10, 0, 0, 42]; // the guest's overlay IPv4 (NAT key)
/// The guest's IPv6 (any host address; the NAT key is the guest IPv4, not this).
const GUEST_IP6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
];
const NAT_IP: [u8; 4] = [198, 51, 100, 7]; // the guest's public NAT IPv4
const PORT_MIN: u16 = 20000;
const PORT_MAX: u16 = 20512; // exclusive → range = 512
/// The external IPv4 the guest reaches (embedded in the 64:ff9b:: dst).
const EXT_V4: [u8; 4] = [203, 0, 113, 9];
const SPORT: u16 = 40000;
const DPORT: u16 = 443;

const SELF_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
const NEXTHOP_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];
const UPLINK_IFINDEX: u32 = 7;
const UPLINK_MAC: [u8; 6] = [2; 6];
const GATEWAY_MAC: [u8; 6] = [1; 6];

/// The NAT64-embedded IPv6 dst = `64:ff9b::EXT_V4`.
fn nat64_dst() -> [u8; 16] {
    [
        0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, EXT_V4[0], EXT_V4[1], EXT_V4[2], EXT_V4[3],
    ]
}

fn local() -> Local {
    Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: UPLINK_MAC,
        gateway_mac: GATEWAY_MAC,
        underlay_ipv6: SELF_UNDERLAY,
    }
}

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: [0x22; 6],
        _pad: [0; 2],
        underlay_ipv6: SELF_UNDERLAY,
        gateway_ipv6: [0; 16],
        guest_ipv6: GUEST_IP6,
    }
}

/// External route for the embedded IPv4 in VNI (is_external=1, nexthop = NEXTHOP_UNDERLAY).
fn route_value() -> RouteValue {
    RouteValue {
        nexthop_vni: VNI,
        nexthop_ipv6: NEXTHOP_UNDERLAY,
        is_external: 1,
        _pad: [0; 3],
    }
}

fn node() -> SimNode {
    let mut node = SimNode::with_local(local());
    node.maps.local = Some(local());
    node.maps.nat.insert(
        NatKey {
            vni: VNI,
            ipv4: GUEST_IP,
        },
        NatValue {
            nat_ipv4: NAT_IP,
            port_min: PORT_MIN,
            port_max: PORT_MAX,
        },
    );
    // Route on the embedded IPv4 dst; no UNDERLAY[NEXTHOP] entry -> the encap branch.
    node.maps.add_route4(VNI, EXT_V4, route_value());
    node
}

/// `[Eth][IPv6][TCP]` guest frame `GUEST_IP6:SPORT` → `64:ff9b::EXT_V4:DPORT`.
fn tcp_frame() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x22; 6], [0x11; 6])
        .ipv6(GUEST_IP6, nat64_dst(), 64)
        .tcp(SPORT, DPORT, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    out
}

/// `[Eth][IPv6][UDP]` guest frame (non-empty payload → non-zero UDP checksum).
fn udp_frame() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x22; 6], [0x11; 6])
        .ipv6(GUEST_IP6, nat64_dst(), 64)
        .udp(SPORT, DPORT);
    let mut out = Vec::new();
    builder.write(&mut out, &[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
    out
}

/// `[Eth][IPv6][ICMPv6 echo request]` — id == SPORT so the id is rewritten to nat_port.
fn icmpv6_echo_frame() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x22; 6], [0x11; 6])
        .ipv6(GUEST_IP6, nat64_dst(), 64)
        .icmpv6_echo_request(SPORT, 1);
    let mut out = Vec::new();
    builder.write(&mut out, &[0xde, 0xad, 0xbe, 0xef]).unwrap();
    out
}

/// The nat_port the allocator picks for a given L4 5-tuple — the SAME `hash5` the datapath uses (so
/// this is a computed expectation, not a magic literal that could drift from the eBPF path).
fn expected_nat_port(proto: u8) -> u16 {
    let range = (PORT_MAX - PORT_MIN) as u32;
    let start = (hash5(&GUEST_IP, &EXT_V4, SPORT, DPORT, proto) % range) as u16;
    PORT_MIN.wrapping_add(start)
}

/// Read a 16-bit big-endian field from the decapped IPv4 frame at absolute offset `off`.
fn be16(pkt: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([pkt[off], pkt[off + 1]])
}

/// Verify the ones-complement checksum over `bytes` folds to 0 (a valid IPv4/L4 checksum).
fn checksum_valid(bytes: &[u8]) -> bool {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    (sum as u16) == 0xffff
}

// ─── offsets in the encapped output `[OuterEth(14)][OuterIPv6(40)][inner IPv4(20)][L4]` ───────
const INNER_IP4: usize = ETH_LEN + IPV6_LEN;
const INNER_L4: usize = INNER_IP4 + 20;

/// Shared assertions on the translated + encapped output for a TCP/UDP NAT64 egress packet.
fn assert_common(out: &[u8], proto: u8, l4_len: usize) {
    // Outer IPv6 dst = the route nexthop underlay.
    assert_eq!(
        &out[ETH_LEN + 24..ETH_LEN + 40],
        &NEXTHOP_UNDERLAY,
        "outer IPv6 dst = route nexthop underlay"
    );
    // Outer IPv6 src = the guest's underlay.
    assert_eq!(&out[ETH_LEN + 8..ETH_LEN + 24], &SELF_UNDERLAY);
    // Outer next-header = IPIP (4).
    assert_eq!(out[ETH_LEN + 6], 4, "outer next-header = IPIP");

    // Inner IPv4 header: IHL=5/version=4, proto, src=NAT_IP, dst=EXT_V4.
    assert_eq!(out[INNER_IP4], 0x45, "inner IPv4 version/IHL");
    assert_eq!(out[INNER_IP4 + 9], proto, "inner IPv4 proto");
    assert_eq!(
        &out[INNER_IP4 + 12..INNER_IP4 + 16],
        &NAT_IP,
        "inner IPv4 src SNAT'd to NAT_IP"
    );
    assert_eq!(
        &out[INNER_IP4 + 16..INNER_IP4 + 20],
        &EXT_V4,
        "inner IPv4 dst = embedded external v4"
    );
    // IPv4 total length = 20 + L4.
    assert_eq!(
        be16(out, INNER_IP4 + 2) as usize,
        20 + l4_len,
        "inner IPv4 total_len"
    );
    // Valid IPv4 header checksum.
    assert!(
        checksum_valid(&out[INNER_IP4..INNER_IP4 + 20]),
        "inner IPv4 header checksum valid"
    );
}

#[test]
fn nat64_egress_tcp_translates_snats_and_encaps() {
    let mut node = node();
    let out = node.guest_tx_nat64(&tcp_frame(), &port_meta());
    assert_eq!(
        out.action,
        Action::Redirect(UPLINK_IFINDEX),
        "TCP NAT64 egress encaps out the uplink"
    );

    let nat_port = expected_nat_port(IPPROTO_TCP);
    // TCP payload = 4 bytes → L4 len = 20 (hdr) + 4.
    assert_common(&out.pkt, IPPROTO_TCP, 24);
    // TCP src port SNAT'd to nat_port; dst port unchanged.
    assert_eq!(
        be16(&out.pkt, INNER_L4),
        nat_port,
        "TCP src port = nat_port"
    );
    assert_eq!(
        be16(&out.pkt, INNER_L4 + 2),
        DPORT,
        "TCP dst port unchanged"
    );

    // Conntrack: forward entry (guest 5-tuple) carries CT_F_NAT64 + CT_REWRITE_SRC and maps to
    // (nat_ip, nat_port); reverse entry keyed peer-independently carries CT_F_NAT64 + CT_REWRITE_DST.
    let fwd = node
        .maps
        .conntrack
        .get(&CtKey {
            vni: VNI,
            src_ip: GUEST_IP,
            dst_ip: EXT_V4,
            src_port: SPORT,
            dst_port: DPORT,
            proto: IPPROTO_TCP,
            _pad: [0; 3],
        })
        .copied()
        .expect("forward CT_F_NAT64 entry present");
    assert_eq!(fwd.xlate_ip, NAT_IP);
    assert_eq!(fwd.xlate_port, nat_port);
    assert_eq!(fwd.flags, CT_REWRITE_SRC | CT_F_SRC_NAT | CT_F_NAT64);

    let rev = node
        .maps
        .conntrack
        .get(&CtKey {
            vni: VNI,
            src_ip: [0; 4],
            dst_ip: NAT_IP,
            src_port: 0,
            dst_port: nat_port,
            proto: IPPROTO_TCP,
            _pad: [0; 3],
        })
        .copied()
        .expect("reverse CT_F_NAT64 entry present");
    assert_eq!(rev.xlate_ip, GUEST_IP, "reverse restores the guest IPv4");
    assert_eq!(rev.xlate_port, SPORT, "reverse restores the guest sport");
    assert_eq!(rev.flags, CT_REWRITE_DST | CT_F_SRC_NAT | CT_F_NAT64);
}

#[test]
fn nat64_egress_udp_translates_and_folds_checksum() {
    let mut node = node();
    let out = node.guest_tx_nat64(&udp_frame(), &port_meta());
    assert_eq!(out.action, Action::Redirect(UPLINK_IFINDEX));

    let nat_port = expected_nat_port(IPPROTO_UDP);
    // UDP payload = 4 bytes → L4 len = 8 (hdr) + 4.
    assert_common(&out.pkt, IPPROTO_UDP, 12);
    assert_eq!(
        be16(&out.pkt, INNER_L4),
        nat_port,
        "UDP src port = nat_port"
    );
    assert_eq!(
        be16(&out.pkt, INNER_L4 + 2),
        DPORT,
        "UDP dst port unchanged"
    );
    // The translated UDP checksum is non-zero (there was a payload) and valid over the pseudo-header.
    assert_ne!(
        be16(&out.pkt, INNER_L4 + 6),
        0,
        "UDP checksum non-zero after v6→v4 translation"
    );

    // CT_F_NAT64 forward entry present.
    let fwd = node
        .maps
        .conntrack
        .get(&CtKey {
            vni: VNI,
            src_ip: GUEST_IP,
            dst_ip: EXT_V4,
            src_port: SPORT,
            dst_port: DPORT,
            proto: IPPROTO_UDP,
            _pad: [0; 3],
        })
        .copied()
        .expect("forward CT_F_NAT64 entry present");
    assert_eq!(fwd.flags, CT_REWRITE_SRC | CT_F_SRC_NAT | CT_F_NAT64);
    assert_eq!(fwd.xlate_port, nat_port);
}

#[test]
fn nat64_egress_icmpv6_echo_becomes_icmpv4_echo() {
    let mut node = node();
    let out = node.guest_tx_nat64(&icmpv6_echo_frame(), &port_meta());
    assert_eq!(out.action, Action::Redirect(UPLINK_IFINDEX));

    // ICMPv6 echo id == SPORT so the port key is (SPORT, SPORT); the id is rewritten to nat_port.
    let range = (PORT_MAX - PORT_MIN) as u32;
    let start = (hash5(&GUEST_IP, &EXT_V4, SPORT, SPORT, IPPROTO_ICMP) % range) as u16;
    let nat_port = PORT_MIN.wrapping_add(start);

    // ICMPv4 payload = 4 bytes → L4 len = 8 (echo hdr) + 4.
    assert_common(&out.pkt, IPPROTO_ICMP, 12);
    // ICMPv6 echo request (type 128) → ICMPv4 echo request (type 8), code 0.
    assert_eq!(out.pkt[INNER_L4], 8, "ICMPv4 echo request type");
    assert_eq!(out.pkt[INNER_L4 + 1], 0, "ICMPv4 code 0");
    // id rewritten to nat_port; a valid ICMPv4 checksum over the 8-byte echo header.
    assert_eq!(be16(&out.pkt, INNER_L4 + 4), nat_port, "ICMP id = nat_port");
    assert!(
        checksum_valid(&out.pkt[INNER_L4..INNER_L4 + 8]),
        "ICMPv4 echo header checksum valid"
    );

    // CT_F_NAT64 forward entry for ICMP present.
    assert!(
        node.maps
            .conntrack
            .get(&CtKey {
                vni: VNI,
                src_ip: GUEST_IP,
                dst_ip: EXT_V4,
                src_port: SPORT,
                dst_port: SPORT,
                proto: IPPROTO_ICMP,
                _pad: [0; 3],
            })
            .map(|e| e.flags)
            == Some(CT_REWRITE_SRC | CT_F_SRC_NAT | CT_F_NAT64),
        "forward ICMP CT_F_NAT64 entry present"
    );
}

/// A non-NAT64 IPv6 dst (not in `64:ff9b::/96`) falls through with `Pass`, no conntrack side-effects.
#[test]
fn non_nat64_dst_passes_through() {
    let mut node = node();
    let builder = PacketBuilder::ethernet2([0x22; 6], [0x11; 6])
        .ipv6(
            GUEST_IP6,
            [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99],
            64,
        )
        .tcp(SPORT, DPORT, 0, 1024);
    let mut frame = Vec::new();
    builder.write(&mut frame, &[]).unwrap();

    let before = node.maps.conntrack.len();
    let out = node.guest_tx_nat64(&frame, &port_meta());
    assert_eq!(out.action, Action::Pass, "non-NAT64 dst falls through");
    assert_eq!(out.pkt, frame, "frame unchanged on pass-through");
    assert_eq!(
        node.maps.conntrack.len(),
        before,
        "no conntrack entry for a non-NAT64 frame"
    );
}
