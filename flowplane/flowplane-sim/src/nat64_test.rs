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
//! L4 checksum; the flow is pinned in conntrack with the `CT_F_NAT64` flag; the result carries the
//! `TunnelEncap{vni, remote}` decision toward the route nexthop (NOT outer bytes — see
//! `flowplane_core::encap`). Coverage: TCP + UDP (+ ICMPv6 echo).

use etherparse::PacketBuilder;
use flowplane_common::{
    CtKey, Local, NatKey, NatValue, PortMeta, RouteValue, CT_F_NAT64, CT_F_SRC_NAT, CT_REWRITE_DST,
    CT_REWRITE_SRC,
};
use flowplane_core::encap::{TunnelEncap, ETH_LEN, IPV6_LEN};
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
        l3: 0,
        _pad: [0; 1],
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

// ─── offsets in the translated (NOT outer-wrapped — see `TunnelEncap`) output
// `[Eth(14)][inner IPv4(20)][L4]` ───────
const INNER_IP4: usize = ETH_LEN;
const INNER_L4: usize = INNER_IP4 + 20;

/// Shared assertions on the translated output for a TCP/UDP NAT64 egress packet. The tunnel
/// decision (route nexthop) is asserted separately by each caller via `out.tunnel`.
fn assert_common(out: &[u8], proto: u8, l4_len: usize) {
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
    assert_eq!(
        out.tunnel,
        Some(TunnelEncap {
            vni: VNI,
            remote: NEXTHOP_UNDERLAY,
        }),
        "tunnel decision carries the route's vni + nexthop underlay"
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
    assert_eq!(
        out.tunnel,
        Some(TunnelEncap {
            vni: VNI,
            remote: NEXTHOP_UNDERLAY,
        }),
        "tunnel decision carries the route's vni + nexthop underlay"
    );

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
    assert_eq!(
        out.tunnel,
        Some(TunnelEncap {
            vni: VNI,
            remote: NEXTHOP_UNDERLAY,
        }),
        "tunnel decision carries the route's vni + nexthop underlay"
    );

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

// ══════════════════════════════════════════════════════════════════════════════
// NAT64 INGRESS conformance (external IPv4 reply → guest IPv6 translation)
//
// These drive the REAL `flowplane_core::nat64::{nat64_ingress_parse, nat64_ingress_write}` via the
// full `SimNode::uplink_nat64_ingress` compose that the eBPF `nat64_ingress` mirrors. An external
// IPv4 reply arrives POST-decap as `[InnerEth(14)][InnerIPv4(20)][L4]` (P2 Task 5: the kernel
// `collect_md` geneve device already stripped the outer Eth/IPv6/UDP/Geneve header — the sim models
// exactly that, not a byte-written wire frame; see `sim.rs`'s module doc), inner dst = the SNAT'd
// NAT_IP, inner src = the external server EXT_V4, L4 dst port = the SNAT'd nat_port — whose reverse
// conntrack entry carries `CT_F_NAT64` + `CT_REWRITE_DST` is reverse-NAT'd (guest IPv4 + orig port
// restored) then EXPANDED (a net +20 GROW, not the old -20 shrink — see
// `process_uplink_nat64_ingress`'s doc comment) to `[Eth][innerIPv6][L4]`: inner IPv6 dst = the
// guest's IPv6, src = `64:ff9b::EXT_V4`, TCP/UDP checksum re-based to the IPv6 pseudo-header (ICMPv4
// echo-reply → ICMPv6 echo-reply). Coverage: TCP + UDP + ICMP. PINNED literals + valid-checksum
// assertions.
// ══════════════════════════════════════════════════════════════════════════════

use flowplane_common::CtEntry;

const IPPROTO_ICMPV6: u8 = 58;
const TAP_IFINDEX: u32 = 9;
const GUEST_MAC: [u8; 6] = [0x22; 6];

/// The reverse (peer-independent) conntrack entry the egress allocator stored: restores the guest
/// IPv4 + orig port, and flags the flow as NAT64 for the ingress expansion.
fn rev_ct(orig_sport: u16) -> CtEntry {
    CtEntry {
        last_seen: 0,
        xlate_ip: GUEST_IP,
        xlate_port: orig_sport,
        flags: CT_REWRITE_DST | CT_F_SRC_NAT | CT_F_NAT64,
        tcp_state: 0,
        fwall_action: 0,
        _pad: [0; 7],
    }
}

/// The `64:ff9b::EXT_V4` IPv6 src the ingress reconstructs from the reply's inner IPv4 src.
fn nat64_src() -> [u8; 16] {
    [
        0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, EXT_V4[0], EXT_V4[1], EXT_V4[2], EXT_V4[3],
    ]
}

/// Prepend a 14-byte inner Ethernet header to a bare `[IPv4][L4]` reply, producing the POST-decap
/// frame `[InnerEth(14)][InnerIPv4][L4]` the ingress dispatch receives. The Ethernet header's
/// content is never read by `ct_apply`/`nat64_ingress_parse` (both operate from `ETH_LEN` onward) —
/// it only needs to occupy 14 bytes, exactly as the sender's own inner Ethernet would ride the
/// tunnel unchanged.
fn ingress_frame(inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ETH_LEN + inner.len());
    out.extend_from_slice(&UPLINK_MAC);
    out.extend_from_slice(&GATEWAY_MAC);
    out.extend_from_slice(&flowplane_core::uplink::ETH_P_IP.to_be_bytes());
    out.extend_from_slice(inner);
    out
}

/// Inner IPv4 reply `EXT_V4:DPORT → NAT_IP:nat_port` (pre-`ct_apply`, valid v4 checksums). Built with
/// etherparse (dummy Ethernet), then the 14-byte Ethernet is stripped to leave `[IPv4][L4]`.
fn inner_reply(proto: u8, nat_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0; 6], [0; 6]).ipv4(EXT_V4, NAT_IP, 63);
    let mut full = Vec::new();
    match proto {
        IPPROTO_TCP => builder
            .tcp(DPORT, nat_port, 0, 1024)
            .write(&mut full, &[0x01, 0x02, 0x03, 0x04])
            .unwrap(),
        IPPROTO_UDP => builder
            .udp(DPORT, nat_port)
            .write(&mut full, &[0xaa, 0xbb, 0xcc, 0xdd])
            .unwrap(),
        _ => unreachable!(),
    }
    full[ETH_LEN..].to_vec()
}

/// Verify the reconstructed guest IPv6 header (offsets in the `[Eth][IPv6][L4]` output frame).
fn assert_ingress_ipv6(out: &[u8], next_hdr: u8, payload_len: usize) {
    // Ethernet: dst = guest MAC, src = GW_MAC, ethertype IPv6.
    assert_eq!(
        &out[0..6],
        &GUEST_MAC,
        "guest-facing Ethernet dst = guest MAC"
    );
    assert_eq!(
        &out[12..14],
        &0x86DDu16.to_be_bytes(),
        "guest-facing ethertype IPv6"
    );
    // IPv6 header at ETH_LEN.
    assert_eq!(out[ETH_LEN] & 0xf0, 0x60, "IPv6 version 6");
    assert_eq!(
        be16(out, ETH_LEN + 4) as usize,
        payload_len,
        "IPv6 payload length = L4 length"
    );
    assert_eq!(out[ETH_LEN + 6], next_hdr, "IPv6 next-header");
    assert_eq!(
        out[ETH_LEN + 7],
        63,
        "IPv6 hop-limit copied from inner v4 TTL"
    );
    assert_eq!(
        &out[ETH_LEN + 8..ETH_LEN + 24],
        &nat64_src(),
        "IPv6 src = 64:ff9b::EXT_V4"
    );
    assert_eq!(
        &out[ETH_LEN + 24..ETH_LEN + 40],
        &GUEST_IP6,
        "IPv6 dst = guest IPv6"
    );
}

/// Verify an IPv6 TCP/UDP checksum folds to 0 over its pseudo-header. `l4` is the absolute L4 offset;
/// `l4_len` the L4 length. Faithful ones-complement sum over pseudo-header (src+dst+len+nexthdr) + L4.
fn v6_l4_checksum_valid(
    out: &[u8],
    src6: &[u8; 16],
    dst6: &[u8; 16],
    nexthdr: u8,
    l4: usize,
    l4_len: usize,
) -> bool {
    let mut sum: u32 = 0;
    for chunk in src6.chunks(2).chain(dst6.chunks(2)) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += l4_len as u32; // upper-layer length (< 65536 → high word 0)
    sum += nexthdr as u32;
    let mut i = l4;
    while i + 1 < l4 + l4_len {
        sum += u16::from_be_bytes([out[i], out[i + 1]]) as u32;
        i += 2;
    }
    if (l4_len & 1) == 1 {
        sum += (out[l4 + l4_len - 1] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    (sum as u16) == 0xffff
}

const OUT_L4: usize = ETH_LEN + IPV6_LEN;

#[test]
fn nat64_ingress_tcp_expands_to_ipv6() {
    let node = node();
    let nat_port = expected_nat_port(IPPROTO_TCP);
    let inner = inner_reply(IPPROTO_TCP, nat_port);
    let l4_len = inner.len() - 20; // 20 (TCP hdr) + 4 payload
    let frame = ingress_frame(&inner);

    let out = node.uplink_nat64_ingress(&frame, TAP_IFINDEX, GUEST_MAC, GUEST_IP6, &rev_ct(SPORT));
    assert_eq!(
        out.action,
        Action::Redirect(TAP_IFINDEX),
        "TCP NAT64 reply delivered to the guest tap"
    );
    // Net +20 bytes (post-decap inner 34 -> inner 54: IPv4(20) header expands to IPv6(40)):
    // [InnerEth(14)][InnerIPv4(20)][L4] -> [Eth(14)][IPv6(40)][L4].
    assert_eq!(
        out.pkt.len(),
        frame.len() + 20,
        "NAT64 ingress is net +20 bytes (v4->v6 header expansion)"
    );
    assert_ingress_ipv6(&out.pkt, IPPROTO_TCP, l4_len);
    // TCP src port unchanged (= server DPORT); dst port restored to the guest sport by ct_apply.
    assert_eq!(be16(&out.pkt, OUT_L4), DPORT, "TCP src port = server port");
    assert_eq!(
        be16(&out.pkt, OUT_L4 + 2),
        SPORT,
        "TCP dst port restored to guest sport"
    );
    assert!(
        v6_l4_checksum_valid(
            &out.pkt,
            &nat64_src(),
            &GUEST_IP6,
            IPPROTO_TCP,
            OUT_L4,
            l4_len
        ),
        "translated TCP checksum valid over the IPv6 pseudo-header"
    );
}

#[test]
fn nat64_ingress_udp_expands_to_ipv6() {
    let node = node();
    let nat_port = expected_nat_port(IPPROTO_UDP);
    let inner = inner_reply(IPPROTO_UDP, nat_port);
    let l4_len = inner.len() - 20; // 8 (UDP hdr) + 4 payload
    let frame = ingress_frame(&inner);

    let out = node.uplink_nat64_ingress(&frame, TAP_IFINDEX, GUEST_MAC, GUEST_IP6, &rev_ct(SPORT));
    assert_eq!(out.action, Action::Redirect(TAP_IFINDEX));
    assert_eq!(out.pkt.len(), frame.len() + 20);
    assert_ingress_ipv6(&out.pkt, IPPROTO_UDP, l4_len);
    assert_eq!(be16(&out.pkt, OUT_L4), DPORT, "UDP src port = server port");
    assert_eq!(
        be16(&out.pkt, OUT_L4 + 2),
        SPORT,
        "UDP dst port restored to guest sport"
    );
    assert_ne!(
        be16(&out.pkt, OUT_L4 + 6),
        0,
        "UDP checksum non-zero after v4→v6 translation"
    );
    assert!(
        v6_l4_checksum_valid(
            &out.pkt,
            &nat64_src(),
            &GUEST_IP6,
            IPPROTO_UDP,
            OUT_L4,
            l4_len
        ),
        "translated UDP checksum valid over the IPv6 pseudo-header"
    );
}

#[test]
fn nat64_ingress_icmpv4_reply_becomes_icmpv6() {
    let node = node();
    // ICMP echo reply: id == nat_port (server echoes the SNAT'd id), seq == 1, 4-byte payload.
    let icmp_id_nat = 0xB0C0u16; // the SNAT'd id the server echoed (any value; restored to SPORT)
    let mut inner = Vec::new();
    // Inner IPv4 header via etherparse (echo reply, type 0), then strip the Ethernet.
    let builder = PacketBuilder::ethernet2([0; 6], [0; 6]).ipv4(EXT_V4, NAT_IP, 63);
    builder
        .icmpv4_echo_reply(icmp_id_nat, 1)
        .write(&mut inner, &[0xde, 0xad, 0xbe, 0xef])
        .unwrap();
    let inner = inner[ETH_LEN..].to_vec();
    let l4_len = inner.len() - 20; // 8 (echo hdr) + 4 payload
    let frame = ingress_frame(&inner);

    // Reverse CT for ICMP restores the guest's original id (SPORT) via ct_apply's ICMP id rewrite.
    let out = node.uplink_nat64_ingress(&frame, TAP_IFINDEX, GUEST_MAC, GUEST_IP6, &rev_ct(SPORT));
    assert_eq!(out.action, Action::Redirect(TAP_IFINDEX));
    assert_eq!(out.pkt.len(), frame.len() + 20);
    assert_ingress_ipv6(&out.pkt, IPPROTO_ICMPV6, l4_len);
    // ICMPv4 echo reply (type 0) → ICMPv6 echo reply (type 129), code 0.
    assert_eq!(out.pkt[OUT_L4], 129, "ICMPv6 echo-reply type");
    assert_eq!(out.pkt[OUT_L4 + 1], 0, "ICMPv6 code 0");
    // id restored to the guest's original id (SPORT); seq unchanged.
    assert_eq!(
        be16(&out.pkt, OUT_L4 + 4),
        SPORT,
        "ICMPv6 id = restored guest id"
    );
    assert_eq!(be16(&out.pkt, OUT_L4 + 6), 1, "ICMPv6 seq unchanged");
    // The ICMPv6 checksum is over the IPv6 pseudo-header + the 8-byte echo header (no payload sum in
    // the eBPF helper — it computes over the 8-byte window). Fold pseudo + the 8-byte header to 0.
    let mut sum: u32 = 0;
    for chunk in nat64_src().chunks(2).chain(GUEST_IP6.chunks(2)) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += 8u32; // upper-layer length used by the helper
    sum += IPPROTO_ICMPV6 as u32;
    let mut i = OUT_L4;
    while i + 1 < OUT_L4 + 8 {
        sum += u16::from_be_bytes([out.pkt[i], out.pkt[i + 1]]) as u32;
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    assert_eq!(
        sum as u16, 0xffff,
        "ICMPv6 echo-header checksum valid over pseudo-header"
    );
}

/// Unified dispatch: a NAT64 return driven through the SHARED `SimNode::uplink_rx` entry (the same
/// `flowplane_core::datapath::process_uplink_rx` the native SimNode runs, mirroring the eBPF
/// `try_uplink_rx` base-vs-NAT-return dispatch) whose reverse conntrack entry carries `CT_F_NAT64 |
/// CT_REWRITE_DST` must be v4→v6-EXPANDED via `process_uplink_nat64_ingress`, NOT delivered as a
/// bare truncated IPv4 packet via the plain base path.
///
/// This protects the dispatch-gap fix: `process_uplink_rx` previously restricted its NAT-return
/// branch to `CT_F_NAT64 == 0`, so NAT64 reverse entries fell through to `process_uplink` and the
/// reply was mis-delivered as a raw IPv4 frame instead of being expanded back to the guest's IPv6.
/// Two proofs it took the NAT64 path: (1) `Action::Redirect(tap)`; (2) the delivered frame is IPv6
/// (ethertype 0x86DD, IPv6 dst == the guest's overlay IPv6 plumbed via `UplinkIn.guest_ipv6`) — the
/// base path would leave it IPv4.
#[test]
fn uplink_rx_dispatches_nat64_return_to_v6_expansion() {
    let mut node = node();
    // Register NAT_IP so the peer-independent reverse-CT demux keys (vni,0,NAT_IP,0,nat_port).
    node.maps.nat_ips.insert((VNI, NAT_IP));
    let nat_port = expected_nat_port(IPPROTO_TCP);
    // Seed the reverse CT_F_NAT64 entry the egress allocator would have stored.
    node.maps.conntrack.insert(
        CtKey {
            vni: VNI,
            src_ip: [0; 4],
            dst_ip: NAT_IP,
            src_port: 0,
            dst_port: nat_port,
            proto: IPPROTO_TCP,
            _pad: [0; 3],
        },
        rev_ct(SPORT),
    );
    // INTERFACES entry for the guest's RESTORED overlay IPv4 (mechanism #2: the delivery target is
    // resolved from the reverse CT entry's `xlate_ip` via `resolve_uplink_target(vni, xlate_ip)` →
    // `INTERFACES[(vni, xlate_ip)]` — the SAME local-delivery entry `program_interface` would have
    // written for this guest).
    node.maps.add_iface(
        VNI,
        GUEST_IP,
        flowplane_common::IfaceValue {
            tap_ifindex: TAP_IFINDEX,
            is_local: 1,
            underlay_ipv6: [0; 16],
            guest_mac: GUEST_MAC,
            peer_capable: 0,
            _pad: [0; 1],
        },
    );

    // PORT_META[TAP_IFINDEX].guest_ipv6 is how `process_uplink_rx`'s CT_F_NAT64 branch sources the
    // guest's overlay IPv6 AFTER resolving the delivery tap (mechanism #2) — see
    // `flowplane_core::datapath::process_uplink_rx`'s doc comment on the fixed guest_ipv6 gap.
    node.maps.port_meta.insert(
        TAP_IFINDEX,
        PortMeta {
            guest_ipv6: GUEST_IP6,
            ..Default::default()
        },
    );

    let inner = inner_reply(IPPROTO_TCP, nat_port);
    let l4_len = inner.len() - 20;
    let frame = ingress_frame(&inner);

    // Drive the UNIFIED dispatch (NOT SimNode::uplink_nat64_ingress directly).
    let out = node.uplink_rx(&frame, VNI, &local());

    assert_eq!(
        out.action,
        Action::Redirect(TAP_IFINDEX),
        "unified uplink_rx must v4→v6-expand the CT_F_NAT64 return and deliver it to the guest tap \
         (regression: dispatched to process_uplink → raw truncated IPv4)"
    );
    // Net +20 bytes: the NAT64 v4→v6 expansion (post-decap inner 34 -> inner 54 headers).
    assert_eq!(
        out.pkt.len(),
        frame.len() + 20,
        "NAT64 ingress is net +20 bytes (proves the v6-expansion path, not plain delivery)"
    );
    // The delivered frame is IPv6 with dst = the guest's overlay IPv6 — NOT a bare IPv4 packet.
    assert_eq!(
        &out.pkt[12..14],
        &0x86DDu16.to_be_bytes(),
        "delivered frame is IPv6 (dispatched to the NAT64 v6-expansion path)"
    );
    assert_ingress_ipv6(&out.pkt, IPPROTO_TCP, l4_len);
    assert_eq!(
        &out.pkt[ETH_LEN + 24..ETH_LEN + 40],
        &GUEST_IP6,
        "IPv6 dst reconstructed to the guest's overlay IPv6 from PORT_META[tap_ifindex].guest_ipv6"
    );
}

/// A reply whose guest port has no NAT64 IPv6 (guest is IPv4-only → PORT_META `guest_ipv6` all-zero)
/// falls through with `Pass` — the parse rejects the all-zero guest IPv6.
#[test]
fn nat64_ingress_ipv4_only_guest_passes() {
    let node = node();
    let nat_port = expected_nat_port(IPPROTO_TCP);
    let frame = ingress_frame(&inner_reply(IPPROTO_TCP, nat_port));
    let out = node.uplink_nat64_ingress(&frame, TAP_IFINDEX, GUEST_MAC, [0u8; 16], &rev_ct(SPORT));
    assert_eq!(
        out.action,
        Action::Pass,
        "IPv4-only guest (no v6) falls through"
    );
}
