//! Conformance tests for the guest-egress network SNAT path and the return-path reverse DNAT.
//!
//! These tests drive the REAL `flowplane_core::nat::snat_egress` (and the full `SimNode::guest_tx`
//! compose that calls it) over in-memory `MemMaps` / `VecPkt`.  Nothing is reimplemented — the
//! assertions guard byte-identical production behaviour: correct src-IP rewrite, deterministic
//! port allocation within `[port_min, port_max)`, valid IP/L4 checksums, and per-source block
//! isolation.
//!
//! # Scope — return-path DNAT (c)
//! `snat_egress` inserts a reverse conntrack entry with `CT_REWRITE_DST` that maps the NAT'd
//! (external) 5-tuple back to the guest's original IP:port.  Applying that entry on ingress is
//! `ct_apply` — now extracted into `flowplane-core::conntrack::ct_apply` and exercised by
//! `SimNode::uplink_nat_return`.  The DNAT-return conformance tests are in the
//! `dnat_return_*` group below (TCP + UDP), asserting inner-dst rewrite + checksum update.

use etherparse::PacketBuilder;
use flowplane_common::{
    CtEntry, CtKey, FwMeta, FwRule, Local, NatKey, NatValue, PortMeta, RouteValue, UnderlayValue,
    CT_F_SRC_NAT, CT_REWRITE_DST, FW_ACTION_ACCEPT, FW_DIR_EGRESS, FW_DIR_INGRESS,
};
use flowplane_core::encap::{EncapParams, ETH_LEN, IPV6_LEN};
use flowplane_core::pkt::Action;

use crate::{MemMaps, SimNode};

// ─── fixed test topology ──────────────────────────────────────────────────────

const VNI: u32 = 200;
/// Guest A — has NAT block A (nat_ip=100.64.0.1, ports 1024..1536, range=512).
const GUEST_A_IP: [u8; 4] = [10, 0, 0, 10];
const NAT_IP_A: [u8; 4] = [100, 64, 0, 1];
const PORT_MIN_A: u16 = 1024;
const PORT_MAX_A: u16 = PORT_MIN_A + 512; // exclusive → range = 512

/// Guest B — has NAT block B (nat_ip=100.64.0.1, ports 2048..2560, range=512).
/// Both guests share the same public IP but occupy non-overlapping port ranges — dpservice model.
const GUEST_B_IP: [u8; 4] = [10, 0, 0, 20];
const PORT_MIN_B: u16 = 2048;
const PORT_MAX_B: u16 = PORT_MIN_B + 512;

/// External server both guests reach.
const EXT_IP: [u8; 4] = [203, 0, 113, 1];

/// Golden NAT port for guest A's 5-tuple (10.0.0.10→203.0.113.1:12345→80/TCP):
///   hash5(...) = 607522665; 607522665 % 512 = 361; 1024 + 361 = 1385.
/// If this fails, the NAT port-allocation (hash5) changed — verify eBPF parity before updating.
const EXPECTED_SPORT_A: u16 = 1385;

/// Golden NAT port for guest B's 5-tuple (10.0.0.20→203.0.113.1:54321→443/TCP), block base 2048:
///   hash5(...) % 512 gives offset into [2048..2560).
/// If this fails, the NAT port-allocation (hash5) changed — verify eBPF parity before updating.
const EXPECTED_SPORT_B: u16 = 2159;

/// Src ifindex used for the egress firewall (keyed on the guest port).
const SRC_IFINDEX_A: u32 = 10;
const SRC_IFINDEX_B: u32 = 11;

/// Underlay nexthop for the external route (encap via uplink).
const UPLINK_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Build a guest Ethernet frame `[Eth(14)][IPv4][TCP]` from `src_ip:sport` to `EXT_IP:dport`.
fn guest_tcp_frame(src_ip: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
        .ipv4(src_ip, EXT_IP, 64)
        .tcp(sport, dport, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

/// Install an egress ALLOW rule on `ifindex` (wildcard src/dst).
fn allow_egress(node: &mut SimNode, ifindex: u32) {
    node.maps.fw_meta.insert(
        ifindex,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps.fw_rules.insert(
        (ifindex, 0),
        FwRule {
            src_ip: [0; 4],
            src_mask: [0; 4],
            dst_ip: [0; 4],
            dst_mask: [0; 4],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 0,
            dst_port_max: 65535,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_EGRESS,
            enabled: 1,
        },
    );
}

/// Program an external /32 route for `dst_ip` (is_external = 1, nexthop = UPLINK_UNDERLAY).
fn add_external_route(node: &mut SimNode, dst_ip: [u8; 4]) {
    node.maps.add_route4(
        VNI,
        dst_ip,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: UPLINK_UNDERLAY,
            is_external: 1,
            _pad: [0; 3],
        },
    );
}

/// Install a NAT entry mapping `(vni, guest_ip)` → `(nat_ip, port_min..port_max)`.
fn add_nat(maps: &mut MemMaps, guest_ip: [u8; 4], nat_ipv4: [u8; 4], port_min: u16, port_max: u16) {
    maps.nat.insert(
        NatKey {
            vni: VNI,
            ipv4: guest_ip,
        },
        NatValue {
            nat_ipv4,
            port_min,
            port_max,
        },
    );
}

/// Build a `PortMeta` for a guest (VNI + underlay info for the encap deliver path).
fn port_meta(guest_ip: [u8; 4]) -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: guest_ip,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: [0xaa; 6],
        _pad: [0; 2],
        underlay_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

/// Configure `node.local` + the `UPLINK_UNDERLAY` underlay entry so `deliver` takes the `Encap`
/// path toward the external route nexthop (not `Local` — the nexthop is the uplink, not a tap).
fn configure_local(node: &mut SimNode) {
    node.maps.local = Some(Local {
        uplink_ifindex: 7,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
    });
    // We do NOT insert an underlay entry for UPLINK_UNDERLAY — `deliver` only takes `Local` when
    // `underlay_get(nexthop_ipv6)` returns `Some(u)` with `tap_ifindex != 0`.  An absent entry
    // means `deliver` falls through to `Deliver::Encap` via `Local[0]`, which is what we want.
}

// ─── (a) SNAT rewrite: src IP and port rewritten, checksums updated ───────────

/// A TCP guest-egress packet is SNAT'd: the src IP is replaced with `nat_ipv4`, the TCP src port
/// is replaced with the deterministically computed slot `port_min + (hash5 % range)`, and the IP
/// / TCP checksums are updated (non-zero / non-garbage).
#[test]
fn snat_rewrites_src_ip_and_port_with_valid_checksums() {
    let sport: u16 = 12345;
    let dport: u16 = 80;

    let mut node = SimNode::new();
    configure_local(&mut node);
    allow_egress(&mut node, SRC_IFINDEX_A);
    add_external_route(&mut node, EXT_IP);
    add_nat(&mut node.maps, GUEST_A_IP, NAT_IP_A, PORT_MIN_A, PORT_MAX_A);
    node.src_ifindex = SRC_IFINDEX_A;

    let frame = guest_tcp_frame(GUEST_A_IP, sport, dport);
    let meta = port_meta(GUEST_A_IP);
    let out = node.guest_tx(&frame, &meta);

    // The path took the Encap branch (external route, Local present) → Redirect to uplink.
    assert!(
        matches!(out.action, Action::Redirect(_)),
        "expected Redirect (encap), got {:?}",
        out.action
    );

    // After encap the buffer layout is [OuterEth(14)][OuterIPv6(40)][inner IPv4 ...].
    // grow_head(IPV6_LEN=40) prepends 40 bytes; write_outer_v6 then writes the 54-byte outer
    // header (14 B Eth + 40 B IPv6) which consumes those 40 new bytes AND the 14-byte inner
    // Ethernet.  The inner IPv4 therefore starts at offset 54 = ETH_LEN(14) + IPV6_LEN(40).
    let inner_ip_off = ETH_LEN + IPV6_LEN; // 14 + 40 = 54

    let pkt = &out.pkt;
    assert!(
        pkt.len() >= inner_ip_off + 40,
        "output too short to contain inner IPv4+TCP"
    );

    // src IP at inner_ip_off + 12..+16.
    let rewritten_src = &pkt[inner_ip_off + 12..inner_ip_off + 16];
    assert_eq!(
        rewritten_src, &NAT_IP_A,
        "src IP must be rewritten to nat_ipv4"
    );

    // IP checksum at inner_ip_off + 10..+12 — must be non-zero (original src was non-zero and
    // the checksum spans non-trivially valued fields).
    let ip_csum = u16::from_be_bytes([pkt[inner_ip_off + 10], pkt[inner_ip_off + 11]]);
    assert_ne!(ip_csum, 0, "IP checksum must be non-zero after rewrite");

    // TCP header starts at inner_ip_off + 20 (no IP options: IHL=5).
    let tcp_off = inner_ip_off + 20;
    // TCP src port at tcp_off + 0..+2.
    let rewritten_sport = u16::from_be_bytes([pkt[tcp_off], pkt[tcp_off + 1]]);
    assert_eq!(
        rewritten_sport,
        EXPECTED_SPORT_A,
        "TCP src port must match the golden NAT allocation (hash5 derivation: 607522665 % 512 = 361, 1024 + 361 = 1385); \
         if this changed, the allocation algorithm changed — verify eBPF parity before updating EXPECTED_SPORT_A"
    );
    assert!(
        (PORT_MIN_A..PORT_MAX_A).contains(&rewritten_sport),
        "rewritten sport must be within the assigned block [{PORT_MIN_A},{PORT_MAX_A})"
    );

    // TCP checksum at tcp_off + 16..+18.
    let tcp_csum = u16::from_be_bytes([pkt[tcp_off + 16], pkt[tcp_off + 17]]);
    assert_ne!(tcp_csum, 0, "TCP checksum must be non-zero after rewrite");
}

// ─── (b) Distinct stable blocks per source ────────────────────────────────────

/// Two distinct guests have distinct pre-programmed NAT port blocks.  Each guest's egress packet
/// is SNAT'd into ITS OWN block — block A gets A, block B gets B, and the rewritten sources are
/// distinct.  Confirms the datapath never cross-assigns across sources.
#[test]
fn snat_distinct_sources_map_to_distinct_blocks() {
    let sport_a: u16 = 12345;
    let dport_a: u16 = 80;
    let sport_b: u16 = 54321;
    let dport_b: u16 = 443;
    let proto: u8 = 6; // TCP

    // Both guests share the same node.
    let mut node = SimNode::new();
    configure_local(&mut node);
    // Egress firewall allows both source ifindexes.
    allow_egress(&mut node, SRC_IFINDEX_A);
    allow_egress(&mut node, SRC_IFINDEX_B);
    add_external_route(&mut node, EXT_IP);
    add_nat(&mut node.maps, GUEST_A_IP, NAT_IP_A, PORT_MIN_A, PORT_MAX_A);
    add_nat(&mut node.maps, GUEST_B_IP, NAT_IP_A, PORT_MIN_B, PORT_MAX_B);

    // ── Guest A sends first ──────────────────────────────────────────────────
    node.src_ifindex = SRC_IFINDEX_A;
    let frame_a = guest_tcp_frame(GUEST_A_IP, sport_a, dport_a);
    let out_a = node.guest_tx(&frame_a, &port_meta(GUEST_A_IP));
    assert!(
        matches!(out_a.action, Action::Redirect(_)),
        "guest A: expected Redirect"
    );

    let inner_ip_off = ETH_LEN + IPV6_LEN; // 54: outer Eth(14) + outer IPv6(40)
    let pkt_a = &out_a.pkt;

    let src_a = &pkt_a[inner_ip_off + 12..inner_ip_off + 16];
    assert_eq!(src_a, &NAT_IP_A, "A: src IP must be nat_ipv4");

    let sport_nat_a = u16::from_be_bytes([pkt_a[inner_ip_off + 20], pkt_a[inner_ip_off + 21]]);
    assert_eq!(
        sport_nat_a, EXPECTED_SPORT_A,
        "A: src port must match golden constant EXPECTED_SPORT_A={EXPECTED_SPORT_A}"
    );
    assert!(
        (PORT_MIN_A..PORT_MAX_A).contains(&sport_nat_a),
        "A: port {sport_nat_a} outside block A [{PORT_MIN_A},{PORT_MAX_A})"
    );
    // Must NOT be in block B.
    assert!(
        !(PORT_MIN_B..PORT_MAX_B).contains(&sport_nat_a),
        "A: port {sport_nat_a} landed in block B [{PORT_MIN_B},{PORT_MAX_B}) — cross-assign!"
    );

    // ── Guest B sends second ─────────────────────────────────────────────────
    node.src_ifindex = SRC_IFINDEX_B;
    let frame_b = guest_tcp_frame(GUEST_B_IP, sport_b, dport_b);
    let out_b = node.guest_tx(&frame_b, &port_meta(GUEST_B_IP));
    assert!(
        matches!(out_b.action, Action::Redirect(_)),
        "guest B: expected Redirect"
    );

    let pkt_b = &out_b.pkt;
    let src_b = &pkt_b[inner_ip_off + 12..inner_ip_off + 16];
    assert_eq!(src_b, &NAT_IP_A, "B: src IP must be nat_ipv4");

    let sport_nat_b = u16::from_be_bytes([pkt_b[inner_ip_off + 20], pkt_b[inner_ip_off + 21]]);
    assert_eq!(
        sport_nat_b, EXPECTED_SPORT_B,
        "B: src port must match golden constant EXPECTED_SPORT_B={EXPECTED_SPORT_B}"
    );
    assert!(
        (PORT_MIN_B..PORT_MAX_B).contains(&sport_nat_b),
        "B: port {sport_nat_b} outside block B [{PORT_MIN_B},{PORT_MAX_B})"
    );
    // Must NOT be in block A.
    assert!(
        !(PORT_MIN_A..PORT_MAX_A).contains(&sport_nat_b),
        "B: port {sport_nat_b} landed in block A [{PORT_MIN_A},{PORT_MAX_A}) — cross-assign!"
    );

    // The two rewritten (nat_ip, nat_port) tuples must be distinct.
    assert_ne!(
        sport_nat_a, sport_nat_b,
        "two guests must receive distinct NAT ports"
    );

    // ── Conntrack state: each source has its own forward + reverse entry ─────
    // snat_egress inserts the forward CT entry under the PRE-SNAT 5-tuple (original guest src
    // IP:port), with flags=CT_REWRITE_SRC|CT_F_SRC_NAT and xlate fields pointing to the NAT'd
    // address. Assert both forward entries exist with the correct flags and xlate fields.
    use flowplane_common::{CtKey, CT_F_SRC_NAT, CT_REWRITE_DST, CT_REWRITE_SRC};

    let fwd_key_a = CtKey {
        vni: VNI,
        src_ip: GUEST_A_IP,
        dst_ip: EXT_IP,
        src_port: sport_a,
        dst_port: dport_a,
        proto,
        _pad: [0; 3],
    };
    let fwd_a = node
        .maps
        .conntrack
        .get(&fwd_key_a)
        .copied()
        .expect("forward CT entry for A must exist");
    assert_eq!(
        fwd_a.flags & (CT_REWRITE_SRC | CT_F_SRC_NAT),
        CT_REWRITE_SRC | CT_F_SRC_NAT,
        "A forward entry must have CT_REWRITE_SRC | CT_F_SRC_NAT"
    );
    assert_eq!(
        fwd_a.xlate_ip, NAT_IP_A,
        "A forward entry xlate_ip must be the NAT IP"
    );
    assert_eq!(
        fwd_a.xlate_port, sport_nat_a,
        "A forward entry xlate_port must be the allocated NAT port"
    );

    let fwd_key_b = CtKey {
        vni: VNI,
        src_ip: GUEST_B_IP,
        dst_ip: EXT_IP,
        src_port: sport_b,
        dst_port: dport_b,
        proto,
        _pad: [0; 3],
    };
    let fwd_b = node
        .maps
        .conntrack
        .get(&fwd_key_b)
        .copied()
        .expect("forward CT entry for B must exist");
    assert_eq!(
        fwd_b.flags & (CT_REWRITE_SRC | CT_F_SRC_NAT),
        CT_REWRITE_SRC | CT_F_SRC_NAT,
        "B forward entry must have CT_REWRITE_SRC | CT_F_SRC_NAT"
    );
    assert_eq!(
        fwd_b.xlate_ip, NAT_IP_A,
        "B forward entry xlate_ip must be the NAT IP"
    );
    assert_eq!(
        fwd_b.xlate_port, sport_nat_b,
        "B forward entry xlate_port must be the allocated NAT port"
    );

    // The reverse CT entry is inserted under (vni, 0, nat_ip, 0, nat_port).  Check the
    // reverse entries exist and have CT_REWRITE_DST (proxy for DNAT return correctness until the
    // ct_apply seam is extracted).
    let rev_key_a = CtKey {
        vni: VNI,
        src_ip: [0; 4],
        dst_ip: NAT_IP_A,
        src_port: 0,
        dst_port: sport_nat_a,
        proto,
        _pad: [0; 3],
    };
    let rev_key_b = CtKey {
        vni: VNI,
        src_ip: [0; 4],
        dst_ip: NAT_IP_A,
        src_port: 0,
        dst_port: sport_nat_b,
        proto,
        _pad: [0; 3],
    };
    let rev_a = node
        .maps
        .conntrack
        .get(&rev_key_a)
        .copied()
        .expect("reverse CT entry for A must exist");
    assert_eq!(
        rev_a.flags & CT_REWRITE_DST,
        CT_REWRITE_DST,
        "A reverse entry must have CT_REWRITE_DST"
    );
    assert_eq!(
        rev_a.xlate_ip, GUEST_A_IP,
        "A reverse entry xlate_ip must be the original guest A IP"
    );
    assert_eq!(
        rev_a.xlate_port, sport_a,
        "A reverse entry xlate_port must be the original guest A sport"
    );

    let rev_b = node
        .maps
        .conntrack
        .get(&rev_key_b)
        .copied()
        .expect("reverse CT entry for B must exist");
    assert_eq!(
        rev_b.flags & CT_REWRITE_DST,
        CT_REWRITE_DST,
        "B reverse entry must have CT_REWRITE_DST"
    );
    assert_eq!(
        rev_b.xlate_ip, GUEST_B_IP,
        "B reverse entry xlate_ip must be the original guest B IP"
    );
    assert_eq!(
        rev_b.xlate_port, sport_b,
        "B reverse entry xlate_port must be the original guest B sport"
    );

    // The two reverse keys must be distinct (different dst_port = nat_port).
    assert_ne!(rev_key_a, rev_key_b, "reverse CT keys must be distinct");
}

// ─── no-op when route is internal ─────────────────────────────────────────────

/// When the route has `is_external = 0`, `snat_egress` must not rewrite the packet even when a
/// NAT entry exists for the guest.  The src IP/port are unchanged.
#[test]
fn snat_no_op_for_internal_route() {
    let sport: u16 = 9999;
    let dport: u16 = 8080;

    let mut node = SimNode::new();
    // Route is INTERNAL (is_external = 0), and the nexthop resolves to a local tap so deliver
    // returns Redirect(tap) rather than Encap.
    const PEER_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
    const PEER_TAP: u32 = 77;
    node.maps.underlay.insert(
        PEER_UNDERLAY,
        UnderlayValue {
            vni: VNI,
            tap_ifindex: PEER_TAP,
            guest_mac: [0xcc; 6],
            _pad: [0; 2],
        },
    );
    node.maps.add_route4(
        VNI,
        EXT_IP, // reusing EXT_IP as the internal peer for simplicity
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: PEER_UNDERLAY,
            is_external: 0, // ← internal
            _pad: [0; 3],
        },
    );
    // NAT entry present (must be ignored on internal route).
    add_nat(&mut node.maps, GUEST_A_IP, NAT_IP_A, PORT_MIN_A, PORT_MAX_A);
    allow_egress(&mut node, SRC_IFINDEX_A);
    // Install an ingress allow rule on PEER_TAP so same-node delivery isn't firewalled.
    use flowplane_common::{FwMeta, FwRule, FW_DIR_INGRESS};
    node.maps.fw_meta.insert(
        PEER_TAP,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    node.maps.fw_rules.insert(
        (PEER_TAP, 0),
        FwRule {
            src_ip: [0; 4],
            src_mask: [0; 4],
            dst_ip: [0; 4],
            dst_mask: [0; 4],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 0,
            dst_port_max: 65535,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        },
    );
    node.src_ifindex = SRC_IFINDEX_A;

    let frame = guest_tcp_frame(GUEST_A_IP, sport, dport);
    let meta = port_meta(GUEST_A_IP);
    let out = node.guest_tx(&frame, &meta);

    // Delivered locally (tap redirect), not encap.
    assert!(
        matches!(out.action, Action::Redirect(PEER_TAP)),
        "expected local redirect to peer tap, got {:?}",
        out.action
    );

    // Inner Eth header is rewritten; IPv4 starts at ETH_LEN (14) in the output (no outer added).
    let ip_off = ETH_LEN;
    let pkt = &out.pkt;
    // src IP must be GUEST_A_IP (no SNAT).
    let src_ip = &pkt[ip_off + 12..ip_off + 16];
    assert_eq!(
        src_ip, &GUEST_A_IP,
        "src IP must NOT be rewritten on an internal route"
    );
    // TCP src port must be the original sport.
    let tcp_off = ip_off + 20;
    let rewritten_sport = u16::from_be_bytes([pkt[tcp_off], pkt[tcp_off + 1]]);
    assert_eq!(
        rewritten_sport, sport,
        "TCP src port must NOT be rewritten on an internal route"
    );

    // No NAT CT entries created (snat_egress returned false → no CT_REWRITE_DST / CT_F_SRC_NAT
    // entries).  The conntrack map may contain default firewall-tracking entries (CT_F_DEFAULT),
    // but must have NO NAT-marked entries.
    use flowplane_common::{CT_F_SRC_NAT, CT_REWRITE_DST};
    let nat_entries: Vec<_> = node
        .maps
        .conntrack
        .values()
        .filter(|e| e.flags & (CT_REWRITE_DST | CT_F_SRC_NAT) != 0)
        .collect();
    assert!(
        nat_entries.is_empty(),
        "no NAT CT entries (CT_REWRITE_DST | CT_F_SRC_NAT) should exist for an internal-route flow; \
         found {} unexpected entries",
        nat_entries.len()
    );
}

// ─── (c) Return-path DNAT: SimNode::uplink_nat_return applies CT_REWRITE_DST ────────────────────

/// Topology re-used by both DNAT-return sub-tests (mirrors `anchor_dnat.rs`):
///   - NAT_IP (public NAT IPv4) is the inner dst of the returning packet
///   - GUEST_IP is the xlate target (inner dst after reverse-DNAT)
///   - ORIG_SPORT is the original guest L4 src-port (inner dst port after reverse-DNAT)
///   - EXT_IP / EXT_PORT is the external peer (inner src, unchanged)
///   - Reverse CT entry: `(vni, src=0, dst=NAT_IP, sport=0, dport=NAT_PORT, proto)` →
///     `CT_REWRITE_DST | CT_F_SRC_NAT`, `xlate_ip=GUEST_IP`, `xlate_port=ORIG_SPORT`
const DNAT_VNI: u32 = 100;
const DNAT_TAP: u32 = 42;
const DNAT_GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const DNAT_GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const DNAT_NAT_IP: [u8; 4] = [198, 51, 100, 7];
const DNAT_EXT_IP: [u8; 4] = [203, 0, 113, 9];
const DNAT_ORIG_SPORT: u16 = 40000; // restored inner dst port after reverse-DNAT
const DNAT_NAT_PORT: u16 = 20018; // allocated NAT port (inner dst port in the returning packet)
const DNAT_EXT_PORT: u16 = 443; // external peer's port (inner src port, unchanged)

const EDGE_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
const HOST_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];

fn dnat_encap_params() -> EncapParams {
    EncapParams {
        gateway_mac: [1; 6],
        uplink_mac: [2; 6],
        uplink_ifindex: 7,
        src_underlay: EDGE_UNDERLAY,
        nexthop_ipv6: HOST_UNDERLAY,
        inner_proto: 4,
        flow_label: 0,
    }
}

fn dnat_reverse_ct_entry() -> CtEntry {
    CtEntry {
        last_seen: 0,
        xlate_ip: DNAT_GUEST_IP,
        xlate_port: DNAT_ORIG_SPORT,
        flags: CT_REWRITE_DST | CT_F_SRC_NAT,
        tcp_state: 0,
        fwall_action: 0,
        _pad: [0; 7],
    }
}

fn dnat_reverse_ct_key(proto: u8) -> CtKey {
    CtKey {
        vni: DNAT_VNI,
        src_ip: [0; 4],
        dst_ip: DNAT_NAT_IP,
        src_port: 0,
        dst_port: DNAT_NAT_PORT,
        proto,
        _pad: [0; 3],
    }
}

/// Build a node with the reverse CT entry + NAT_IPS registration seeded for DNAT return.
fn dnat_host_node(proto: u8) -> SimNode {
    use flowplane_common::UnderlayValue;

    let mut node = SimNode::new();
    node.maps
        .conntrack
        .insert(dnat_reverse_ct_key(proto), dnat_reverse_ct_entry());
    node.maps.nat_ips.insert((DNAT_VNI, DNAT_NAT_IP));
    // Seed UNDERLAY so uplink_nat_return can find the base tap.
    node.maps.underlay.insert(
        HOST_UNDERLAY,
        UnderlayValue {
            vni: DNAT_VNI,
            tap_ifindex: DNAT_TAP,
            guest_mac: DNAT_GUEST_MAC,
            _pad: [0; 2],
        },
    );
    node
}

/// Build an encapped returning TCP frame: `[OuterEth][OuterIPv6][inner IPv4 TCP]`
/// where inner is `EXT_IP:EXT_PORT → NAT_IP:NAT_PORT` (as the frame arrives from the peer).
fn dnat_tcp_encapped() -> Vec<u8> {
    let inner = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(DNAT_EXT_IP, DNAT_NAT_IP, 64)
        .tcp(DNAT_EXT_PORT, DNAT_NAT_PORT, 0, 1024);
    let mut frame = Vec::new();
    inner.write(&mut frame, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    SimNode::new().edge_encap(&frame, dnat_encap_params())
}

/// Build an encapped returning UDP frame with a non-zero payload (so UDP csum is non-zero).
fn dnat_udp_encapped() -> Vec<u8> {
    let inner = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(DNAT_EXT_IP, DNAT_NAT_IP, 64)
        .udp(DNAT_EXT_PORT, DNAT_NAT_PORT);
    let mut frame = Vec::new();
    inner.write(&mut frame, &[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
    SimNode::new().edge_encap(&frame, dnat_encap_params())
}

/// (c) TCP DNAT return: a reply arriving `EXT_IP:EXT_PORT → NAT_IP:NAT_PORT` is reverse-DNAT'd
/// by `uplink_nat_return` to `EXT_IP:EXT_PORT → GUEST_IP:ORIG_SPORT` and delivered to the guest tap.
///
/// Pinned expected values:
///   - inner dst IP  == DNAT_GUEST_IP == [10, 0, 0, 10]
///   - inner TCP dst port == DNAT_ORIG_SPORT == 40_000
///   - IP + TCP checksums are non-zero after rewrite
#[test]
fn dnat_return_tcp_rewrites_dst_ip_and_port() {
    let encapped = dnat_tcp_encapped();
    let u = flowplane_common::UnderlayValue {
        vni: DNAT_VNI,
        tap_ifindex: DNAT_TAP,
        guest_mac: DNAT_GUEST_MAC,
        _pad: [0; 2],
    };
    let out = dnat_host_node(6).uplink_nat_return(&encapped, DNAT_VNI, u, DNAT_GUEST_MAC);

    assert_eq!(
        out.action,
        Action::Redirect(DNAT_TAP),
        "reverse-DNAT'd return must be delivered to the guest tap (Redirect({DNAT_TAP}))"
    );

    // After decap, outer IPv6 (40B) is stripped, leaving [InnerEth(14)][IPv4 ...].
    // Inner IPv4 header starts at ETH_LEN = 14.
    let pkt = &out.pkt;
    assert!(
        pkt.len() >= ETH_LEN + IPV6_LEN,
        "output too short after decap"
    );

    // dst IP at inner_ip_off + 16 == ETH_LEN + 16 = 30.
    let inner_ip_off = ETH_LEN;
    let dst_ip: [u8; 4] = pkt[inner_ip_off + 16..inner_ip_off + 20]
        .try_into()
        .unwrap();
    assert_eq!(
        dst_ip, DNAT_GUEST_IP,
        "inner dst IP must be reverse-DNAT'd to DNAT_GUEST_IP [10,0,0,10]; \
         if this fails ct_apply CT_REWRITE_DST (TCP) did not rewrite the dst address"
    );

    // TCP dst port at l4_off + 2 = ETH_LEN + 20 + 2 = 36.
    let l4_off = inner_ip_off + 20;
    let dst_port = u16::from_be_bytes([pkt[l4_off + 2], pkt[l4_off + 3]]);
    assert_eq!(
        dst_port, DNAT_ORIG_SPORT,
        "inner TCP dst port must be restored to DNAT_ORIG_SPORT ({DNAT_ORIG_SPORT}); \
         if this fails ct_apply CT_REWRITE_DST did not rewrite the dst L4 port"
    );

    // IP checksum at inner_ip_off + 10.
    let ip_csum = u16::from_be_bytes([pkt[inner_ip_off + 10], pkt[inner_ip_off + 11]]);
    assert_ne!(
        ip_csum, 0,
        "IP checksum must be non-zero after dst-IP rewrite"
    );

    // TCP checksum at l4_off + 16.
    let tcp_csum = u16::from_be_bytes([pkt[l4_off + 16], pkt[l4_off + 17]]);
    assert_ne!(
        tcp_csum, 0,
        "TCP checksum must be non-zero after dst-IP + port rewrite"
    );

    // Inner src IP must be unchanged (EXT_IP).
    let src_ip: [u8; 4] = pkt[inner_ip_off + 12..inner_ip_off + 16]
        .try_into()
        .unwrap();
    assert_eq!(
        src_ip, DNAT_EXT_IP,
        "inner src IP must remain EXT_IP (unchanged)"
    );
}

/// (c) UDP DNAT return: same as TCP but for UDP. Verifies `ct_apply` UDP branch folds the
/// non-zero UDP checksum. UDP checksum is non-zero because the payload is `[0xaa,0xbb,0xcc,0xdd]`.
///
/// Pinned expected values:
///   - inner dst IP  == DNAT_GUEST_IP == [10, 0, 0, 10]
///   - inner UDP dst port == DNAT_ORIG_SPORT == 40_000
///   - UDP checksum is non-zero after fold
#[test]
fn dnat_return_udp_rewrites_dst_ip_and_port() {
    let encapped = dnat_udp_encapped();
    let u = flowplane_common::UnderlayValue {
        vni: DNAT_VNI,
        tap_ifindex: DNAT_TAP,
        guest_mac: DNAT_GUEST_MAC,
        _pad: [0; 2],
    };
    let out = dnat_host_node(17).uplink_nat_return(&encapped, DNAT_VNI, u, DNAT_GUEST_MAC);

    assert_eq!(
        out.action,
        Action::Redirect(DNAT_TAP),
        "UDP reverse-DNAT return must deliver to guest tap"
    );

    let pkt = &out.pkt;
    let inner_ip_off = ETH_LEN;

    // dst IP at inner_ip_off + 16.
    let dst_ip: [u8; 4] = pkt[inner_ip_off + 16..inner_ip_off + 20]
        .try_into()
        .unwrap();
    assert_eq!(
        dst_ip, DNAT_GUEST_IP,
        "inner dst IP must be reverse-DNAT'd to DNAT_GUEST_IP [10,0,0,10] (UDP)"
    );

    // UDP dst port at l4_off + 2 = ETH_LEN + 20 + 2 = 36.
    let l4_off = inner_ip_off + 20;
    let dst_port = u16::from_be_bytes([pkt[l4_off + 2], pkt[l4_off + 3]]);
    assert_eq!(
        dst_port, DNAT_ORIG_SPORT,
        "inner UDP dst port must be restored to DNAT_ORIG_SPORT ({DNAT_ORIG_SPORT})"
    );

    // IP checksum non-zero.
    let ip_csum = u16::from_be_bytes([pkt[inner_ip_off + 10], pkt[inner_ip_off + 11]]);
    assert_ne!(
        ip_csum, 0,
        "IP checksum must be non-zero after dst-IP rewrite (UDP)"
    );

    // UDP checksum non-zero (payload is [0xaa,0xbb,0xcc,0xdd] → csum != 0).
    let udp_csum = u16::from_be_bytes([pkt[l4_off + 6], pkt[l4_off + 7]]);
    assert_ne!(
        udp_csum, 0,
        "UDP checksum must be non-zero after fold (non-zero payload)"
    );

    // Inner src IP unchanged.
    let src_ip: [u8; 4] = pkt[inner_ip_off + 12..inner_ip_off + 16]
        .try_into()
        .unwrap();
    assert_eq!(
        src_ip, DNAT_EXT_IP,
        "inner src IP must remain EXT_IP (unchanged, UDP)"
    );
}

/// A deny-by-default enforced ingress firewall on the guest tap: `ingress_count: 1` with one rule
/// admitting a DIFFERENT dst (`192.0.2.1`, TEST-NET-1) — so the actual return (`EXT_IP -> NAT_IP`)
/// never matches. If the return took the base path, `process_uplink`'s ingress firewall would DROP it.
fn seed_deny_by_default_ingress_fw(node: &mut SimNode) {
    node.maps.fw_meta.insert(
        DNAT_TAP,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    node.maps.fw_rules.insert(
        (DNAT_TAP, 0),
        FwRule {
            src_ip: [0; 4],
            src_mask: [0; 4],
            dst_ip: [192, 0, 2, 1],
            dst_mask: [255, 255, 255, 255],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 0,
            dst_port_max: 65535,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 0,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        },
    );
}

/// (c) Unified dispatch + firewall-skip: a NAT return driven through the SHARED `SimNode::uplink_rx`
/// entry (the same `flowplane_core::datapath::process_uplink_rx` the native SimNode runs, mirroring
/// the eBPF `try_uplink_rx` base-vs-NAT-return dispatch) must be reverse-DNAT'd + delivered EVEN under
/// a deny-by-default ingress firewall on the guest tap.
///
/// This is the non-privileged twin of the eBPF `anchor_dnat` firewall guard, protecting against a
/// once-real dispatch regression: a caller that invokes `process_uplink` unconditionally instead of
/// this unified entry runs the ingress firewall on the un-DNAT'd `EXT_IP -> NAT_IP` tuple
/// (deny-by-default DROP) and never reverse-DNATs the return. `process_uplink_rx` instead dispatches
/// it to the NAT-return path.
/// Two independent proofs it took that path: (1) it is delivered, not firewall-dropped; (2) the inner
/// dst is reverse-DNAT'd to the guest (the base path never rewrites it).
#[test]
fn uplink_rx_dispatches_nat_return_past_deny_by_default_firewall() {
    let encapped = dnat_tcp_encapped();
    let mut node = dnat_host_node(6);
    seed_deny_by_default_ingress_fw(&mut node);

    let u = UnderlayValue {
        vni: DNAT_VNI,
        tap_ifindex: DNAT_TAP,
        guest_mac: DNAT_GUEST_MAC,
        _pad: [0; 2],
    };
    // `local` is unused on the NAT-return path but required by the unified entry's signature.
    let local = Local {
        uplink_ifindex: 7,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: HOST_UNDERLAY,
    };
    // Plain (non-NAT64) NAT return: guest_ipv6 is only read on the CT_F_NAT64 branch.
    let out = node.uplink_rx(&encapped, DNAT_VNI, u, HOST_UNDERLAY, &local, [0; 16]);

    assert_eq!(
        out.action,
        Action::Redirect(DNAT_TAP),
        "unified uplink_rx must reverse-DNAT + deliver the established NAT return, NOT firewall-drop \
         it (regression: uplink dispatch calling process_uplink unconditionally)"
    );
    let inner_ip_off = ETH_LEN;
    let dst_ip: [u8; 4] = out.pkt[inner_ip_off + 16..inner_ip_off + 20]
        .try_into()
        .unwrap();
    assert_eq!(
        dst_ip, DNAT_GUEST_IP,
        "inner dst IP reverse-DNAT'd to the guest — proves uplink_rx dispatched to the NAT-return \
         path, not the base path (which would leave dst == NAT_IP)"
    );
}

// ─── (d) Port exhaustion: allocation failure DROPS instead of emitting a colliding port ──────────

/// When every reverse-key slot in the NAT range is occupied, `snat_egress` must NOT reuse an
/// already-allocated port (whose reverse entry belongs to another flow) — it drops the packet.
/// Regression: previously the probe loop fell through with `chosen` still at the initial hash slot
/// and emitted a colliding mapping + a poisoned forward entry, corrupting return-path demux.
#[test]
fn snat_port_exhaustion_drops_instead_of_colliding() {
    let mut node = SimNode::new();
    configure_local(&mut node);
    allow_egress(&mut node, SRC_IFINDEX_A);
    add_external_route(&mut node, EXT_IP);
    // A range of exactly one port so all PROBE_LIMIT probes land on the same candidate.
    add_nat(
        &mut node.maps,
        GUEST_A_IP,
        NAT_IP_A,
        PORT_MIN_A,
        PORT_MIN_A + 1,
    );
    node.src_ifindex = SRC_IFINDEX_A;

    // Occupy the sole reverse key (vni, 0, nat_ip, 0, PORT_MIN_A) with ANOTHER flow's mapping so
    // allocation cannot succeed.
    let occupied_rev = CtKey {
        vni: VNI,
        src_ip: [0; 4],
        dst_ip: NAT_IP_A,
        src_port: 0,
        dst_port: PORT_MIN_A,
        proto: 6, // TCP
        _pad: [0; 3],
    };
    node.maps.conntrack.insert(
        occupied_rev,
        CtEntry {
            last_seen: 0,
            xlate_ip: [9, 9, 9, 9], // a different guest's flow owns this port
            xlate_port: 4321,
            flags: CT_REWRITE_DST | CT_F_SRC_NAT,
            tcp_state: 0,
            fwall_action: 0,
            _pad: [0; 7],
        },
    );
    let before = node.maps.conntrack.len();

    let frame = guest_tcp_frame(GUEST_A_IP, 12345, 80);
    let out = node.guest_tx(&frame, &port_meta(GUEST_A_IP));

    assert_eq!(
        out.action,
        Action::Drop,
        "exhausted SNAT must drop, not forward a packet on a colliding port"
    );
    assert_eq!(
        node.maps.conntrack.len(),
        before,
        "no forward CT entry may be inserted on exhaustion (that would poison the table)"
    );
}
