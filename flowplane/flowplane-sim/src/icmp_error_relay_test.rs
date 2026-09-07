//! F3 — ICMP-error LB relay oracle coverage (v4). An ICMP error (type 3/11/12) destined to a VIP,
//! whose embedded inner is a TCP/UDP flow SOURCED from that VIP, is relayed (bytes unchanged) to the
//! Maglev backend that owns the ORIGINAL client->VIP flow. Faithful rebuild of the pre-P2 eBPF
//! `lb::lb_select_forward_icmp_error` (recovered from 7a9a962), now in flowplane_core + sim-tested.

use flowplane_common::{FwMeta, FwRule, IfaceValue, LbBackend, LbKey, LbValue, Local, MaglevKey};
use flowplane_core::pkt::Action;

use crate::SimNode;

// PMTUD fix (see `process_uplink`'s `is_icmp_relay` exemption): the ICMP-error relay arm is now EXEMPT
// from the backend's ingress firewall, so the LOCAL-delivery relay tests below deliver regardless of the
// backend policy — they seed NO ingress allow-all (an earlier revision had to, because the relayed error
// was evaluated on its OUTER ICMP tuple and dropped by the default-deny). `icmp_error_relayed_through_
// realistic_backend_firewall` proves the exemption survives a realistic restrictive policy; the plain
// LOCAL tests run with no firewall at all. The REMOTE-delivery tests return via `reforward()` before the
// firewall check regardless.

const VNI: u32 = 100;
const VIP: [u8; 4] = [203, 0, 113, 50];
const CLIENT: [u8; 4] = [198, 51, 100, 9];
const ROUTER: [u8; 4] = [192, 0, 2, 1]; // the node that emitted the ICMP error (outer src)
const SERVICE_PORT: u16 = 443;
const CLIENT_PORT: u16 = 51000;

const BACKEND_A_UL: [u8; 16] = ul(0xa1);
const BACKEND_B_UL: [u8; 16] = ul(0xb2);
const LOCAL_UL: [u8; 16] = ul(0x0e);
const BACKEND_A_TAP: u32 = 61;
// The LOCAL-delivery tests below select a backend that IS this node itself (LOCAL_UL), so the LB
// arm resolves the delivery tap via `INTERFACES[(vni, BACKEND_A_OVERLAY_IP)]`.
const BACKEND_A_OVERLAY_IP: [u8; 4] = [10, 0, 0, 181];

const fn ul(last: u8) -> [u8; 16] {
    [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last]
}

/// Left-justify a v4 addr into the 16-byte `LbBackend.overlay_ip` representation (`is_v6 == 0`).
const fn v4_in_16(ip: [u8; 4]) -> [u8; 16] {
    [
        ip[0], ip[1], ip[2], ip[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
}

fn local() -> Local {
    Local {
        uplink_ifindex: 5,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: LOCAL_UL,
    }
}

/// A node with a 2-backend WAN LB service for VIP:SERVICE_PORT (both backends remote by default).
fn edge_node_two_backends() -> SimNode {
    let mut n = SimNode::with_local(local());
    n.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: VIP,
            port: SERVICE_PORT,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 1,
            size: 2,
        },
    );
    n.maps.maglev.insert(
        MaglevKey {
            table_id: 1,
            slot: 0,
        },
        LbBackend {
            node_vtep: BACKEND_A_UL,
            vni: VNI,
            ..Default::default()
        },
    );
    n.maps.maglev.insert(
        MaglevKey {
            table_id: 1,
            slot: 1,
        },
        LbBackend {
            node_vtep: BACKEND_B_UL,
            vni: VNI,
            ..Default::default()
        },
    );
    n
}

/// Build `[Eth][outer IPv4 proto=ICMP][ICMP error(8)][embedded IPv4][embedded L4(8)]`, hand-assembled
/// with correct outer + embedded IPv4 header checksums. `err_type` = ICMP type (3/11/12). Embedded
/// inner = the ORIGINAL VIP->CLIENT packet (src=VIP:SERVICE_PORT, dst=CLIENT:CLIENT_PORT).
fn eth_icmp_error_embedding_vip_flow(err_type: u8, inner_proto: u8) -> Vec<u8> {
    fn ipv4_hdr(src: [u8; 4], dst: [u8; 4], proto: u8, total_len: u16) -> [u8; 20] {
        let mut h = [0u8; 20];
        h[0] = 0x45; // v4, IHL=5
        h[2..4].copy_from_slice(&total_len.to_be_bytes());
        h[8] = 64; // TTL
        h[9] = proto;
        h[12..16].copy_from_slice(&src);
        h[16..20].copy_from_slice(&dst);
        let mut sum = 0u32;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([h[i], h[i + 1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let csum = !(sum as u16);
        h[10..12].copy_from_slice(&csum.to_be_bytes());
        h
    }
    // embedded inner: VIP:SERVICE_PORT -> CLIENT:CLIENT_PORT, first 8 L4 bytes suffice.
    let mut embedded = Vec::new();
    embedded.extend_from_slice(&ipv4_hdr(VIP, CLIENT, inner_proto, 28)); // 20 IP + 8 L4
    embedded.extend_from_slice(&SERVICE_PORT.to_be_bytes()); // sport
    embedded.extend_from_slice(&CLIENT_PORT.to_be_bytes()); // dport
    embedded.extend_from_slice(&[0u8; 4]); // rest of the (truncated) L4 header
                                           // outer ICMP error: type, code=0, csum(unchecked here), 4 unused bytes, then embedded.
    let mut icmp = vec![err_type, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&embedded);
    // outer IPv4: ROUTER -> VIP, proto=ICMP(1).
    let outer_total = (20 + icmp.len()) as u16;
    let mut frame = vec![
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x08, 0x00,
    ];
    frame.extend_from_slice(&ipv4_hdr(ROUTER, VIP, 1, outer_total));
    frame.extend_from_slice(&icmp);
    frame
}

#[test]
fn icmp_error_to_vip_relays_to_backend() {
    // size-1 table: any embedded VIP flow relays to the single backend, delivered locally.
    let mut n = SimNode::with_local(local());
    n.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: VIP,
            port: SERVICE_PORT,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 9,
            size: 1,
        },
    );
    // Self-select (LOCAL_UL == this node's own `local()` underlay): the LB arm takes the
    // local-delivery branch and resolves the tap via `INTERFACES[(vni, BACKEND_A_OVERLAY_IP)]`.
    n.maps.maglev.insert(
        MaglevKey {
            table_id: 9,
            slot: 0,
        },
        LbBackend {
            node_vtep: LOCAL_UL,
            overlay_ip: v4_in_16(BACKEND_A_OVERLAY_IP),
            vni: VNI,
            is_v6: 0,
            _pad: [0; 3],
        },
    );
    n.maps.add_iface(
        VNI,
        BACKEND_A_OVERLAY_IP,
        IfaceValue {
            tap_ifindex: BACKEND_A_TAP,
            is_local: 1,
            underlay_ipv6: LOCAL_UL,
            guest_mac: [7; 6],
            peer_capable: 0,
            _pad: [0; 1],
        },
    );

    let frame = eth_icmp_error_embedding_vip_flow(3, 6); // dest-unreach, embedded TCP
    let orig = frame.clone();
    let out = n.uplink(&frame, VNI, &local());

    assert_eq!(
        out.action,
        Action::Redirect(BACKEND_A_TAP),
        "ICMP error to a VIP must be relayed to the Maglev backend (local delivery)"
    );
    // The relay forwards the ICMP-error frame's IP payload unchanged (only the inner Ethernet header,
    // bytes 0..14, is rewritten by decap_and_rewrite; the IP payload at 14.. is intact).
    assert_eq!(
        &out.pkt[14..],
        &orig[14..],
        "ICMP-error IP payload relayed byte-unchanged"
    );
}

/// A REALISTIC backend ingress policy: allow only TCP/`SERVICE_PORT` from anywhere (`ingress_count = 1`
/// so the default-deny is armed). This does NOT match the relayed ICMP error's OUTER tuple (proto = 1),
/// so before the PMTUD fix the relayed error was dropped here; after it, the relay arm is exempt.
fn allow_ingress_tcp_service_port(n: &mut SimNode, tap: u32) {
    n.maps.fw_meta.insert(
        tap,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    n.maps.fw_rules.insert(
        (tap, 0),
        FwRule {
            src_ip: [0, 0, 0, 0],
            src_mask: [0, 0, 0, 0],
            dst_ip: [0, 0, 0, 0],
            dst_mask: [0, 0, 0, 0],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: SERVICE_PORT,
            dst_port_max: SERVICE_PORT,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: 1,
            direction: 0,
            enabled: 1,
        },
    );
}

/// Build the size-1 self-select local-backend node used by the LOCAL-delivery relay tests, WITHOUT any
/// firewall seeding (each caller seeds its own). Self-select: `LOCAL_UL == local()`'s underlay, so the
/// LB arm takes the local-delivery branch and resolves the tap via `INTERFACES[(vni, overlay)]`.
fn local_backend_node(inner_proto: u8, table_id: u32) -> SimNode {
    let mut n = SimNode::with_local(local());
    n.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: VIP,
            port: SERVICE_PORT,
            proto: inner_proto,
            _pad: 0,
        },
        LbValue { table_id, size: 1 },
    );
    n.maps.maglev.insert(
        MaglevKey { table_id, slot: 0 },
        LbBackend {
            node_vtep: LOCAL_UL,
            overlay_ip: v4_in_16(BACKEND_A_OVERLAY_IP),
            vni: VNI,
            is_v6: 0,
            _pad: [0; 3],
        },
    );
    n.maps.add_iface(
        VNI,
        BACKEND_A_OVERLAY_IP,
        IfaceValue {
            tap_ifindex: BACKEND_A_TAP,
            is_local: 1,
            underlay_ipv6: LOCAL_UL,
            guest_mac: [7; 6],
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    n
}

#[test]
fn icmp_error_relayed_through_realistic_backend_firewall() {
    // PMTUD fix: a relayed ICMP error is EXEMPT from the backend's ingress firewall. Seed a realistic
    // "allow TCP/443 from any" backend policy — it does NOT match the relayed error's OUTER ICMP tuple
    // (proto = 1), so before the fix this dropped (blackholing PMTUD/dest-unreachable feedback). The
    // relay arm now bypasses step 2, so the error reaches the backend that owns the embedded flow.
    let mut n = local_backend_node(6, 9);
    allow_ingress_tcp_service_port(&mut n, BACKEND_A_TAP);
    let frame = eth_icmp_error_embedding_vip_flow(3, 6); // dest-unreach, embedded TCP
    assert_eq!(
        n.uplink(&frame, VNI, &local()).action,
        Action::Redirect(BACKEND_A_TAP),
        "relayed ICMP error must bypass the backend ingress firewall (PMTUD reaches the backend)"
    );
}

#[test]
fn icmp_error_selects_on_embedded_inner_not_outer() {
    // Prove the relay hashes the EMBEDDED flow. 2-backend table, both remote -> observe the reforward
    // target (TunnelEncap.remote). Determinism: same embedded flow -> same backend every build.
    let frame = eth_icmp_error_embedding_vip_flow(11, 6); // time-exceeded, embedded TCP
    let out = edge_node_two_backends().uplink(&frame, VNI, &local());

    let remote = out
        .tunnel
        .expect("remote backend relay must emit a TunnelEncap")
        .remote;
    assert!(
        remote == BACKEND_A_UL || remote == BACKEND_B_UL,
        "relayed to one of the seeded backends"
    );
    let out2 = edge_node_two_backends().uplink(&frame, VNI, &local());
    assert_eq!(
        out2.tunnel.expect("remote relay").remote,
        remote,
        "relay backend selection is deterministic for a fixed embedded flow"
    );
}

#[test]
fn icmp_error_embedded_src_not_a_vip_is_not_relayed() {
    // No LB service for the embedded src -> not relayed -> normal path (Drop: no local iface/not edge).
    let mut n = edge_node_two_backends();
    n.maps.lb.clear();
    let frame = eth_icmp_error_embedding_vip_flow(3, 6);
    let out = n.uplink(&frame, VNI, &local());
    assert_eq!(
        out.action,
        Action::Drop,
        "no VIP match -> falls through to the base path (Drop)"
    );
}

#[test]
fn icmp_error_embedded_udp_relayed_but_icmp_embedded_not() {
    // Embedded UDP relays; embedded ICMP (proto 1) does not (matches dpservice: TCP/UDP only).
    let mut relayed = SimNode::with_local(local());
    relayed.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: VIP,
            port: SERVICE_PORT,
            proto: 17,
            _pad: 0,
        },
        LbValue {
            table_id: 5,
            size: 1,
        },
    );
    // Self-select (LOCAL_UL == this node's own `local()` underlay) — same shape as
    // `icmp_error_to_vip_relays_to_backend`.
    relayed.maps.maglev.insert(
        MaglevKey {
            table_id: 5,
            slot: 0,
        },
        LbBackend {
            node_vtep: LOCAL_UL,
            overlay_ip: v4_in_16(BACKEND_A_OVERLAY_IP),
            vni: VNI,
            is_v6: 0,
            _pad: [0; 3],
        },
    );
    relayed.maps.add_iface(
        VNI,
        BACKEND_A_OVERLAY_IP,
        IfaceValue {
            tap_ifindex: BACKEND_A_TAP,
            is_local: 1,
            underlay_ipv6: LOCAL_UL,
            guest_mac: [7; 6],
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    let udp_frame = eth_icmp_error_embedding_vip_flow(3, 17);
    assert_eq!(
        relayed.uplink(&udp_frame, VNI, &local()).action,
        Action::Redirect(BACKEND_A_TAP),
        "embedded UDP flow relays"
    );

    let mut n = edge_node_two_backends();
    let icmp_inner = eth_icmp_error_embedding_vip_flow(3, 1);
    assert_eq!(
        n.uplink(&icmp_inner, VNI, &local()).action,
        Action::Drop,
        "embedded ICMP not relayed"
    );
}
