//! ICMPv6-error LB relay oracle coverage (v6 sibling of `icmp_error_relay_test.rs`). An ICMPv6 error
//! (type 1/2/3/4) destined to a VIP, whose embedded inner is a TCP/UDP flow SOURCED from that VIP, is
//! relayed (bytes unchanged) to the Maglev backend that owns the ORIGINAL client->VIP flow — so PMTUD
//! (ICMPv6 Packet Too Big, type 2) / dest-unreachable errors reach the right backend. Fresh v6 mirror
//! of the v4 F3 relay (no pre-P2 eBPF original existed for v6); now in flowplane_core + sim-tested.

use flowplane_common::{FwMeta, FwRule6, IfaceValue, LbBackend, LbKey, LbValue, Local, MaglevKey};
use flowplane_core::pkt::Action;

use crate::SimNode;

// PMTUD fix (see `process_uplink_v6`'s `is_icmp_relay` exemption, v6 sibling of the v4 note): the
// ICMPv6-error relay arm is now EXEMPT from the backend's ingress firewall, so the LOCAL-delivery relay
// tests below deliver regardless of the backend policy and seed NO ingress allow-all. `icmpv6_error_
// relayed_through_realistic_backend_firewall` proves the exemption survives a realistic restrictive
// policy; the plain LOCAL tests run with no firewall at all. The REMOTE-delivery tests return via
// `reforward()` before the firewall check regardless.

const VNI: u32 = 100;
const VIP: [u8; 16] = addr6(0x50);
const CLIENT: [u8; 16] = addr6(0x09);
const ROUTER: [u8; 16] = addr6(0x01); // the node that emitted the ICMPv6 error (outer src)
const SERVICE_PORT: u16 = 443;
const CLIENT_PORT: u16 = 51000;

const BACKEND_A_UL: [u8; 16] = ul(0xa1);
const BACKEND_B_UL: [u8; 16] = ul(0xb2);
const LOCAL_UL: [u8; 16] = ul(0x0e);
const BACKEND_A_TAP: u32 = 61;
// The LOCAL-delivery tests below select a backend that IS this node itself (LOCAL_UL), so the LB arm
// resolves the delivery tap via `INTERFACES6[(vni, BACKEND_A_OVERLAY_IP6)]`.
const BACKEND_A_OVERLAY_IP6: [u8; 16] = addr6(0xb1);

/// A documentation-prefix v6 addr (`2001:db8::last`) for the overlay VIP/client/router side.
const fn addr6(last: u8) -> [u8; 16] {
    [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last,
    ]
}

/// A `2001::last` underlay /128 (VTEP side).
const fn ul(last: u8) -> [u8; 16] {
    [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last]
}

/// `last4` of a v6 addr — the control-plane LB-key convention (matches `lb_select_forward_v6`).
const fn last4(a: [u8; 16]) -> [u8; 4] {
    [a[12], a[13], a[14], a[15]]
}

fn local() -> Local {
    Local {
        uplink_ifindex: 5,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: LOCAL_UL,
    }
}

/// A node with a 2-backend WAN LB service for `(VNI, last4(VIP), SERVICE_PORT, TCP)` (both remote).
fn edge_node_two_backends() -> SimNode {
    let mut n = SimNode::with_local(local());
    n.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: last4(VIP),
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
            is_v6: 1,
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
            is_v6: 1,
            ..Default::default()
        },
    );
    n
}

/// Build `[Eth(0x86DD)][outer IPv6 nexthdr=ICMPv6(58)][ICMPv6 error(8)][embedded IPv6][embedded L4(8)]`.
/// `err_type` = ICMPv6 type (1 DestUnreach / 2 PacketTooBig / 3 TimeExceeded / 4 ParamProblem). The
/// embedded inner = the ORIGINAL VIP->CLIENT packet (src=VIP:SERVICE_PORT, dst=CLIENT:CLIENT_PORT).
fn eth_icmp6_error_embedding_vip_flow(err_type: u8, inner_proto: u8) -> Vec<u8> {
    fn ipv6_hdr(src: [u8; 16], dst: [u8; 16], nexthdr: u8, payload_len: u16) -> [u8; 40] {
        let mut h = [0u8; 40];
        h[0] = 0x60; // version 6
        h[4..6].copy_from_slice(&payload_len.to_be_bytes());
        h[6] = nexthdr;
        h[7] = 64; // hop limit
        h[8..24].copy_from_slice(&src);
        h[24..40].copy_from_slice(&dst);
        h
    }
    // embedded inner: VIP:SERVICE_PORT -> CLIENT:CLIENT_PORT, first 8 L4 bytes suffice.
    let mut embedded = Vec::new();
    embedded.extend_from_slice(&ipv6_hdr(VIP, CLIENT, inner_proto, 8)); // 8 L4 bytes as payload
    embedded.extend_from_slice(&SERVICE_PORT.to_be_bytes()); // sport
    embedded.extend_from_slice(&CLIENT_PORT.to_be_bytes()); // dport
    embedded.extend_from_slice(&[0u8; 4]); // rest of the (truncated) L4 header
                                           // ICMPv6 error: type, code=0, csum(unchecked here), 4 bytes (MTU/pointer/unused), then embedded.
    let mut icmp = vec![err_type, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&embedded);
    // outer IPv6: ROUTER -> VIP, nexthdr=ICMPv6(58).
    let mut frame = vec![
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x86, 0xDD,
    ];
    frame.extend_from_slice(&ipv6_hdr(ROUTER, VIP, 58, icmp.len() as u16));
    frame.extend_from_slice(&icmp);
    frame
}

/// A size-1 LB service whose sole backend is THIS node (LOCAL_UL) — the LB arm takes the local-delivery
/// branch and resolves the tap via `INTERFACES6[(vni, BACKEND_A_OVERLAY_IP6)]`.
fn local_backend_node(inner_proto: u8, table_id: u32) -> SimNode {
    let mut n = SimNode::with_local(local());
    n.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: last4(VIP),
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
            overlay_ip: BACKEND_A_OVERLAY_IP6,
            vni: VNI,
            is_v6: 1,
            _pad: [0; 3],
        },
    );
    n.maps.add_iface6(
        VNI,
        BACKEND_A_OVERLAY_IP6,
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
fn icmpv6_error_to_vip_relays_to_backend() {
    // ICMPv6 Packet Too Big (type 2 — the v6 PMTUD case): the embedded VIP flow relays to the single
    // backend, delivered locally. The relay forwards the frame's IP payload byte-unchanged.
    let mut n = local_backend_node(6, 9);
    let frame = eth_icmp6_error_embedding_vip_flow(2, 6); // packet-too-big, embedded TCP
    let orig = frame.clone();
    let out = n.uplink_v6(&frame, VNI, &local());

    assert_eq!(
        out.action,
        Action::Redirect(BACKEND_A_TAP),
        "ICMPv6 error to a VIP must be relayed to the Maglev backend (local delivery)"
    );
    // Only the inner Ethernet header (bytes 0..14) is rewritten by decap_and_rewrite; the IP payload
    // at 14.. is intact.
    assert_eq!(
        &out.pkt[14..],
        &orig[14..],
        "ICMPv6-error IP payload relayed byte-unchanged"
    );
}

/// A REALISTIC backend ingress policy: allow only TCP/`SERVICE_PORT` from anywhere (`ingress_count = 1`
/// so the default-deny is armed). This does NOT match the relayed ICMPv6 error's OUTER tuple (nexthdr =
/// 58), so before the PMTUD fix the relayed error was dropped here; after it, the relay arm is exempt.
fn allow_ingress_tcp_service_port6(n: &mut SimNode, tap: u32) {
    n.maps.fw_meta6.insert(
        tap,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    n.maps.fw_rules6.insert(
        (tap, 0),
        FwRule6 {
            src_ip: [0; 16],
            src_mask: [0; 16],
            dst_ip: [0; 16],
            dst_mask: [0; 16],
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

#[test]
fn icmpv6_error_relayed_through_realistic_backend_firewall() {
    // PMTUD fix (v6): a relayed ICMPv6 error is EXEMPT from the backend's ingress firewall. Seed a
    // realistic "allow TCP/443 from any" backend policy — it does NOT match the relayed error's OUTER
    // ICMPv6 tuple (nexthdr = 58), so before the fix this dropped (blackholing the ICMPv6 Packet-Too-Big
    // PMTUD feedback). The relay arm now bypasses step 2, so the error reaches the owning backend.
    let mut n = local_backend_node(6, 9);
    allow_ingress_tcp_service_port6(&mut n, BACKEND_A_TAP);
    let frame = eth_icmp6_error_embedding_vip_flow(2, 6); // packet-too-big, embedded TCP
    assert_eq!(
        n.uplink_v6(&frame, VNI, &local()).action,
        Action::Redirect(BACKEND_A_TAP),
        "relayed ICMPv6 error must bypass the backend ingress firewall (PMTUD reaches the backend)"
    );
}

#[test]
fn icmpv6_error_selects_on_embedded_inner_not_outer() {
    // Prove the relay hashes the EMBEDDED flow, for EVERY ICMPv6 error type. 2-backend table, both
    // remote -> observe the reforward target (TunnelEncap.remote). Determinism: same embedded flow ->
    // same backend every build, regardless of error type.
    let mut chosen: Option<[u8; 16]> = None;
    for err_type in [1u8, 2, 3, 4] {
        let frame = eth_icmp6_error_embedding_vip_flow(err_type, 6);
        let out = edge_node_two_backends().uplink_v6(&frame, VNI, &local());
        let remote = out
            .tunnel
            .unwrap_or_else(|| {
                panic!("type {err_type}: remote backend relay must emit a TunnelEncap")
            })
            .remote;
        assert!(
            remote == BACKEND_A_UL || remote == BACKEND_B_UL,
            "type {err_type}: relayed to one of the seeded backends"
        );
        match chosen {
            None => chosen = Some(remote),
            Some(prev) => assert_eq!(
                prev, remote,
                "relay backend selection is independent of the ICMPv6 error type"
            ),
        }
    }
}

#[test]
fn icmpv6_error_embedded_src_not_a_vip_is_not_relayed() {
    // No LB service for the embedded src -> not relayed -> normal path (Drop: no local iface/not edge).
    let mut n = edge_node_two_backends();
    n.maps.lb.clear();
    let frame = eth_icmp6_error_embedding_vip_flow(1, 6);
    let out = n.uplink_v6(&frame, VNI, &local());
    assert_eq!(
        out.action,
        Action::Drop,
        "no VIP match -> falls through to the base v6 path (Drop)"
    );
}

#[test]
fn icmpv6_error_embedded_udp_relayed_but_icmp6_embedded_not() {
    // Embedded UDP relays; embedded ICMPv6 (proto 58) does not (matches dpservice: TCP/UDP only).
    let mut relayed = local_backend_node(17, 5);
    let udp_frame = eth_icmp6_error_embedding_vip_flow(1, 17);
    assert_eq!(
        relayed.uplink_v6(&udp_frame, VNI, &local()).action,
        Action::Redirect(BACKEND_A_TAP),
        "embedded UDP flow relays"
    );

    let mut n = edge_node_two_backends();
    let icmp_inner = eth_icmp6_error_embedding_vip_flow(1, 58);
    assert_eq!(
        n.uplink_v6(&icmp_inner, VNI, &local()).action,
        Action::Drop,
        "embedded ICMPv6 not relayed"
    );
}
