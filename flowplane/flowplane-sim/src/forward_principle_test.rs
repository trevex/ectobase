//! Locks the "dataplane forwards L3 (incl. ICMP echo); it does NOT answer ping locally" principle
//! (only ARP/ND/RA/DHCP are answered locally, elsewhere). A regression that reintroduces a local
//! ICMP echo responder for a VIP / NAT IP fails here.

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, IfaceValue, LbBackend, LbKey, LbValue, Local, MaglevKey, FW_ACTION_ACCEPT,
    FW_DIR_INGRESS,
};
use flowplane_core::pkt::Action;

use crate::SimNode;

const VNI: u32 = 100;
const VIP: [u8; 4] = [203, 0, 113, 50];
const NAT_IP: [u8; 4] = [203, 0, 113, 60];
const CLIENT: [u8; 4] = [198, 51, 100, 9];
// The backend is THIS node itself (LB self-select, DSR): its node_vtep must equal `local()`'s own
// underlay so the LB arm takes the local-delivery branch and resolves the tap via
// `INTERFACES[(vni, BACKEND_OVERLAY_IP)]`.
const BACKEND_UL: [u8; 16] = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e];
const BACKEND_OVERLAY_IP: [u8; 4] = [10, 0, 0, 181];
const BACKEND_TAP: u32 = 61;

fn local() -> Local {
    Local {
        uplink_ifindex: 5,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: BACKEND_UL,
    }
}

/// Seed a permissive ingress ALLOW (proto/addr/port wildcard) on `tap` so the shared LB
/// local-delivery arm's deny-by-default ingress firewall does not drop the forwarded packet
/// before the behavior under test is observed. Mirrors nat_test.rs / lb_scenario_test.rs precedent.
fn allow_ingress_all(node: &mut SimNode, tap: u32) {
    node.maps.fw_meta.insert(
        tap,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    node.maps.fw_rules.insert(
        (tap, 0),
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
            proto: 0,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        },
    );
}

fn eth_ipv4_icmp_echo(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(src, dst, 64)
        .icmpv4_echo_request(1, 1);
    let mut out = Vec::new();
    b.write(&mut out, &[0xde, 0xad]).unwrap();
    out
}

#[test]
fn ping_to_lb_vip_forwards_to_backend_not_answered() {
    let mut n = SimNode::with_local(local());
    // ICMP LB service (proto 1, port 0 — lb_select_forward uses lookup_port 0 for ICMP).
    n.maps.lb.insert(
        LbKey {
            vni: VNI,
            ipv4: VIP,
            port: 0,
            proto: 1,
            _pad: 0,
        },
        LbValue {
            table_id: 3,
            size: 1,
        },
    );
    n.maps.maglev.insert(
        MaglevKey {
            table_id: 3,
            slot: 0,
        },
        LbBackend {
            node_vtep: BACKEND_UL,
            overlay_ip: {
                let mut o = [0u8; 16];
                o[..4].copy_from_slice(&BACKEND_OVERLAY_IP);
                o
            },
            vni: VNI,
            is_v6: 0,
            _pad: [0; 3],
        },
    );
    n.maps.add_iface(
        VNI,
        BACKEND_OVERLAY_IP,
        IfaceValue {
            tap_ifindex: BACKEND_TAP,
            is_local: 1,
            underlay_ipv6: BACKEND_UL,
            guest_mac: [7; 6],
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    allow_ingress_all(&mut n, BACKEND_TAP);

    let frame = eth_ipv4_icmp_echo(CLIENT, VIP);
    let out = n.uplink(&frame, VNI, &local());
    assert_eq!(
        out.action,
        Action::Redirect(BACKEND_TAP),
        "ping to an LB VIP must be Maglev-forwarded to a backend, NOT answered locally"
    );
    // Still an echo REQUEST (type 8): the dataplane did not synthesize a reply.
    let l4 = 14 + 20;
    assert_eq!(
        out.pkt[l4], 8,
        "must remain an echo request forwarded to the backend"
    );
}

#[test]
fn ping_to_nat_ip_with_no_conntrack_drops_not_answered() {
    // A NAT IP is a SNAT egress address with no backend; an unsolicited ping with no reverse CT
    // must fall through to the base path and Drop (fail-closed), never be answered in place.
    let mut n = SimNode::with_local(local());
    n.maps.nat_ips.insert((VNI, NAT_IP));
    let frame = eth_ipv4_icmp_echo(CLIENT, NAT_IP);
    let out = n.uplink_rx(&frame, VNI, &local());
    assert_eq!(
        out.action,
        Action::Drop,
        "unsolicited ping to a NAT IP drops (no backend, no CT); the dataplane does not answer it"
    );
}
