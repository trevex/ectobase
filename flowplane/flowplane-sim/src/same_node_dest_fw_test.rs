//! Same-node delivery enforces the DESTINATION's ingress firewall in the guest-egress path (the
//! cross-node uplink ingress path, where it normally runs, is skipped). A flow the destination
//! denies must stay denied for its whole life — not just its first packet.

use etherparse::PacketBuilder;
use flowplane_common::{
    FwRule, FwRule6, IfaceValue, PortMeta, RouteValue, UnderlayValue, FW_ACTION_ACCEPT,
    FW_DIR_EGRESS,
};

use crate::SimNode;
use flowplane_core::pkt::Action;

const VNI: u32 = 300;
const SRC_IP: [u8; 4] = [10, 0, 0, 10];
const DST_IP: [u8; 4] = [10, 0, 0, 20];
const SRC_IFINDEX: u32 = 10;
const DST_TAP: u32 = 77;
const DST_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

fn frame(syn: bool) -> Vec<u8> {
    let mut step = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
        .ipv4(SRC_IP, DST_IP, 64)
        .tcp(40000, 22, 0, 1024);
    step = if syn { step.syn() } else { step.ack(1) };
    let mut out = Vec::new();
    step.write(&mut out, &[]).unwrap();
    out
}

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: SRC_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: [0xaa; 6],
        l3: 0,
        offloaded: 0,
        underlay_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

/// The source may send anything; the destination (DST_TAP) has no ingress rules at all, so its
/// deny-by-default applies to everything.
fn node() -> SimNode {
    let mut node = SimNode::new();
    node.maps.underlay.insert(
        DST_UNDERLAY,
        UnderlayValue {
            vni: VNI,
            tap_ifindex: DST_TAP,
            guest_mac: [0xcc; 6],
            _pad: [0; 2],
        },
    );
    node.maps.add_route4(
        VNI,
        DST_IP,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: DST_UNDERLAY,
            is_external: 0,
            _pad: [0; 3],
        },
    );
    // Local delivery is demuxed by (vni, overlay dst) via INTERFACES.
    node.maps.add_iface(
        VNI,
        DST_IP,
        IfaceValue {
            tap_ifindex: DST_TAP,
            is_local: 1,
            underlay_ipv6: [0; 16],
            guest_mac: [0xcc; 6],
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    node.maps.add_fw_rule(
        SRC_IFINDEX,
        FwRule {
            src_port_max: 65535,
            dst_port_max: 65535,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_EGRESS,
            enabled: 1,
            ..Default::default()
        },
    );
    node.src_ifindex = SRC_IFINDEX;
    node
}

/// Control: with an ingress allow on the destination, the same flow is delivered — so a Drop in the
/// test below is the destination's firewall, not the wiring.
#[test]
fn a_flow_the_destination_allows_is_delivered() {
    let mut n = node();
    n.maps.add_fw_rule(
        DST_TAP,
        FwRule {
            src_port_max: 65535,
            dst_port_max: 65535,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            action: FW_ACTION_ACCEPT,
            enabled: 1,
            ..Default::default()
        },
    );
    let meta = port_meta();
    for syn in [true, false] {
        assert_eq!(
            n.guest_tx(&frame(syn), &meta).action,
            Action::Redirect(DST_TAP)
        );
    }
}

#[test]
fn a_flow_the_destination_denies_stays_denied() {
    let mut n = node();
    let meta = port_meta();
    assert_eq!(
        n.guest_tx(&frame(true), &meta).action,
        Action::Drop,
        "first packet"
    );
    assert_eq!(
        n.guest_tx(&frame(false), &meta).action,
        Action::Drop,
        "second packet of the same flow slipped past the destination's ingress firewall"
    );
}

/// The refused first packet must not leave a pre-seeded reverse entry behind either: the
/// destination (which may not send anything — it has no egress rules) would otherwise reach the
/// source by riding it, past its own egress firewall and the source's ingress firewall.
#[test]
fn a_refused_flow_opens_no_path_back() {
    let mut n = node();
    // The source is locally deliverable too.
    n.maps.add_iface(
        VNI,
        SRC_IP,
        IfaceValue {
            tap_ifindex: SRC_IFINDEX,
            is_local: 1,
            underlay_ipv6: [0; 16],
            guest_mac: [0xaa; 6],
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    n.maps.add_route4(
        VNI,
        SRC_IP,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: DST_UNDERLAY,
            is_external: 0,
            _pad: [0; 3],
        },
    );
    let meta = port_meta();
    assert_eq!(n.guest_tx(&frame(true), &meta).action, Action::Drop);

    // The reply-shaped packet from the destination back to the source.
    let mut back = Vec::new();
    PacketBuilder::ethernet2([0xcc; 6], [0xbb; 6])
        .ipv4(DST_IP, SRC_IP, 64)
        .tcp(22, 40000, 0, 1024)
        .syn()
        .ack(1)
        .write(&mut back, &[])
        .unwrap();
    n.src_ifindex = DST_TAP;
    let dst_meta = PortMeta {
        guest_ipv4: DST_IP,
        guest_mac: [0xcc; 6],
        ..port_meta()
    };
    assert_eq!(
        n.guest_tx(&back, &dst_meta).action,
        Action::Drop,
        "the destination reached the source through the refused flow's reverse entry"
    );
}

// ---- IPv6 ---------------------------------------------------------------------------------------

const SRC6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];
const DST6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
];

fn frame6(syn: bool) -> Vec<u8> {
    let mut step = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
        .ipv6(SRC6, DST6, 64)
        .tcp(40000, 22, 0, 1024);
    step = if syn { step.syn() } else { step.ack(1) };
    let mut out = Vec::new();
    step.write(&mut out, &[]).unwrap();
    out
}

fn node6() -> SimNode {
    let mut node = SimNode::new();
    node.maps.add_route6(
        VNI,
        DST6,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: DST_UNDERLAY,
            is_external: 0,
            _pad: [0; 3],
        },
    );
    node.maps.add_iface6(
        VNI,
        DST6,
        IfaceValue {
            tap_ifindex: DST_TAP,
            is_local: 1,
            underlay_ipv6: [0; 16],
            guest_mac: [0xcc; 6],
            peer_capable: 0,
            _pad: [0; 1],
        },
    );
    node.maps.add_fw_rule6(
        SRC_IFINDEX,
        FwRule6 {
            src_port_max: 65535,
            dst_port_max: 65535,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_EGRESS,
            enabled: 1,
            ..Default::default()
        },
    );
    node.src_ifindex = SRC_IFINDEX;
    node
}

fn port_meta6() -> PortMeta {
    PortMeta {
        guest_ipv6: SRC6,
        ..port_meta()
    }
}

#[test]
fn v6_a_flow_the_destination_allows_is_delivered() {
    let mut n = node6();
    n.maps.add_fw_rule6(
        DST_TAP,
        FwRule6 {
            src_port_max: 65535,
            dst_port_max: 65535,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            action: FW_ACTION_ACCEPT,
            enabled: 1,
            ..Default::default()
        },
    );
    for syn in [true, false] {
        assert_eq!(
            n.guest_tx_v6(&frame6(syn), &port_meta6()).action,
            Action::Redirect(DST_TAP)
        );
    }
}

#[test]
fn v6_a_flow_the_destination_denies_stays_denied() {
    let mut n = node6();
    assert_eq!(
        n.guest_tx_v6(&frame6(true), &port_meta6()).action,
        Action::Drop,
        "first packet"
    );
    assert_eq!(
        n.guest_tx_v6(&frame6(false), &port_meta6()).action,
        Action::Drop,
        "second packet of the same flow slipped past the destination's ingress firewall"
    );
}
