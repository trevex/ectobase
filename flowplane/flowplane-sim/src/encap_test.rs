//! Sim oracle: the v4 guest-egress overlay decision. Drives the REAL `SimNode::guest_tx` (the
//! production `flowplane_core::datapath::process_guest_tx` compose) and asserts the emitted
//! `TunnelEncap{vni, remote}` decision — NOT outer bytes: under Geneve `collect_md` the kernel
//! builds the outer Eth/IPv6/UDP/Geneve header via `bpf_skb_set_tunnel_key`, so the datapath itself
//! never touches the wire bytes on encap. The inner frame must be byte-for-byte unchanged.

use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, PortMeta, RouteValue, FW_ACTION_ACCEPT, FW_DIR_EGRESS, FW_DIR_INGRESS,
};
use flowplane_core::encap::TunnelEncap;
use flowplane_core::pkt::Action;

use crate::SimNode;

const VNI: u32 = 100;
const SRC_IFINDEX: u32 = 10;
const UPLINK_IFINDEX: u32 = 7;
const GUEST_IP: [u8; 4] = [10, 0, 0, 42];
const EXT_IP: [u8; 4] = [203, 0, 113, 9];
const NEXTHOP_UNDERLAY: [u8; 16] = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];
const SELF_UNDERLAY: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// Deliberately DIFFERENT from `VNI` (the sender's own vni) so the tunnel-decision assertion proves
/// the wire vni comes from the matched ROUTE (`RouteValue::nexthop_vni`), not the sender's own vni.
const ROUTE_VNI: u32 = 900;

fn local() -> flowplane_common::Local {
    flowplane_common::Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [2; 6],
        gateway_mac: [3; 6],
        underlay_ipv6: SELF_UNDERLAY,
    }
}

fn port_meta() -> PortMeta {
    PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: [0xaa; 6],
        l3: 0,
        _pad: [0; 1],
        underlay_ipv6: SELF_UNDERLAY,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    }
}

/// `[Eth][IPv4][TCP]` guest frame GUEST_IP -> EXT_IP.
fn frame() -> Vec<u8> {
    let b = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
        .ipv4(GUEST_IP, EXT_IP, 64)
        .tcp(40000, 80, 0, 1024);
    let mut out = Vec::new();
    b.write(&mut out, &[1, 2, 3, 4]).unwrap();
    out
}

/// Install a wildcard ALLOW rule for `dir` on `ifindex`.
fn allow(node: &mut SimNode, ifindex: u32, dir: u8) {
    let meta = node.maps.fw_meta.entry(ifindex).or_insert(FwMeta {
        ingress_count: 0,
        egress_count: 0,
    });
    let idx = if dir == FW_DIR_EGRESS {
        meta.egress_count += 1;
        meta.egress_count - 1
    } else {
        meta.ingress_count += 1;
        meta.ingress_count - 1
    };
    node.maps.fw_rules.insert(
        (ifindex, idx),
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
            direction: dir,
            enabled: 1,
        },
    );
}

/// A node wired so `guest_tx` GUEST_IP->EXT_IP takes the encap arm: external route, no
/// `UNDERLAY[nexthop]` entry (so `deliver` falls through to `Deliver::Encap`).
fn encap_node() -> SimNode {
    let mut node = SimNode::with_local(local());
    node.maps.local = Some(local());
    node.src_ifindex = SRC_IFINDEX;
    node.maps.add_route4(
        VNI,
        EXT_IP,
        RouteValue {
            nexthop_vni: ROUTE_VNI,
            nexthop_ipv6: NEXTHOP_UNDERLAY,
            is_external: 1,
            _pad: [0; 3],
        },
    );
    allow(&mut node, SRC_IFINDEX, FW_DIR_EGRESS);
    node
}

#[test]
fn guest_tx_v4_emits_tunnel_encap_and_leaves_inner_bytes_unchanged() {
    let mut node = encap_node();
    let f = frame();
    let out = node.guest_tx(&f, &port_meta());

    assert_eq!(
        out.action,
        Action::Redirect(UPLINK_IFINDEX),
        "encap redirects out the uplink"
    );
    assert_eq!(
        out.tunnel,
        Some(TunnelEncap {
            vni: ROUTE_VNI,
            remote: NEXTHOP_UNDERLAY
        }),
        "tunnel decision carries the ROUTE's vni + nexthop underlay"
    );
    assert_eq!(
        out.pkt, f,
        "no NAT in play: inner frame is byte-for-byte unchanged (no outer bytes written)"
    );
}

/// Coverage: the "local delivery, not encap" case (`UNDERLAY[nexthop].tap_ifindex != 0` ->
/// `Deliver::Local`) must emit NO tunnel decision.
#[test]
fn guest_tx_v4_local_delivery_emits_no_tunnel_decision() {
    const PEER_TAP: u32 = 55;
    const PEER_UNDERLAY: [u8; 16] = [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

    let mut node = SimNode::new();
    node.src_ifindex = SRC_IFINDEX;
    // Local delivery is now demuxed by (vni, overlay dst) via INTERFACES. The egress route lookup
    // still needs an internal ROUTES entry for the packet to reach the deliver stage (miss = Pass).
    node.maps.add_route4(
        VNI,
        EXT_IP,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: PEER_UNDERLAY,
            is_external: 0,
            _pad: [0; 3],
        },
    );
    node.maps.add_iface(
        VNI,
        EXT_IP,
        flowplane_common::IfaceValue {
            tap_ifindex: PEER_TAP,
            is_local: 1,
            underlay_ipv6: [0; 16],
            guest_mac: [0xcc; 6],
            _pad: [0; 2],
        },
    );
    allow(&mut node, SRC_IFINDEX, FW_DIR_EGRESS);
    allow(&mut node, PEER_TAP, FW_DIR_INGRESS);

    let out = node.guest_tx(&frame(), &port_meta());
    assert_eq!(out.action, Action::Redirect(PEER_TAP));
    assert_eq!(out.tunnel, None, "local delivery emits no tunnel decision");
}
