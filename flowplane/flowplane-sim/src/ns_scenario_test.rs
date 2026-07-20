//! Full North-South walking-skeleton scenario, end to end through the REAL datapath core:
//! external packet -> edge encap -> host uplink decap + ingress firewall + conntrack -> guest.
//! Every processing step is a real `flowplane_core` fn (via `SimNode`); nothing is reimplemented here.

use etherparse::PacketBuilder;
use flowplane_common::{FwMeta, FwRule, FW_ACTION_ACCEPT, FW_DIR_INGRESS};
use flowplane_core::conntrack::ct_key;
use flowplane_core::encap::{EncapParams, ETH_LEN, IPV6_LEN};
use flowplane_core::maps::Maps;
use flowplane_core::pkt::Action;
use flowplane_core::uplink::GW_MAC;

use crate::{SimNode, VecPkt};

const VNI: u32 = 100;
const TAP: u32 = 42;
const GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x00];
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];
const EXT_IP: [u8; 4] = [203, 0, 113, 9];
const EDGE_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
const HOST_UNDERLAY: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];

/// A full guest Ethernet frame `[Eth][IPv4][TCP]` (the tunnel payload before the inner Eth is
/// consumed on encap), from `EXT_IP` -> `GUEST_IP` on `dport`.
fn inner_eth_frame(dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x11; 6], [0x22; 6])
        .ipv4(EXT_IP, GUEST_IP, 64)
        .tcp(40000, dport, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

fn encap_params() -> EncapParams {
    EncapParams {
        gateway_mac: [1; 6],
        uplink_mac: [2; 6],
        uplink_ifindex: 7,
        src_underlay: EDGE_UNDERLAY,
        nexthop_ipv6: HOST_UNDERLAY,
        inner_proto: 4, // IPPROTO_IPIP
        flow_label: 0,
    }
}

/// Install an ingress ALLOW rule on `tap` for TCP -> GUEST_IP:port.
fn allow_tcp(node: &mut SimNode, port: u16) {
    node.maps.fw_meta.insert(
        TAP,
        FwMeta {
            ingress_count: 1,
            egress_count: 0,
        },
    );
    node.maps.fw_rules.insert(
        (TAP, 0),
        FwRule {
            src_ip: [0; 4],
            src_mask: [0; 4],
            dst_ip: GUEST_IP,
            dst_mask: [255, 255, 255, 255],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: port,
            dst_port_max: port,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 6,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        },
    );
}

#[test]
fn external_to_guest_encap_decap_fw_allow_ct() {
    let inner = inner_eth_frame(443);

    // Edge encapsulates toward the host underlay.
    let edge = SimNode::new();
    let encapped = edge.edge_encap(&inner, encap_params());
    // Outer IPv6 dst (at ETH_LEN + 24) is the host underlay.
    assert_eq!(&encapped[ETH_LEN + 24..ETH_LEN + 40], &HOST_UNDERLAY);

    // Host runs the real uplink base path: ingress FW allow (new flow) + CT create + decap+rewrite.
    let mut host = SimNode::new();
    allow_tcp(&mut host, 443);
    let out = host.host_uplink(&encapped, VNI, TAP, GUEST_MAC);

    assert_eq!(
        out.action,
        Action::Redirect(TAP),
        "delivered to the guest tap"
    );
    assert_eq!(&out.pkt[0..6], &GUEST_MAC, "inner eth dst = guest MAC");
    assert_eq!(&out.pkt[6..12], &GW_MAC, "inner eth src = gateway MAC");
    assert_eq!(&out.pkt[12..14], &[0x08, 0x00], "inner ethertype = IPv4");
    assert_eq!(
        out.pkt.len(),
        inner.len(),
        "outer Eth+IPv6 stripped, inner Eth restored"
    );
    // A new flow seeds the forward key (and a reverse key). Assert the forward entry exists.
    let fwd_key = ct_key(&VecPkt::from_bytes(&encapped), ETH_LEN + IPV6_LEN, VNI).unwrap();
    assert!(
        host.maps.conntrack_get(&fwd_key).is_some(),
        "forward conntrack entry created"
    );
}

#[test]
fn external_to_guest_firewall_drop_on_unopened_port() {
    // Allow only :443, but the flow targets :80 -> ingress firewall drops the new flow.
    let inner = inner_eth_frame(80);
    let edge = SimNode::new();
    let encapped = edge.edge_encap(&inner, encap_params());

    let mut host = SimNode::new();
    allow_tcp(&mut host, 443);
    let out = host.host_uplink(&encapped, VNI, TAP, GUEST_MAC);

    assert_eq!(
        out.action,
        Action::Drop,
        "unopened port dropped by ingress firewall"
    );
    assert_eq!(
        host.maps.conntrack.len(),
        0,
        "dropped flow leaves no conntrack entry"
    );
}
