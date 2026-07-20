//! Tests for the outer IPv6 flow-label entropy helpers (RFC 6437/6438 fabric ECMP).
use crate::{SimNode, VecPkt};
use etherparse::PacketBuilder;
use flowplane_common::{
    FwMeta, FwRule, Local, PortMeta, RouteValue, FW_ACTION_ACCEPT, FW_DIR_EGRESS,
};
use flowplane_core::encap::ETH_LEN;
use flowplane_core::parse::{flow_label20, hash5, hash_v6, inner_flow_label};
use flowplane_core::pkt::Action;

#[test]
fn flow_label20_stays_within_20_bits() {
    // Any 32-bit hash folds into the low 20 bits; the top 12 bits must be clear
    // (they overlap the IPv6 version/traffic-class nibble and must not be set).
    assert_eq!(flow_label20(0xFFFF_FFFF) & 0xFFF0_0000, 0);
    assert_eq!(flow_label20(0x1234_5678) & 0xFFF0_0000, 0);
    assert_eq!(flow_label20(0) & 0xFFF0_0000, 0);
}

#[test]
fn flow_label20_folds_high_bits_in() {
    // Fold is (h ^ (h >> 20)) & 0xFFFFF, so bits above 20 influence the label
    // (otherwise high-entropy hashes would collide on their low 20 bits).
    let a = flow_label20(0x0000_0001);
    let b = flow_label20(0x0010_0001); // differs only in bit 20 -> XORs into bit 0
    assert_ne!(a, b);
}

#[test]
fn hash_v6_is_deterministic_and_flow_sensitive() {
    let s = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let d = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let h = hash_v6(&s, &d, 1000, 80, 6);
    assert_eq!(h, hash_v6(&s, &d, 1000, 80, 6)); // deterministic
    assert_ne!(h, hash_v6(&s, &d, 1001, 80, 6)); // different sport -> different hash
    assert_ne!(h, hash_v6(&d, &s, 1000, 80, 6)); // swapped addrs -> different hash
}

#[test]
fn inner_flow_label_v4_matches_hash5_fold() {
    // [eth(14)][inner IPv4(20)][TCP ports] — the helper must hash the inner 5-tuple.
    let mut b = vec![0u8; ETH_LEN + 24];
    b[ETH_LEN] = 0x45; // version 4, IHL 5
    b[ETH_LEN + 9] = 6; // proto = TCP
    b[ETH_LEN + 12..ETH_LEN + 16].copy_from_slice(&[10, 0, 0, 1]); // src
    b[ETH_LEN + 16..ETH_LEN + 20].copy_from_slice(&[10, 0, 0, 2]); // dst
    b[ETH_LEN + 20..ETH_LEN + 22].copy_from_slice(&1234u16.to_be_bytes()); // sport
    b[ETH_LEN + 22..ETH_LEN + 24].copy_from_slice(&80u16.to_be_bytes()); // dport
    let p = VecPkt::from_bytes(&b);
    let expect = flow_label20(hash5(&[10, 0, 0, 1], &[10, 0, 0, 2], 1234, 80, 6));
    assert_eq!(inner_flow_label(&p, ETH_LEN, false), expect);
    assert_eq!(inner_flow_label(&p, ETH_LEN, false) & 0xFFF0_0000, 0); // 20-bit
}

#[test]
fn inner_flow_label_v6_matches_hashv6_fold() {
    // [eth(14)][inner IPv6(40)][TCP ports].
    let src = [0x20u8, 1, 0, 0xa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20u8, 1, 0, 0xb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let mut b = vec![0u8; ETH_LEN + 44];
    b[ETH_LEN] = 0x60; // version 6
    b[ETH_LEN + 6] = 6; // next-header = TCP
    b[ETH_LEN + 8..ETH_LEN + 24].copy_from_slice(&src);
    b[ETH_LEN + 24..ETH_LEN + 40].copy_from_slice(&dst);
    b[ETH_LEN + 40..ETH_LEN + 42].copy_from_slice(&5000u16.to_be_bytes()); // sport
    b[ETH_LEN + 42..ETH_LEN + 44].copy_from_slice(&443u16.to_be_bytes()); // dport
    let p = VecPkt::from_bytes(&b);
    let expect = flow_label20(hash_v6(&src, &dst, 5000, 443, 6));
    assert_eq!(inner_flow_label(&p, ETH_LEN, true), expect);
}

// End-to-end: guest_tx must write the inner-flow hash into the encapped outer IPv6 flow label.
#[test]
fn guest_tx_encap_carries_inner_flow_label() {
    const IFINDEX: u32 = 10;
    const UPLINK_IFINDEX: u32 = 7;
    const VNI: u32 = 100;
    let guest_ip = [10, 0, 2, 20];
    let dest_ip = [10, 1, 1, 1];
    let nexthop = [0x20u8, 1, 0xd, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    let mut node = SimNode::new();
    node.src_ifindex = IFINDEX;
    node.maps.local = Some(Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    });
    // is_external:0 + no local underlay entry for nexthop → deliver returns Encap, no NAT rewrite,
    // so the label is computed from the unchanged inner 5-tuple.
    node.maps.add_route4(
        VNI,
        dest_ip,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: nexthop,
            is_external: 0,
            _pad: [0; 3],
        },
    );
    node.maps.fw_meta.insert(
        IFINDEX,
        FwMeta {
            ingress_count: 0,
            egress_count: 1,
        },
    );
    node.maps.fw_rules.insert(
        (IFINDEX, 0),
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
            direction: FW_DIR_EGRESS,
            enabled: 1,
        },
    );

    let meta = PortMeta {
        vni: VNI,
        guest_ipv4: guest_ip,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: [0xaa; 6],
        _pad: [0; 2],
        underlay_ipv6: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    };
    let mut frame = Vec::new();
    PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
        .ipv4(guest_ip, dest_ip, 64)
        .udp(12345, 53)
        .write(&mut frame, &[])
        .unwrap();

    let out = node.guest_tx(&frame, &meta);
    assert!(
        matches!(out.action, Action::Redirect(UPLINK_IFINDEX)),
        "expected encap redirect, got {:?}",
        out.action
    );
    // Outer IPv6 first word is at offset ETH_LEN. Version must be 6, flow label must equal the
    // inner-flow hash (UDP 12345->53, proto 17), unchanged by NAT.
    let w = u32::from_be_bytes([
        out.pkt[ETH_LEN],
        out.pkt[ETH_LEN + 1],
        out.pkt[ETH_LEN + 2],
        out.pkt[ETH_LEN + 3],
    ]);
    let expected = flow_label20(hash5(&guest_ip, &dest_ip, 12345, 53, 17));
    assert_eq!(w >> 28, 6, "outer IPv6 version must stay 6");
    assert_ne!(expected, 0, "test flow should hash to a non-zero label");
    assert_eq!(
        w & 0xFFFFF,
        expected,
        "outer flow label must be the inner-flow hash"
    );
}
