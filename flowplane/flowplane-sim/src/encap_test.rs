use crate::VecPkt;
use flowplane_core::encap::{write_outer_v6, EncapParams, ETH_LEN, IPV6_LEN};
use flowplane_core::pkt::Pkt;

#[test]
fn encap_writes_outer_v6_header() {
    let mut p = VecPkt::from_bytes(&[0u8; 34]);
    assert!(p.grow_head(IPV6_LEN));
    let e = EncapParams {
        gateway_mac: [1, 1, 1, 1, 1, 1],
        uplink_mac: [2, 2, 2, 2, 2, 2],
        uplink_ifindex: 7,
        src_underlay: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa],
        nexthop_ipv6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb],
        inner_proto: 4,
        flow_label: 0,
    };
    assert!(write_outer_v6(&mut p, &e));
    assert_eq!(p.read_array::<6>(0), Some(e.gateway_mac)); // outer eth dst
    assert_eq!(p.read_array::<6>(6), Some(e.uplink_mac)); // outer eth src
    assert_eq!(p.read_u16_be(12), Some(0x86DD));
    assert_eq!(p.read_u8(ETH_LEN), Some(0x60));
    // write_outer_v6 derives payload_length from logical_len, not the (ignored) inner_len
    // field. grow_head(IPV6_LEN) made logical_len = 34 + 40 = 74, so the encapsulated inner
    // length is 74 - ETH_LEN - IPV6_LEN = 20.
    assert_eq!(p.read_u16_be(ETH_LEN + 4), Some(20));
    assert_eq!(p.read_array::<2>(ETH_LEN + 6), Some([4, 64]));
    assert_eq!(p.read_array::<16>(ETH_LEN + 8), Some(e.src_underlay));
    assert_eq!(p.read_array::<16>(ETH_LEN + 24), Some(e.nexthop_ipv6));
}

#[test]
fn encap_inner_len_uses_logical_not_linear() {
    // Simulate a non-linear skb: the linear head holds only the outer header room, but the
    // true (logical) frame is much larger with the inner payload in a "paged" region.
    // write_outer_v6 must derive the outer payload_length from logical_len, not buf.len().
    let mut p = VecPkt::from_bytes(&[0u8; ETH_LEN + IPV6_LEN]); // 54-byte linear head only
    p.set_logical_len(ETH_LEN + IPV6_LEN + 1400); // 1400-byte inner in the "frags"
    let e = EncapParams {
        gateway_mac: [1, 1, 1, 1, 1, 1],
        uplink_mac: [2, 2, 2, 2, 2, 2],
        uplink_ifindex: 7,
        src_underlay: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa],
        nexthop_ipv6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb],
        inner_proto: 4,
        flow_label: 0,
    };
    assert!(write_outer_v6(&mut p, &e));
    // outer IPv6 payload_length == logical_len - ETH_LEN - IPV6_LEN == 1400, NOT
    // buf.len() - ETH_LEN - IPV6_LEN == 0.
    assert_eq!(p.read_u16_be(ETH_LEN + 4), Some(1400));
}

#[test]
fn encap_writes_flow_label_into_outer_v6() {
    let mut p = VecPkt::from_bytes(&[0u8; 34]);
    assert!(p.grow_head(IPV6_LEN));
    let e = EncapParams {
        gateway_mac: [1, 1, 1, 1, 1, 1],
        uplink_mac: [2, 2, 2, 2, 2, 2],
        uplink_ifindex: 7,
        src_underlay: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa],
        nexthop_ipv6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb],
        inner_proto: 4,
        flow_label: 0x0FF_ABCDE, // bits above 20 must be masked off by the writer
    };
    assert!(write_outer_v6(&mut p, &e));
    // IPv6 first word = version(6) | traffic-class(0) | flow-label(0xABCDE).
    assert_eq!(p.read_u8(ETH_LEN), Some(0x60)); // version=6, tc hi nibble=0
    assert_eq!(p.read_u8(ETH_LEN + 1), Some(0x0A)); // tc lo nibble=0, label[19:16]=0xA
    assert_eq!(p.read_u8(ETH_LEN + 2), Some(0xBC)); // label[15:8]
    assert_eq!(p.read_u8(ETH_LEN + 3), Some(0xDE)); // label[7:0]
}
