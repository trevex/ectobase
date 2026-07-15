use crate::VecPkt;
use xdp_dp_core::encap::{write_outer_v6, EncapParams, ETH_LEN, IPV6_LEN};
use xdp_dp_core::pkt::Pkt;

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
        inner_len: 34,
        inner_proto: 4,
    };
    assert!(write_outer_v6(&mut p, &e));
    assert_eq!(p.read_array::<6>(0), Some(e.gateway_mac)); // outer eth dst
    assert_eq!(p.read_array::<6>(6), Some(e.uplink_mac)); // outer eth src
    assert_eq!(p.read_u16_be(12), Some(0x86DD));
    assert_eq!(p.read_u8(ETH_LEN), Some(0x60));
    assert_eq!(p.read_u16_be(ETH_LEN + 4), Some(34));
    assert_eq!(p.read_array::<2>(ETH_LEN + 6), Some([4, 64]));
    assert_eq!(p.read_array::<16>(ETH_LEN + 8), Some(e.src_underlay));
    assert_eq!(p.read_array::<16>(ETH_LEN + 24), Some(e.nexthop_ipv6));
}
