use crate::firewall_test::tcp_v4;
use crate::{MemMaps, VecPkt};
use etherparse::PacketBuilder;
use xdp_dp_common::{LbKey, LbValue, MaglevKey};
use xdp_dp_core::lb::{lb_select_forward, lb_select_forward_v6};

fn tcp_v6(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ipv6(src, dst, 64).tcp(sport, dport, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

#[test]
fn lb_select_returns_maglev_backend() {
    let vni = 100u32;
    let vip = [10, 0, 100, 1];
    let backend_ul = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
    let mut m = MemMaps::default();
    m.lb.insert(
        LbKey {
            vni,
            ipv4: vip,
            port: 443,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 1,
            size: 1,
        },
    );
    m.maglev.insert(
        MaglevKey {
            table_id: 1,
            slot: 0,
        },
        backend_ul,
    ); // size 1 => slot 0 always

    let pkt = VecPkt::from_bytes(&tcp_v4([203, 0, 113, 9], vip, 5000, 443));
    assert_eq!(lb_select_forward(&pkt, &m, 0, vni), Some(backend_ul));
    let pkt2 = VecPkt::from_bytes(&tcp_v4([203, 0, 113, 9], [10, 0, 0, 5], 5000, 443));
    assert_eq!(lb_select_forward(&pkt2, &m, 0, vni), None);
}

#[test]
fn lb_select_v6_returns_maglev_backend() {
    let vni = 100u32;
    // VIP with last-4 bytes = the LB key ipv4 (matching the control-plane `last4`).
    let vip6 = [0x20u8, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 100, 1];
    let vip4 = [10, 0, 100, 1];
    let src6 = [0x20u8, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9];
    let backend_ul = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
    let mut m = MemMaps::default();
    m.lb.insert(
        LbKey {
            vni,
            ipv4: vip4,
            port: 443,
            proto: 6,
            _pad: 0,
        },
        LbValue {
            table_id: 1,
            size: 1,
        },
    );
    m.maglev.insert(
        MaglevKey {
            table_id: 1,
            slot: 0,
        },
        backend_ul,
    ); // size 1 => slot 0 always

    // ip_off = 0: PacketBuilder::ipv6 emits starting at the IPv6 header (no Ethernet).
    let pkt = VecPkt::from_bytes(&tcp_v6(src6, vip6, 5000, 443));
    assert_eq!(lb_select_forward_v6(&pkt, &m, 0, vni), Some(backend_ul));

    // Non-LB dst (last-4 != VIP key) => None.
    let other = [0x20u8, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 5];
    let pkt2 = VecPkt::from_bytes(&tcp_v6(src6, other, 5000, 443));
    assert_eq!(lb_select_forward_v6(&pkt2, &m, 0, vni), None);
}
