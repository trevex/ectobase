use crate::firewall_test::tcp_v4;
use crate::{MemMaps, VecPkt};
use xdp_dp_common::{LbKey, LbValue, MaglevKey};
use xdp_dp_core::lb::lb_select_forward;

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
