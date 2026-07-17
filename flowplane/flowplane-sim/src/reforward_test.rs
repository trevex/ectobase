use crate::VecPkt;
use flowplane_common::Local;
use flowplane_core::encap::{reforward, ETH_LEN};
use flowplane_core::pkt::Action;

#[test]
fn reforward_rewrites_outer_to_backend() {
    let mut p = VecPkt::from_bytes(&[0u8; ETH_LEN + 40 + 40]); // eth + outer v6 + inner placeholder
    let local = Local {
        uplink_ifindex: 9,
        uplink_mac: [2; 6],
        gateway_mac: [1; 6],
        underlay_ipv6: [0; 16],
    };
    let lb_ul = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
    let backend = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
    assert_eq!(
        reforward(&mut p, &local, &lb_ul, &backend),
        Action::Redirect(9)
    );
    assert_eq!(&p.bytes()[0..6], &[1u8; 6]);
    assert_eq!(&p.bytes()[6..12], &[2u8; 6]);
    assert_eq!(&p.bytes()[ETH_LEN + 8..ETH_LEN + 24], &lb_ul);
    assert_eq!(&p.bytes()[ETH_LEN + 24..ETH_LEN + 40], &backend);
}
