use crate::{MemMaps, VecPkt};
use flowplane_common::CtKey6;
use flowplane_core::conntrack::{ct_create_default6, ct_key6, invert_key6};
use flowplane_core::maps::Maps;

/// Minimal IPv6 + TCP packet: 40-byte v6 header (src @ +8, dst @ +24, next-header @ +6) followed
/// by a 20-byte TCP header (ports @ +40).
fn v6_tcp(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16) -> Vec<u8> {
    let mut b = vec![0u8; 40 + 20];
    b[8..24].copy_from_slice(&src);
    b[24..40].copy_from_slice(&dst);
    b[6] = 6; // next header = TCP
    b[40..42].copy_from_slice(&sport.to_be_bytes());
    b[42..44].copy_from_slice(&dport.to_be_bytes());
    b
}

#[test]
fn ct_create_default6_seeds_forward_and_reverse() {
    let src = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let pkt = VecPkt::from_bytes(&v6_tcp(src, dst, 1111, 80));
    let mut m = MemMaps::default();
    ct_create_default6(&pkt, &mut m, 0, 100, 5);
    let fwd = ct_key6(&pkt, 0, 100).unwrap();
    assert!(m.conntrack6_get(&fwd).is_some(), "forward entry seeded");
    assert!(
        m.conntrack6_get(&invert_key6(&fwd)).is_some(),
        "reverse pre-seeded"
    );
    // invert twice == original
    assert_eq!(invert_key6(&invert_key6(&fwd)), fwd);
}

#[test]
fn ct_key6_reads_v6_5tuple() {
    let src = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa];
    let dst = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xb];
    let pkt = VecPkt::from_bytes(&v6_tcp(src, dst, 4000, 443));
    let k = ct_key6(&pkt, 0, 42).unwrap();
    assert_eq!(k.vni, 42);
    assert_eq!(k.src_ip, src);
    assert_eq!(k.dst_ip, dst);
    assert_eq!(k.src_port, 4000);
    assert_eq!(k.dst_port, 443);
    assert_eq!(k.proto, 6);
    assert_eq!(
        invert_key6(&k),
        CtKey6 {
            vni: 42,
            src_ip: dst,
            dst_ip: src,
            src_port: 443,
            dst_port: 4000,
            proto: 6,
            _pad: [0; 3],
        }
    );
}
