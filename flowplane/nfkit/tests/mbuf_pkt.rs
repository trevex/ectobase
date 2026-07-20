use flowplane_core::pkt::Pkt;
use nfkit::{Eal, MbufPkt, Mempool};

#[test]
fn mbufpkt_matches_vecpkt_ops() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_mp3",
    ])
    .expect("EAL init");
    let pool = Mempool::new("mp3", 1023, 250, 0).expect("pool");
    let mut mb = pool.alloc().expect("alloc");
    let tail = mb.append(8).unwrap();
    tail.copy_from_slice(&[10, 11, 12, 13, 14, 15, 16, 17]);
    let mut p = MbufPkt::new(&mut mb);

    assert_eq!(p.len(), 8);
    assert_eq!(p.read_array::<4>(2), Some([12, 13, 14, 15]));
    assert!(p.write_bytes(0, &[0xaa, 0xbb]));
    assert_eq!(p.read_array::<2>(0), Some([0xaa, 0xbb]));
    assert!(p.grow_head(2));
    assert!(p.write_bytes(0, &[1, 2]));
    assert_eq!(p.len(), 10);
    assert_eq!(p.read_array::<4>(0), Some([1, 2, 0xaa, 0xbb]));
    assert!(p.shrink_head(2));
    assert_eq!(p.len(), 8);
    assert_eq!(p.read_array::<2>(0), Some([0xaa, 0xbb]));
    assert_eq!(p.read_array::<4>(4), Some([14, 15, 16, 17]));
    assert_eq!(p.read_array::<4>(7), None);
    assert!(!p.write_bytes(7, &[1, 2, 3, 4]));

    // set_tail parity vs VecPkt: grow zero-fills, shrink truncates, equal is a no-op.
    // Build a fresh 8-byte mbuf + a matching VecPkt, then resize both identically.
    let mut mb2 = pool.alloc().expect("alloc2");
    let tail2 = mb2.append(8).unwrap();
    tail2.copy_from_slice(&[10, 11, 12, 13, 14, 15, 16, 17]);
    let mut p2 = MbufPkt::new(&mut mb2);
    let mut vp = flowplane_sim::VecPkt::from_bytes(&[10, 11, 12, 13, 14, 15, 16, 17]);
    // grow to 16: new tail must be zero on BOTH.
    assert!(p2.set_tail(16));
    assert!(vp.set_tail(16));
    assert_eq!(p2.len(), 16);
    let mut got = [0u8; 16];
    for (i, b) in got.iter_mut().enumerate() {
        *b = p2.read_array::<1>(i).unwrap()[0];
    }
    assert_eq!(&got[..8], &[10, 11, 12, 13, 14, 15, 16, 17]);
    assert_eq!(
        &got[8..],
        &[0u8; 8],
        "grown tail is zero-filled (matches VecPkt)"
    );
    assert_eq!(got.to_vec(), vp.into_bytes());
    // shrink to 4.
    assert!(p2.set_tail(4));
    assert_eq!(p2.len(), 4);
    assert_eq!(p2.read_array::<4>(0), Some([10, 11, 12, 13]));
}
