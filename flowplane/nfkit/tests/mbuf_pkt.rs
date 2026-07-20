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
}
