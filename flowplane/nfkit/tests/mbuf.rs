// Mbuf data + head/tail ops over a real DPDK mbuf. ONE test (single Eal::init). --test-threads=1.
use nfkit::{Eal, Mempool};

#[test]
fn mbuf_ops() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_mbuf",
    ])
    .expect("EAL init");
    let pool = Mempool::new("mb", 1023, 250, 0).expect("pool");
    let mut m = pool.alloc().expect("alloc");
    assert_eq!(m.len(), 0, "fresh mbuf is empty");

    let tail = m.append(4).expect("append");
    tail.copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(m.len(), 4);
    assert_eq!(m.data(), &[1, 2, 3, 4]);

    let head = m.prepend(2).expect("prepend");
    head.copy_from_slice(&[0xaa, 0xbb]);
    assert_eq!(m.data(), &[0xaa, 0xbb, 1, 2, 3, 4]);

    m.adjust(2).expect("adjust");
    m.trim(1).expect("trim");
    assert_eq!(m.data(), &[1, 2, 3]);

    // beyond headroom must error, not corrupt: default headroom is 128; 5000 must fail.
    assert!(m.prepend(5000).is_err());
}
