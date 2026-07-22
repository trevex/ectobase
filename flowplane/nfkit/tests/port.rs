// Configure net_null with 1 queue, rx empty, and verify tx ownership transfer:
// sent mbufs are freed by DPDK exactly once (no leak, no double free). --test-threads=1.
//
// NOTE: net_null always generates synthetic rx packets (nb_bufs on every rx call), so the rx
// burst is drained after the call; the critical assertion is the avail_count round-trip on tx.
use nfkit::{Eal, MbufBurst, Mempool, Port};

#[test]
fn port_configures_and_tx_transfers_ownership() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--vdev",
        "net_null0",
        "--file-prefix",
        "nfkit_port",
    ])
    .expect("EAL init");
    let pool = Mempool::new("p", 1023, 250, 0).expect("pool");
    let port = Port::configure(0, 1, &pool).expect("configure port 0");
    let (mut rx, mut tx) = port.queue(0);

    // net_null generates synthetic mbufs on every rx call; drain them so the pool stabilises
    // before we measure avail_before. Any returned count is acceptable.
    let mut burst = MbufBurst::new();
    let _n = rx.rx(&mut burst);
    drop(burst); // free any synthetic mbufs back to pool

    let avail_before = pool.avail_count();
    let mut burst = MbufBurst::new();
    for _ in 0..4 {
        let mut m = pool.alloc().unwrap();
        m.append(64).unwrap();
        burst.push(m);
    }
    let sent = tx.tx(&mut burst);
    assert_eq!(sent, 4, "net_null accepts all");
    assert!(burst.is_empty(), "sent mbufs removed from the burst");
    assert_eq!(
        pool.avail_count(),
        avail_before,
        "sent mbufs freed exactly once by DPDK"
    );
}
