//! EdtPacer: out-of-order enqueue releases in departure order; not-yet-due mbufs stay queued; FIFO
//! among equal edt; empty/next_departure. Synthetic `now` — no real clock. Run --test-threads=1.
//!
//! EAL init is process-global/single-shot, so ALL assertions live in ONE `#[test]` to avoid a
//! double-init panic. This one test exercises: out-of-order → departure-order release, not-due
//! stays queued, FIFO among equal edt, and empty/next_departure.
use nfkit::{Eal, EdtPacer, Mempool};

// tag each mbuf with a 1-byte id so we can assert WHICH mbuf was released.
fn tagged(pool: &Mempool, id: u8) -> nfkit::Mbuf {
    let mut mb = pool.alloc().expect("alloc");
    mb.append(1).expect("append");
    mb.data_mut()[0] = id;
    mb
}
fn id_of(mb: &nfkit::Mbuf) -> u8 {
    mb.data()[0]
}

#[test]
fn pacer_releases_in_departure_order_and_fifo() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_edt",
    ])
    .expect("EAL");
    let pool = Mempool::new("edt_pool", 1023, 250, 0).expect("pool");

    // --- out-of-order enqueue → departure-order release, not-due, empty ---
    let mut p = EdtPacer::new();
    // enqueue OUT of order: edt 300(id=3), 100(id=1), 200(id=2)
    p.enqueue(tagged(&pool, 3), 300);
    p.enqueue(tagged(&pool, 1), 100);
    p.enqueue(tagged(&pool, 2), 200);
    assert_eq!(p.len(), 3);
    assert_eq!(p.next_departure(), Some(100));
    // nothing due before 100
    assert!(p.drain_due(99).is_empty());
    // now=150 → only id=1 (edt 100)
    let due = p.drain_due(150);
    assert_eq!(due.iter().map(id_of).collect::<Vec<_>>(), vec![1]);
    // now=300 → id=2 then id=3, in departure order
    let due = p.drain_due(300);
    assert_eq!(due.iter().map(id_of).collect::<Vec<_>>(), vec![2, 3]);
    assert!(p.is_empty());
    assert_eq!(p.next_departure(), None);

    // --- FIFO among equal edt: ids 10 then 11 at edt 100 → released [10, 11] ---
    let mut q = EdtPacer::new();
    q.enqueue(tagged(&pool, 10), 100);
    q.enqueue(tagged(&pool, 11), 100);
    assert_eq!(q.len(), 2);
    let due = q.drain_due(100);
    assert_eq!(due.iter().map(id_of).collect::<Vec<_>>(), vec![10, 11]);
    assert!(q.is_empty());
    assert_eq!(q.next_departure(), None);
}
