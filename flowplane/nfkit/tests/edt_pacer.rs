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

    // --- large-N ordering stress: ~100 mbufs enqueued in SHUFFLED edt order, all due at once ---
    // Deterministic shuffle (no RNG): a coprime step (37) over the ring of 100 permutes 0..100 so
    // consecutive enqueues have non-monotonic edts. Each mbuf's edt = (id+1)*10 (distinct, id-derivable
    // so we can recover the expected edt from the released tag). After drain_due(u64::MAX) — every mbuf
    // due — the released order must be by non-decreasing edt (i.e. released ids strictly ascending),
    // proving departure ordering holds at scale for an all-due-at-once batch.
    const N: u64 = 100;
    let edt_of_id = |id: u8| (id as u64 + 1) * 10;
    let mut r = EdtPacer::new();
    let mut idx: u64 = 0;
    for _ in 0..N {
        idx = (idx + 37) % N; // coprime step → visits every 0..N exactly once, out of order
        let id = idx as u8;
        r.enqueue(tagged(&pool, id), edt_of_id(id));
    }
    assert_eq!(r.len() as u64, N);
    let released = r.drain_due(u64::MAX);
    assert_eq!(released.len() as u64, N, "all mbufs due at once");
    let edts: Vec<u64> = released.iter().map(|mb| edt_of_id(id_of(mb))).collect();
    assert!(
        edts.windows(2).all(|w| w[0] <= w[1]),
        "released in non-decreasing edt order at scale: {edts:?}"
    );
    assert!(r.is_empty());
    assert_eq!(r.next_departure(), None);
}
