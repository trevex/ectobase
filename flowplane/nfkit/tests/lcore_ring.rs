//! LcoreRing = a DPDK rte_ring carrying Mbuf ownership between lcores (MP enqueue / SC dequeue).
//! Two cases, run --no-huge, -l 0-4 (4 workers), --test-threads=1:
//!  1. Concurrent multi-producer handoff: each of N worker lcores enqueues K uniquely-stamped mbufs
//!     into ONE ring; the main lcore (single consumer) drains all N*K, asserting every id is present
//!     exactly once and each stamp is intact (no torn ptr / wrong mbuf).
//!  2. Full-ring returns the mbuf (no leak): a count-2 ring (usable 1) accepts one enqueue, then the
//!     second comes back as Err(mbuf) — asserted usable and freed; pool accounting shows no net leak.
use nfkit::{Eal, LcoreRing, MbufBurst, Mempool};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

const N_WORKERS: u16 = 4;
const K: u32 = 512; // per worker; N_WORKERS*K = 2048 < 4095 (ring never fills in case 1)

/// Encode (queue, i) -> a globally-unique u32 id.
fn make_id(q: u16, i: u32) -> u32 {
    (u32::from(q) << 16) | i
}

#[test]
fn lcore_ring_handoff_and_full() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0-4",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_ring",
    ])
    .expect("EAL init");

    // ── Case 1: concurrent multi-producer handoff ────────────────────────────
    // Cache 0 so avail_count is exact (no per-lcore cache hiding buffers).
    let pool = Arc::new(Mempool::new("ringpool", 8191, 0, 0).expect("pool"));
    let ring = Arc::new(LcoreRing::new("handoff", 4096, 0).expect("ring")); // usable 4095

    let pool_w = Arc::clone(&pool);
    let ring_w = Arc::clone(&ring);
    let produced = AtomicU32::new(0);
    nfkit::LcoreRuntime::for_each_worker(N_WORKERS, |q| {
        for i in 0..K {
            // Alloc an mbuf and stamp a 4-byte marker id into its data.
            let mut m = loop {
                if let Some(m) = pool_w.alloc() {
                    break m;
                }
                std::hint::spin_loop(); // pool briefly drained by peers; retry
            };
            let id = make_id(q, i);
            m.append(4).expect("tailroom for id")[..4].copy_from_slice(&id.to_le_bytes());
            // MP enqueue; the ring is sized so it never fills, but spin on the (impossible here)
            // transient-full path to be safe — never drop/leak the mbuf.
            let mut m = m;
            loop {
                match ring_w.enqueue(m) {
                    Ok(()) => break,
                    Err(back) => {
                        m = back; // ring took nothing; we still own it — retry
                        std::hint::spin_loop();
                    }
                }
            }
            produced.fetch_add(1, Ordering::Relaxed);
        }
    });
    let total = N_WORKERS as u32 * K;
    assert_eq!(produced.load(Ordering::Relaxed), total, "all enqueued");

    // Main lcore = the single consumer: drain the whole ring, collecting every id.
    let mut seen = vec![0u8; total as usize];
    let mut dequeued = 0u32;
    loop {
        let mut burst = MbufBurst::new();
        let n = ring.dequeue_burst(&mut burst);
        if n == 0 {
            break;
        }
        assert_eq!(n, burst.len(), "dequeue_burst count matches pushed mbufs");
        for m in burst.drain(..) {
            let data = m.data();
            assert_eq!(data.len(), 4, "each mbuf carries exactly its 4-byte stamp");
            let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            // Decode (q,i) and range-check, then mark present-exactly-once.
            let q = (id >> 16) as u16;
            let i = id & 0xffff;
            assert!(q < N_WORKERS && i < K, "id {id} decodes to a valid (q,i)");
            let idx = (u32::from(q) * K + i) as usize;
            assert_eq!(seen[idx], 0, "id {id} dequeued more than once (torn/dup)");
            seen[idx] = 1;
            dequeued += 1;
            // m drops here → freed back to pool.
        }
    }
    assert_eq!(dequeued, total, "dequeued exactly N*K mbufs");
    assert!(seen.iter().all(|&s| s == 1), "no id missing");
    // Every mbuf returned to the pool → no leak across the whole handoff.
    assert_eq!(
        pool.avail_count(),
        8191,
        "all handoff mbufs freed (no leak, no double-count)"
    );
    drop(ring); // drained → nothing leaked at ring free

    // ── Case 2: full ring returns the mbuf (no leak) ─────────────────────────
    // count 2 → usable capacity 1. Cache 0 for exact accounting.
    let pool2 = Mempool::new("tinypool", 63, 0, 0).expect("pool2");
    let ring2 = LcoreRing::new("tiny", 2, 0).expect("tiny ring");
    let base = pool2.avail_count();

    let mut a = pool2.alloc().expect("alloc a");
    a.append(4).expect("tailroom")[..4].copy_from_slice(&0xAAAA_BBBBu32.to_le_bytes());
    assert!(ring2.enqueue(a).is_ok(), "first enqueue fits (usable=1)");
    assert_eq!(
        pool2.avail_count(),
        base - 1,
        "one mbuf now lives in the ring"
    );

    let mut b = pool2.alloc().expect("alloc b");
    b.append(4).expect("tailroom")[..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    assert_eq!(
        pool2.avail_count(),
        base - 2,
        "b held by wrapper before enqueue"
    );
    match ring2.enqueue(b) {
        Ok(()) => panic!("second enqueue must fail — ring is full"),
        Err(returned) => {
            // The Err path handed the SAME mbuf back, still usable.
            let d = returned.data();
            assert_eq!(d.len(), 4, "returned mbuf usable (data_len intact)");
            assert_eq!(
                u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
                0x1234_5678,
                "returned mbuf is the exact one we tried to enqueue"
            );
            drop(returned); // freed → back to pool
        }
    }
    assert_eq!(
        pool2.avail_count(),
        base - 1,
        "only the ring's one mbuf outstanding; the returned Err mbuf was freed (no leak)"
    );

    // Drain the ring's single mbuf so nothing leaks at ring free.
    let mut burst = MbufBurst::new();
    assert_eq!(ring2.dequeue_burst(&mut burst), 1, "the one enqueued mbuf");
    burst.clear(); // drops the mbuf → freed
    assert_eq!(
        pool2.avail_count(),
        base,
        "ring drained; all mbufs back (no net leak)"
    );
}
