//! §5b GATE anchor: prove a NON-EAL writer thread can safely mutate a lock-free + QSBR-RCU
//! `rte_hash` concurrently with a reader thread that (a) is ALSO a plain non-lcore `std::thread`
//! and (b) reports quiescence via `rte_rcu_qsbr_quiescent` each loop.
//!
//! WHY THIS EXISTS: the serve design has a single tokio (non-EAL) writer mutating the config maps
//! while datapath lcores read them lock-free. `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` + an
//! attached QSBR variable is documented to make 1-writer / N-lock-free-reader safe. But the writer
//! and (here) the reader are NOT EAL lcores — they are ordinary OS threads. This anchor is the
//! proof that that arrangement does not segfault / corrupt / hang. If it fails, the serve design
//! must pivot to the rte_ring-drained-by-a-control-lcore fallback.
//!
//! DESIGN of the test:
//!  * A single QSBR variable, 64-byte aligned (rte_rcu_qsbr requires align_of == 64), heap-owned by
//!    the main thread and outliving both worker threads. Sized for MAX_THREADS via
//!    `nfkit_rcu_qsbr_get_memsize`.
//!  * One LF+RCU `DpdkHash<K,V>` built over that QSBR pointer. It is shared across the writer and
//!    reader threads via a `SendPtr(*mut DpdkHash)` — we DELIBERATELY bypass Rust's `&mut`/`&`
//!    aliasing rules because the WHOLE POINT is that rte_hash's LF+RCU machinery provides the
//!    concurrency safety at the C level (1 writer + N lock-free readers). This test is precisely
//!    the empirical proof that that bypass is sound for non-lcore threads.
//!  * Reader thread: registers + onlines reader id 0, then loops looking up a rotating key and
//!    calling `nfkit_rcu_qsbr_quiescent(qsbr, 0)` every iteration until a stop flag. Reporting
//!    quiescence is what lets the writer's deferred key reclamation (rte_hash_del_key -> QSBR defer
//!    queue) actually make progress. If the reader NEVER reported quiescence, deletes would pile up
//!    on the defer queue and the writer could stall once it fills (that stall/hang is itself part of
//!    what we validate: quiescence-reporting matters).
//!  * Writer thread (spawned; main joins both): ~100k iterations of insert-churn (overwrite existing
//!    keys within capacity, insert fresh ones) + remove() churn to exercise concurrent add + del
//!    against the live reader.
//!
//! Run: cargo test -p nfkit --test rcu_writer_reader_anchor -- --ignored --test-threads=1

use nfkit::{DpdkHash, Eal};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};

const MAX_THREADS: u32 = 4;
const READER_ID: u32 = 0;
const CAP: u32 = 4096; // hash capacity
const N_KEYS: u32 = 2048; // working set of churned keys (< CAP so churn never permanently saturates)
const WRITER_ITERS: u32 = 100_000;

#[repr(C)]
#[derive(Copy, Clone)]
struct K {
    v: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct V {
    // A self-describing value: `magic` fixed + `key` echoes the key. Lets the post-run scan assert
    // every surviving entry is well-formed (no torn / half-written value observed by an iterator).
    magic: u64,
    key: u32,
    _pad: u32,
}

const MAGIC: u64 = 0xA5A5_1234_DEAD_BEEF;

fn mkv(key: u32) -> V {
    V {
        magic: MAGIC,
        key,
        _pad: 0,
    }
}

/// Raw pointer we can move across threads. SAFETY (see module doc): the pointee is an LF+RCU
/// rte_hash-backed DpdkHash; DPDK guarantees 1-writer/N-lock-free-reader safety at the C level, so
/// concurrent `insert`/`remove` (writer) + `get` (reader) through this pointer is sound even though
/// Rust's borrow checker would forbid the `&mut`/`&` aliasing.
#[derive(Copy, Clone)]
struct SendPtr(*mut DpdkHash<K, V>);
unsafe impl Send for SendPtr {}

/// Raw QSBR pointer, movable across threads. SAFETY: points to a single initialized, 64-byte-aligned
/// `rte_rcu_qsbr` owned by the main thread that outlives every worker.
#[derive(Copy, Clone)]
struct QsbrPtr(*mut dpdk_sys::rte_rcu_qsbr);
unsafe impl Send for QsbrPtr {}

#[test]
#[ignore = "requires EAL --no-huge; run with -- --ignored --test-threads=1"]
fn rcu_external_writer_qsbr_reader() {
    let _eal = Eal::init([
        "nfkit_rcu_anchor",
        "-l",
        "0-1",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_rcu_anchor",
    ])
    .expect("EAL init");

    // ── 1. Allocate + init the QSBR variable (64-byte aligned, heap, outlives both threads) ──────
    let sz = unsafe { dpdk_sys::nfkit_rcu_qsbr_get_memsize(MAX_THREADS) };
    assert!(sz >= std::mem::size_of::<dpdk_sys::rte_rcu_qsbr>());
    // rte_rcu_qsbr requires 64-byte alignment; a Box<[u8]> does NOT guarantee that, so hand-allocate.
    let layout = Layout::from_size_align(sz, 64).expect("qsbr layout");
    // SAFETY: non-zero size; freed once at the end after both threads join.
    let qsbr = unsafe { alloc_zeroed(layout) }.cast::<dpdk_sys::rte_rcu_qsbr>();
    assert!(!qsbr.is_null(), "qsbr alloc");
    // SAFETY: qsbr points to `sz` zeroed, 64B-aligned bytes ≥ get_memsize(MAX_THREADS).
    let rc = unsafe { dpdk_sys::nfkit_rcu_qsbr_init(qsbr, MAX_THREADS) };
    assert_eq!(rc, 0, "qsbr init");

    // ── 2. Build the LF+RCU hash over that QSBR, pre-seed the working set ────────────────────────
    // SAFETY: qsbr is initialized and outlives `hash` (freed after both threads join, below).
    let mut hash =
        unsafe { DpdkHash::<K, V>::new_lf_rcu("rcu_anchor", CAP, 0, qsbr).expect("lf+rcu hash") };
    for k in 0..N_KEYS {
        assert!(hash.insert(&K { v: k }, mkv(k)), "seed insert {k}");
    }

    let hash_ptr = SendPtr(&mut hash as *mut _);
    let qsbr_ptr = QsbrPtr(qsbr);
    let stop = Arc::new(AtomicBool::new(false));
    // Barrier(2): reader onlines itself, then both threads rendezvous so the writer only starts
    // churning (and thus deferring frees) once the reader is registered + online.
    let barrier = Arc::new(Barrier::new(2));
    // Reader records any malformed value it ever observes (magic mismatch or key!=lookup key). A
    // non-zero count == the LF read raced a write badly = GATE FAILURE.
    let reader_bad = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let reader_hits = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // ── 3. Reader thread — plain std::thread, NOT an EAL lcore (this is the point) ───────────────
    let reader = {
        let stop = stop.clone();
        let barrier = barrier.clone();
        let reader_bad = reader_bad.clone();
        let reader_hits = reader_hits.clone();
        std::thread::spawn(move || {
            // Force capture of the WHOLE Send wrappers (not their `.0` fields — disjoint closure
            // captures would otherwise capture bare `*mut` which isn't Send), then unwrap inside.
            let qsbr_ptr = qsbr_ptr;
            let hash_ptr = hash_ptr;
            let qsbr = qsbr_ptr.0;
            let hp = hash_ptr.0;
            // Register + online BEFORE any read so the writer's deferred frees track this reader.
            // SAFETY: reader id 0 < MAX_THREADS; qsbr initialized for MAX_THREADS.
            let rr = unsafe { dpdk_sys::nfkit_rcu_qsbr_thread_register(qsbr, READER_ID) };
            assert_eq!(rr, 0, "reader register");
            unsafe { dpdk_sys::nfkit_rcu_qsbr_thread_online(qsbr, READER_ID) };
            barrier.wait();

            let mut i: u32 = 0;
            while !stop.load(Ordering::Relaxed) {
                let key = K { v: i % N_KEYS };
                // SAFETY: LF+RCU hash → lock-free reader-safe concurrent with the writer's
                // insert/remove. See SendPtr doc.
                if let Some(val) = unsafe { (*hp).get(&key) } {
                    reader_hits.fetch_add(1, Ordering::Relaxed);
                    if val.magic != MAGIC || val.key != key.v {
                        reader_bad.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Report quiescence EVERY iteration → lets the writer's rte_hash_del_key defer-queue
                // reclamation make progress. Omitting this can stall the writer once the DQ fills.
                // SAFETY: this thread is registered+online as READER_ID on `qsbr`.
                unsafe { dpdk_sys::nfkit_rcu_qsbr_quiescent(qsbr, READER_ID) };
                i = i.wrapping_add(1);
            }
        })
    };

    // ── 4. Writer thread — also a plain non-lcore std::thread ────────────────────────────────────
    let writer = {
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let hash_ptr = hash_ptr; // force whole-wrapper capture (Send), see reader note
            let hp = hash_ptr.0;
            barrier.wait();
            // Churn: overwrite within the working set, plus a rolling remove+reinsert to drive the
            // RCU delete/reclaim path (defer queue) concurrently with the reader.
            for it in 0..WRITER_ITERS {
                let key = it % N_KEYS;
                // overwrite existing key with a fresh (still well-formed) value
                // SAFETY: single writer; LF+RCU hash. See SendPtr doc.
                unsafe { (*hp).insert(&K { v: key }, mkv(key)) };
                // every few iters, remove a (different) key then reinsert it → exercises del+reclaim
                if it % 4 == 0 {
                    let dk = (it.wrapping_mul(7)) % N_KEYS;
                    unsafe {
                        (*hp).remove(&K { v: dk });
                        (*hp).insert(&K { v: dk }, mkv(dk));
                    }
                }
            }
        })
    };

    writer.join().expect("writer join");
    stop.store(true, Ordering::Relaxed);
    reader.join().expect("reader join");

    // ── 5. Post-run assertions (main thread, after join → exclusive access again) ────────────────
    let bad = reader_bad.load(Ordering::Relaxed);
    let hits = reader_hits.load(Ordering::Relaxed);
    assert_eq!(
        bad, 0,
        "reader observed {bad} malformed values (torn/corrupt read) out of {hits} hits — GATE FAIL"
    );
    assert!(
        hits > 0,
        "reader never saw a single live entry — test not exercising the path"
    );

    // NOTE on count bound: with internal QSBR RCU, `rte_hash_del_key` DEFERS slot reclamation to the
    // QSBR defer queue — a deleted key's slot is not recycled (and keeps counting toward
    // `rte_hash_count`) until every registered reader has passed a grace period AND the DQ is
    // drained (which happens lazily, on subsequent add/del). So at snapshot time the live count can
    // legitimately exceed the N_KEYS working set by up to the number of not-yet-reclaimed slots. The
    // only hard invariant is that it never exceeds table capacity CAP. (This lazy-reclaim behavior
    // is a key input for Task 4's SharedConfigMaps sizing — see the report.)
    let count = hash.count();
    assert!(
        count <= CAP as usize,
        "count {count} exceeds table capacity {CAP} — corruption"
    );
    // Full scan: every surviving entry must be well-formed (magic + key echo).
    let mut scanned = 0usize;
    let mut malformed = 0usize;
    hash.for_each(|k, v| {
        scanned += 1;
        if v.magic != MAGIC || v.key != k.v {
            malformed += 1;
        }
    });
    assert_eq!(
        malformed, 0,
        "for_each scan found {malformed} malformed entries — GATE FAIL"
    );
    eprintln!(
        "rcu anchor OK: reader_hits={hits}, post-run count={count}, scanned={scanned}, malformed=0"
    );

    // Drop the hash (frees rte_hash + its RCU DQ) BEFORE freeing the QSBR it references.
    drop(hash);
    // SAFETY: both threads joined; hash dropped; qsbr no longer referenced. Same layout as alloc.
    unsafe { dealloc(qsbr.cast::<u8>(), layout) };
}
