//! §5b GATE anchor: prove a NON-EAL writer thread can safely mutate a lock-free + QSBR-RCU
//! typed hash concurrently with a reader thread that (a) is ALSO a plain non-lcore `std::thread`
//! and (b) reports quiescence via `rte_rcu_qsbr_quiescent` each loop.
//!
//! WHY THIS EXISTS: the serve design has a single tokio (non-EAL) writer mutating the config maps
//! while datapath lcores read them lock-free. `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` + an
//! attached QSBR variable is documented to make 1-writer / N-lock-free-reader safe FOR THE KEY
//! TABLE. But the VALUE must also be published/reclaimed RCU-safely. This anchor is the proof
//! that reads of the value never tear and never use-after-free under overwrite + delete churn.
//!
//! STRENGTHENED (§5b gate hardening): the earlier version wrote a byte-identical value per key
//! (`magic` + `key` echo), so overwriting key K always wrote the SAME bytes — a torn read that
//! mixed two writes of K produced identical bytes and was UNDETECTABLE. The reviewer flagged that
//! this cannot prove value safety. This version writes DISTINCT values over time: each write folds
//! a monotonically-increasing `seq` into the value AND stores a `checksum = mix(magic,key,seq)`.
//! A reader validates `magic == MAGIC && key == looked_up_key && checksum == mix(magic,key,seq)`.
//! Because `seq` changes every write, a torn read that splices the low half of write A with the
//! high half of write B yields a `checksum` that does not match its own `seq` -> DETECTED. Any
//! use-after-free of a reclaimed value box likewise yields garbage -> DETECTED (checksum/magic).
//!
//! DETECTION PROOF: run this anchor against the OLD `Vec<Option<V>>` slab storage (which DPDK's
//! LF+RCU does NOT cover) and it can observe malformed reads / UB. Run it against `RcuHash`
//! (value stored in the rte_hash data pointer, RCU-reclaimed) and it passes cleanly.
//!
//! Run: cargo test -p nfkit --test rcu_writer_reader_anchor -- --ignored --test-threads=1

use nfkit::{Eal, RcuHash};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

const MAX_THREADS: u32 = 4;
const READER_ID: u32 = 0;
const CAP: u32 = 4096; // hash capacity
const N_KEYS: u32 = 2048; // working set of churned keys (< CAP so churn never permanently saturates)
const WRITER_ITERS: u32 = 200_000;
/// Keys are offset by a non-zero base so no key is the all-zero byte pattern. DPDK's cuckoo hash
/// reserves the all-zero key slot (`EMPTY_SLOT == 0`, dummy key-store slot 0 is zeroed): inserting
/// an all-zero key aliases that dummy slot and, with RCU value auto-free configured, causes a
/// spurious free of the dummy's data pointer. `RcuHash` documents this constraint; the anchor and
/// `SharedConfigMaps` simply never use an all-zero key.
const KEY_BASE: u32 = 1;

#[inline]
fn mkkey(i: u32) -> K {
    K { v: KEY_BASE + i }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct K {
    v: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct V {
    // A self-describing value that CHANGES every write. `seq` is a per-write monotonic counter, so
    // overwriting key K cycles its value through many DISTINCT bit patterns. The wide `body` makes
    // the value a large multi-word memcpy so a torn read (splicing two writes) has a real window;
    // `checksum` binds ALL fields, so any torn read or use-after-free breaks it. This is the same
    // amplified detector that reliably catches the OLD `Vec<Option<V>>` slab racing (see the
    // scratch demonstration in the task report) — so a clean pass here genuinely proves RcuHash is
    // value-safe, not merely that the race is hard to hit.
    magic: u64,
    key: u32,
    seq: u32,
    body: [u64; 16],
    checksum: u64,
}

const MAGIC: u64 = 0xA5A5_1234_DEAD_BEEF;

/// Value integrity checksum over ALL self-describing fields. A read that mixes two distinct writes
/// (different `seq`/`body`) or reads freed memory will not satisfy `checksum == mix(..)`.
#[inline]
fn mix(magic: u64, key: u32, seq: u32, body: &[u64; 16]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    h ^= magic;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h ^= u64::from(key) ^ (u64::from(seq) << 32);
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    for w in body {
        h ^= *w;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn mkv(key: u32, seq: u32) -> V {
    // body is seq-dependent so every overwrite writes a DISTINCT wide payload.
    let mut body = [0u64; 16];
    for (i, w) in body.iter_mut().enumerate() {
        *w = (u64::from(seq) << 20)
            ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ u64::from(key);
    }
    V {
        magic: MAGIC,
        key,
        seq,
        body,
        checksum: mix(MAGIC, key, seq, &body),
    }
}

/// Returns true iff `v` is a fully-consistent value for `looked_up_key` (magic ok, key echoes the
/// lookup key, and the checksum binds magic+key+seq+body). A torn/UAF read fails this.
#[inline]
fn well_formed(v: &V, looked_up_key: u32) -> bool {
    v.magic == MAGIC && v.key == looked_up_key && v.checksum == mix(v.magic, v.key, v.seq, &v.body)
}

/// Raw pointer we can move across threads. SAFETY (see module doc): the pointee is an LF+RCU
/// rte_hash-backed `RcuHash`; DPDK guarantees 1-writer/N-lock-free-reader safety at the C level for
/// both the key table AND (with `RcuHash`) the value pointer, so concurrent `insert`/`remove`
/// (writer) + `get` (reader) through this pointer is sound even though Rust's borrow checker would
/// forbid the `&mut`/`&` aliasing.
#[derive(Copy, Clone)]
struct SendPtr(*mut RcuHash<K, V>);
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
    let layout = Layout::from_size_align(sz, 64).expect("qsbr layout");
    // SAFETY: non-zero size; freed once at the end after both threads join.
    let qsbr = unsafe { alloc_zeroed(layout) }.cast::<dpdk_sys::rte_rcu_qsbr>();
    assert!(!qsbr.is_null(), "qsbr alloc");
    // SAFETY: qsbr points to `sz` zeroed, 64B-aligned bytes ≥ get_memsize(MAX_THREADS).
    let rc = unsafe { dpdk_sys::nfkit_rcu_qsbr_init(qsbr, MAX_THREADS) };
    assert_eq!(rc, 0, "qsbr init");

    // ── 2. Build the LF+RCU RcuHash over that QSBR, pre-seed the working set ──────────────────────
    // SAFETY: qsbr is initialized and outlives `hash` (freed after both threads join, below).
    let mut hash =
        unsafe { RcuHash::<K, V>::new_lf_rcu("rcu_anchor", CAP, 0, qsbr).expect("lf+rcu hash") };
    for k in 0..N_KEYS {
        let key = mkkey(k);
        assert!(hash.insert(&key, mkv(key.v, 0)), "seed insert {k}");
    }

    let hash_ptr = SendPtr(&mut hash as *mut _);
    let qsbr_ptr = QsbrPtr(qsbr);
    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(2));
    let reader_bad = Arc::new(AtomicU64::new(0));
    let reader_hits = Arc::new(AtomicU64::new(0));

    // ── 3. Reader thread — plain std::thread, NOT an EAL lcore (this is the point) ───────────────
    let reader = {
        let stop = stop.clone();
        let barrier = barrier.clone();
        let reader_bad = reader_bad.clone();
        let reader_hits = reader_hits.clone();
        std::thread::spawn(move || {
            let qsbr_ptr = qsbr_ptr;
            let hash_ptr = hash_ptr;
            let qsbr = qsbr_ptr.0;
            let hp = hash_ptr.0;
            // SAFETY: reader id 0 < MAX_THREADS; qsbr initialized for MAX_THREADS.
            let rr = unsafe { dpdk_sys::nfkit_rcu_qsbr_thread_register(qsbr, READER_ID) };
            assert_eq!(rr, 0, "reader register");
            unsafe { dpdk_sys::nfkit_rcu_qsbr_thread_online(qsbr, READER_ID) };
            barrier.wait();

            let mut i: u32 = 0;
            while !stop.load(Ordering::Relaxed) {
                let key = mkkey(i % N_KEYS);
                // SAFETY: LF+RCU hash → lock-free reader-safe concurrent with the writer's
                // insert/remove. See SendPtr doc.
                if let Some(val) = unsafe { (*hp).get(&key) } {
                    reader_hits.fetch_add(1, Ordering::Relaxed);
                    if !well_formed(&val, key.v) {
                        reader_bad.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Report quiescence EVERY iteration → lets the writer's rte_hash del/overwrite
                // defer-queue reclamation make progress.
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
            let hash_ptr = hash_ptr;
            let hp = hash_ptr.0;
            barrier.wait();
            // Churn: overwrite within the working set with a DISTINCT value every time (seq = it),
            // plus a rolling remove+reinsert to drive the RCU delete/reclaim path (defer queue)
            // concurrently with the reader. Distinct seq per write is what makes torn reads
            // detectable.
            for it in 0..WRITER_ITERS {
                let key = mkkey(it % N_KEYS);
                // overwrite existing key with a fresh, DISTINCT (but well-formed) value.
                // SAFETY: single writer; LF+RCU hash. See SendPtr doc.
                unsafe { (*hp).insert(&key, mkv(key.v, it)) };
                // every few iters, remove a (different) key then reinsert it → exercises del+reclaim
                if it % 4 == 0 {
                    let dk = mkkey((it.wrapping_mul(7)) % N_KEYS);
                    unsafe {
                        (*hp).remove(&dk);
                        (*hp).insert(&dk, mkv(dk.v, it));
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
        "reader observed {bad} malformed values (torn/UAF read) out of {hits} hits — GATE FAIL"
    );
    assert!(
        hits > 0,
        "reader never saw a single live entry — test not exercising the path"
    );

    let count = hash.count();
    assert!(
        count <= CAP as usize,
        "count {count} exceeds table capacity {CAP} — corruption"
    );
    // Full scan: every surviving entry must be well-formed (magic + key echo + checksum).
    let mut scanned = 0usize;
    let mut malformed = 0usize;
    hash.for_each(|k, v| {
        scanned += 1;
        if !well_formed(v, k.v) {
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

    // Drop the hash (frees rte_hash + its RCU DQ, reclaiming all remaining value boxes) BEFORE
    // freeing the QSBR it references.
    drop(hash);
    // SAFETY: both threads joined; hash dropped; qsbr no longer referenced. Same layout as alloc.
    unsafe { dealloc(qsbr.cast::<u8>(), layout) };
}
