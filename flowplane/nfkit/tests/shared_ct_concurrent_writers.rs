//! Shared reverse-conntrack (`SharedConfigMaps::shared_ct`) under REAL concurrent multi-lcore writers.
//!
//! ── WHAT THIS EXERCISES ───────────────────────────────────────────────────────────────────────
//! `shared_ct` is the ONE datapath table written from MANY lcores: a guest's SNAT/NAT64 EGRESS pins
//! the peer-independent reverse entry `(vni, 0, nat_ip, 0, nat_port)` so a WAN reply RSS-steered to
//! ANY lcore can resolve the reverse-DNAT. `RcuHash` is SINGLE-WRITER (rcu_hash.rs:30-36:
//! `RW_CONCURRENCY_LF` = ONE writer + N lock-free readers, NOT concurrent writers — concurrent
//! `rte_hash_add_key`/`del_key` corrupt the table). A recent review fix SERIALIZES the write path
//! behind `SharedConfigMaps::shared_ct_write` (a `std::sync::Mutex`) while reads stay lock-free +
//! RCU-covered.
//!
//! This test drives that concurrent-writer path for real: N worker lcores (`for_each_worker`) each
//! call `shared_ct_insert`/`_remove` — the EXACT calls `snat_egress` makes — CONCURRENTLY from their
//! own lcore, into a DISJOINT per-worker keyspace. It asserts the single-writer Mutex keeps the
//! `RcuHash` intact: every insert lands, byte-exact, with no torn/lost/duplicate entries, and reads
//! interleaved DURING the write phase never observe a partially-written entry. BEFORE the Mutex fix,
//! concurrent `RcuHash` writes from multiple lcores would data-race and corrupt the table; this
//! asserts they don't.
//!
//! EAL is process-global → run with `--test-threads=1`. One `#[test]`, one EAL init.

use flowplane_common::{CtEntry, CtKey, CT_F_SRC_NAT, CT_REWRITE_DST};
use nfkit::{worker_lcore_count, Eal, LcoreRuntime, SharedConfigMaps};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

const DNAT_VNI: u32 = 100;
/// Distinct reverse NAT port per index `i` (host order), same shape a real SNAT allocation uses.
const NAT_PORT_BASE: u16 = 20000;
/// Guest IP the reverse entry restores the inner dst to (constant across entries; the reverse KEY
/// varies by `nat_ip`/`nat_port`, the payload varies by encoded (q,i)).
const GUEST_IP: [u8; 4] = [10, 0, 0, 10];

/// Distinct entries per worker `q`. K is sized off the ACTUAL worker count so the table stays well
/// within capacity: total = n_workers * K.
const K: u16 = 512;

/// The peer-independent reverse key `(vni, 0, nat_ip, 0, nat_port)` for worker `q`, index `i`.
/// The keyspace is partitioned by `q` via `nat_ip[1] = q` → workers NEVER collide on a key, so the
/// test proves writer-serialization soundness (no torn/lost inserts), not last-writer-wins.
/// The index `i` (0..K, up to 512) is encoded across the LOW TWO nat_ip bytes so a single `u8` never
/// wraps (K may exceed 256): `nat_ip = [10, q, i>>8, i&0xff]`. The 4-byte `dst_ip` is thus a unique
/// identity for every (q, i) — used both for dedup and to recover (q, i) in `shared_ct_for_each`.
fn rev_key(q: u16, i: u16) -> CtKey {
    CtKey {
        vni: DNAT_VNI,
        src_ip: [0; 4],
        dst_ip: [10, q as u8, (i >> 8) as u8, i as u8], // nat_ip (reverse shape: src==0)
        src_port: 0,
        dst_port: NAT_PORT_BASE.wrapping_add(i),
        proto: 6,
        _pad: [0; 3],
    }
}

/// Recover `(q, i)` from a reverse key's `dst_ip` (the inverse of `rev_key`'s encoding).
fn qi_of(dst_ip: [u8; 4]) -> (u16, u16) {
    let q = dst_ip[1] as u16;
    let i = ((dst_ip[2] as u16) << 8) | (dst_ip[3] as u16);
    (q, i)
}

/// A reverse CT entry whose payload uniquely encodes `(q, i)` so post-barrier assertions verify the
/// RIGHT entry landed under each key (not just presence). Realistic flags (`CT_REWRITE_DST |
/// CT_F_SRC_NAT`) + `xlate_ip = GUEST_IP`, exactly what `snat_egress` pins.
fn rev_entry(q: u16, i: u16) -> CtEntry {
    CtEntry {
        // Encode (q,i) into last_seen so a partial/torn write is detectable byte-exact.
        last_seen: ((q as u64) << 32) | (i as u64),
        xlate_ip: GUEST_IP,
        xlate_port: i, // also encode i here (restored inner dst port slot)
        flags: CT_REWRITE_DST | CT_F_SRC_NAT,
        tcp_state: 0,
        fwall_action: 0,
        gen_bytes: [0; 4],
        _pad: [0; 3],
    }
}

/// Which keys does a worker REMOVE in the concurrent remove sub-phase? Odd `i` are removed, even
/// `i` survive — so post-barrier we expect exactly the even-`i` half per worker.
fn is_removed(i: u16) -> bool {
    i % 2 == 1
}

#[test]
fn shared_ct_concurrent_multilcore_writers() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0-4",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_ctcw",
    ])
    .expect("EAL init");

    let n_workers = worker_lcore_count();
    assert!(n_workers >= 1, "need at least one worker lcore");
    eprintln!("shared_ct concurrent writers: n_workers={n_workers}, K={K} per worker");

    // ONE shared config half — its `shared_ct` is the table under test. Size generously: total live
    // entries = n_workers * K, and HEADROOM is applied internally.
    let capacity = (n_workers as u32) * (K as u32) + 1024;
    let shared = SharedConfigMaps::new(0, capacity).expect("shared config");

    // Count torn/partial reads observed mid-phase across all workers (must stay 0).
    let torn_reads = AtomicUsize::new(0);
    // Per-worker report of how many of its own inserts succeeded (should be K each).
    let insert_ok: Vec<Mutex<usize>> = (0..n_workers).map(|_| Mutex::new(0)).collect();
    let remove_ok: Vec<Mutex<usize>> = (0..n_workers).map(|_| Mutex::new(0)).collect();

    LcoreRuntime::for_each_worker(n_workers, |q| {
        // Register as an RCU reader so the writer's deferred frees can make progress; report
        // quiescence periodically (this thread both writes and reads).
        let tok = shared.register_reader();

        let mut inserts = 0usize;

        // ── Phase 1: concurrent inserts into this worker's DISJOINT keyspace ──────
        for i in 0..K {
            let key = rev_key(q, i);
            // The EXACT call snat_egress makes (write serialized behind the single-writer Mutex).
            if shared.shared_ct_insert(key, rev_entry(q, i)) {
                inserts += 1;
            }

            // Interleave reads DURING the write phase: read our own just-written key (must be
            // byte-exact) plus a neighbor worker's key (may be None mid-phase; a Some MUST be
            // byte-exact — never partially written).
            if let Some(got) = shared.shared_ct_get(&key) {
                if got != rev_entry(q, i) {
                    torn_reads.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                // We JUST inserted it (and no other worker touches this key) → must be present.
                torn_reads.fetch_add(1, Ordering::Relaxed);
            }
            let neighbor = (q + 1) % n_workers;
            if let Some(got) = shared.shared_ct_get(&rev_key(neighbor, i)) {
                // A neighbor may or may not have reached index i yet; if present it MUST be the
                // neighbor's exact entry, never torn.
                if got != rev_entry(neighbor, i) {
                    torn_reads.fetch_add(1, Ordering::Relaxed);
                }
            }

            if i % 64 == 0 {
                shared.report_quiescent(&tok);
            }
        }
        *insert_ok[q as usize].lock().unwrap() = inserts;
        shared.report_quiescent(&tok);

        // ── Phase 2: concurrent removes of half our own keys (odd i) ─────────────
        let mut removes = 0usize;
        for i in 0..K {
            if is_removed(i) {
                let key = rev_key(q, i);
                if shared.shared_ct_remove(&key) {
                    removes += 1;
                }
                // Immediately after removing, the key must be absent (own disjoint keyspace).
                if shared.shared_ct_get(&key).is_some() {
                    torn_reads.fetch_add(1, Ordering::Relaxed);
                }
            }
            if i % 64 == 0 {
                shared.report_quiescent(&tok);
            }
        }
        *remove_ok[q as usize].lock().unwrap() = removes;
        shared.report_quiescent(&tok);
    });

    // ── Post-barrier assertions on the MAIN thread (all workers joined) ──────────
    assert_eq!(
        torn_reads.load(Ordering::Relaxed),
        0,
        "a reader observed a TORN/partial/lost shared_ct entry during concurrent writes — \
         the single-writer Mutex did NOT protect the RcuHash"
    );

    // Every worker inserted all K of its keys.
    for q in 0..n_workers {
        assert_eq!(
            *insert_ok[q as usize].lock().unwrap(),
            K as usize,
            "worker {q}: all {K} shared_ct inserts succeeded (table not full / no lost writes)"
        );
    }
    // Every worker removed exactly the odd-i half (K/2 for even K).
    let expected_removes = (K / 2) as usize;
    for q in 0..n_workers {
        assert_eq!(
            *remove_ok[q as usize].lock().unwrap(),
            expected_removes,
            "worker {q}: removed exactly the odd-i half of its keys"
        );
    }

    // (a) Every SURVIVING entry (even i) is present via shared_ct_get, byte-exact; every removed
    //     entry (odd i) is absent.
    for q in 0..n_workers {
        for i in 0..K {
            let key = rev_key(q, i);
            let got = shared.shared_ct_get(&key);
            if is_removed(i) {
                assert_eq!(got, None, "worker {q} i={i}: removed key must be absent");
            } else {
                assert_eq!(
                    got,
                    Some(rev_entry(q, i)),
                    "worker {q} i={i}: surviving key must hold its EXACT entry (no torn write / \
                     no wrong-entry-under-key)"
                );
            }
        }
    }

    // (b) shared_ct_for_each counts EXACTLY the survivors: n_workers * (K/2). Also rebuild the set
    //     of visited keys to assert (c) no duplicates and no missing keys.
    let survivors_per_worker = (K - K / 2) as usize; // even i (includes i=0)
    let expected_total = (n_workers as usize) * survivors_per_worker;
    let mut seen: std::collections::HashSet<[u8; 4]> = std::collections::HashSet::new();
    let mut count = 0usize;
    let mut dup = 0usize;
    let mut bad_shape = 0usize;
    shared.shared_ct_for_each(|k, v| {
        count += 1;
        // Every entry must be a peer-independent reverse entry (src==0, src_port==0) with our
        // realistic flags — proves no foreign/corrupt key materialized.
        if k.src_ip != [0; 4]
            || k.src_port != 0
            || k.proto != 6
            || v.flags != (CT_REWRITE_DST | CT_F_SRC_NAT)
            || v.xlate_ip != GUEST_IP
        {
            bad_shape += 1;
        }
        // dst_ip encodes (q,i) → the identity of the entry. Verify the payload matches the key.
        let (q, i) = qi_of(k.dst_ip);
        if v != &rev_entry(q, i) {
            bad_shape += 1;
        }
        if !seen.insert(k.dst_ip) {
            dup += 1;
        }
    });
    assert_eq!(
        bad_shape, 0,
        "shared_ct_for_each yielded a malformed/mismatched entry"
    );
    assert_eq!(dup, 0, "shared_ct_for_each yielded DUPLICATE keys");
    assert_eq!(
        count, expected_total,
        "shared_ct_for_each count must equal n_workers * survivors_per_worker \
         ({n_workers} * {survivors_per_worker})"
    );
    assert_eq!(
        seen.len(),
        expected_total,
        "distinct survivor keys must equal the expected total (no missing keys)"
    );

    eprintln!(
        "OK: {n_workers} lcores × {K} concurrent inserts, half removed → {count} survivors \
         intact, 0 torn reads, 0 dup/missing keys"
    );
}
