// Typed rte_hash: add/lookup/miss/overwrite over a POD key + Copy value. Requires EAL; --test-threads=1.
use nfkit::{DpdkHash, Eal};

#[derive(Copy, Clone)]
#[repr(C)]
struct K {
    a: u32,
    b: u32,
}

#[test]
fn dpdk_hash_add_lookup_overwrite() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_hash",
    ])
    .expect("EAL init");
    let mut h: DpdkHash<K, u64> = DpdkHash::new("t", 1024, 0).expect("hash");
    assert_eq!(h.get(&K { a: 1, b: 2 }), None);
    h.insert(&K { a: 1, b: 2 }, 42);
    assert_eq!(h.get(&K { a: 1, b: 2 }), Some(42));
    assert_eq!(h.get(&K { a: 1, b: 3 }), None, "different key misses");
    h.insert(&K { a: 1, b: 2 }, 99);
    assert_eq!(h.get(&K { a: 1, b: 2 }), Some(99));

    // for_each iteration: EAL is process-global/single-shot, so this shares the one EAL init above.
    // Insert N=5 distinct (K, V) into a fresh hash, collect via for_each, and assert the collected
    // SET equals the inserted set (rte_hash iteration order is unspecified — compare sorted).
    let mut it: DpdkHash<K, u64> = DpdkHash::new("iter", 1024, 0).expect("iter hash");
    let inserted: Vec<(K, u64)> = vec![
        (K { a: 1, b: 10 }, 100),
        (K { a: 2, b: 20 }, 200),
        (K { a: 3, b: 30 }, 300),
        (K { a: 4, b: 40 }, 400),
        (K { a: 5, b: 50 }, 500),
    ];
    for (k, v) in &inserted {
        it.insert(k, *v);
    }
    let mut collected: Vec<(u32, u32, u64)> = Vec::new();
    it.for_each(|k, v| collected.push((k.a, k.b, *v)));
    collected.sort_unstable();

    let mut expected: Vec<(u32, u32, u64)> = inserted.iter().map(|(k, v)| (k.a, k.b, *v)).collect();
    expected.sort_unstable();

    assert_eq!(
        collected, expected,
        "for_each must visit every inserted entry exactly once"
    );

    // Capacity/observability: a small hash (entries=64) fed 300 distinct keys MUST saturate.
    // `insert` is fallible (`-> bool`); the grow-on-demand slab guarantees no OOB regardless of
    // whatever position rte_hash returns. Assert: (a) no panic, (b) >=1 insert returns false once
    // full, (c) for_each == the set of true-inserted keys, (d) each true key round-trips via get,
    // (e) a false-insert key is absent (no partial/corrupt slot).
    let mut cap: DpdkHash<u64, u64> = DpdkHash::new("cap", 64, 0).expect("cap hash");
    let mut true_keys: Vec<u64> = Vec::new();
    let mut false_keys: Vec<u64> = Vec::new();
    for key in 0u64..300 {
        if cap.insert(&key, key.wrapping_mul(7)) {
            true_keys.push(key);
        } else {
            false_keys.push(key);
        }
    }
    assert!(
        !false_keys.is_empty(),
        "a 64-entry hash fed 300 keys must observably saturate (>=1 false insert)"
    );

    let mut seen: Vec<u64> = Vec::new();
    cap.for_each(|k, _v| seen.push(*k));
    seen.sort_unstable();
    let mut expect_true = true_keys.clone();
    expect_true.sort_unstable();
    assert_eq!(
        seen, expect_true,
        "for_each must yield exactly the set of true-inserted keys"
    );

    for key in &true_keys {
        assert_eq!(
            cap.get(key),
            Some(key.wrapping_mul(7)),
            "every true-inserted key must round-trip via get"
        );
    }

    let dropped = false_keys[0];
    assert_eq!(
        cap.get(&dropped),
        None,
        "a false-insert key must be absent (no partial/corrupt slot)"
    );
    assert!(
        !seen.contains(&dropped),
        "a false-insert key must not appear in for_each"
    );
}
