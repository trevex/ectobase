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
}
