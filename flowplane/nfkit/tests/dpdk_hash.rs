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
}
