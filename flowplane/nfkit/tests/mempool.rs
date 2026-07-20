// Mempool alloc/free accounting. Requires EAL; --test-threads=1.
use nfkit::{Eal, Mempool};

#[test]
fn mempool_allocates_and_frees() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_mp",
    ])
    .expect("EAL init");
    let pool = Mempool::new("t", 1023, 250, 0).expect("pool");
    let before = pool.avail_count();
    let m = pool.alloc().expect("alloc one");
    assert_eq!(pool.avail_count(), before - 1, "alloc takes one buffer");
    drop(m);
    assert_eq!(pool.avail_count(), before, "drop returns the buffer");
}
