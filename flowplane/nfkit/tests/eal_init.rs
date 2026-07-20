// Proof-of-toolchain: initialize DPDK EAL on THIS host with no hugepages, no PCI, a null
// vdev — then verify the safety guard rejects a second init in the same process.
// Run with `--test-threads=1` (EAL is process-global; tests share the process).
use nfkit::{Eal, EalError};

#[test]
fn eal_inits_once_and_rejects_reinit() {
    let eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--vdev",
        "net_null0",
        "--file-prefix",
        "nfkit_test",
    ])
    .expect("EAL init failed — check hugepages/permissions/vdev support");
    // EAL is up; a null port should exist.
    assert!(eal.port_count() >= 1, "expected the net_null0 vdev port");

    // A second init in the same process must be REJECTED (not UB) — the safety guard.
    // `eal` is still alive here, so EAL_INITIALIZED is true.
    let again = Eal::init([
        "nfkit-test",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--vdev",
        "net_null0",
    ]);
    assert!(
        matches!(again, Err(EalError::AlreadyInit)),
        "reinit must return AlreadyInit, got {again:?}",
    );
}
