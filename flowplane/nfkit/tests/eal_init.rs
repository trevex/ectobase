// Proof-of-toolchain: initialize DPDK EAL on THIS host with no hugepages, no PCI, a null
// vdev — then clean up. If this passes in CI, the environment is good end to end.
use nfkit::Eal;

#[test]
fn eal_inits_on_null_vdev_no_huge() {
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
}
