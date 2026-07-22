//! net_tap rte_flow e2e: build the `nettap_flow` example, then run the `hack/dpdk/nettap-flow.sh`
//! harness (reserves+restores hugepages) which programs a 5-tuple→DROP rule on the net_tap PMD and
//! asserts the resulting kernel tc-flower filter carries the matched dst-ip/dst-port key. SKIPS
//! (passes) when unprivileged / hugepages not reservable / the kernel lacks cls_flower or net_tap
//! flow lowering (script exit 77). Run with `--test-threads=1`.

#[test]
fn nettap_flow_programs_tc_flower_filter() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let root = format!("{dir}/../..");

    // Build the example unprivileged (no root-owned target/), then run the privileged harness.
    let b = std::process::Command::new("cargo")
        .args(["build", "-p", "nfkit", "--example", "nettap_flow"])
        .current_dir(&root)
        .status()
        .expect("build nettap_flow");
    assert!(b.success(), "failed to build the nettap_flow example");
    let bin = format!("{root}/target/debug/examples/nettap_flow");

    let status = std::process::Command::new("bash")
        .arg(format!("{root}/hack/dpdk/nettap-flow.sh"))
        .env("NETTAP_BIN", &bin)
        .current_dir(&root)
        .status()
        .expect("run nettap-flow.sh");

    match status.code() {
        Some(0) => {}
        Some(77) => {
            eprintln!(
                "nettap rte_flow test skipped (unprivileged / no hugepages / no cls_flower / no \
                 net_tap flow lowering)"
            );
        }
        other => panic!("nettap-flow.sh failed: exit {other:?}"),
    }
}
