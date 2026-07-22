// Drives hack/dpdk/afxdp-loopback.sh. SKIPS (passes) when unprivileged / no hugepages / af_xdp
// absent (script exits 77). Runs the real e2e in a privileged job.
use std::process::Command;

#[test]
fn afxdp_veth_loopback() {
    let root = format!("{}/../..", env!("CARGO_MANIFEST_DIR")); // repo root (from flowplane/nfkit)
    let build = Command::new("cargo")
        .args(["build", "-p", "nfkit", "--example", "l2fwd"])
        .current_dir(&root)
        .status()
        .expect("build example");
    assert!(build.success());
    let bin = format!("{root}/target/debug/examples/l2fwd");

    let status = Command::new("bash")
        .arg(format!("{root}/hack/dpdk/afxdp-loopback.sh"))
        .env("L2FWD_BIN", &bin)
        .current_dir(&root)
        .status()
        .expect("run loopback script");
    match status.code() {
        Some(0) => {}
        Some(77) => eprintln!("afxdp loopback skipped (unprivileged / no hugepages)"),
        other => panic!("afxdp loopback failed: exit {other:?}"),
    }
}
