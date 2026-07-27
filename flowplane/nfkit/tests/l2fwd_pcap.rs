// Deterministic DoD: run the l2fwd example on net_pcap over a fixture, assert every output frame
// has src/dst MAC swapped vs the input. Runs the BUILT example binary (avoids nested cargo lock).
use std::process::Command;

#[test]
fn l2fwd_pcap_swaps_macs() {
    let dir = env!("CARGO_MANIFEST_DIR"); // .../flowplane/nfkit
    let root = format!("{dir}/../.."); // repo root
    let input = format!("{dir}/tests/data/l2fwd_in.pcap");
    let out = format!("{dir}/tests/data/l2fwd_out.pcap");
    let _ = std::fs::remove_file(&out);

    // Build the example, then run the built binary directly (nested `cargo run` inside `cargo test`
    // can deadlock on the target-dir lock).
    let b = Command::new("cargo")
        .args(["build", "-p", "nfkit", "--example", "l2fwd"])
        .current_dir(&root)
        .status()
        .expect("build l2fwd");
    assert!(b.success());
    let bin = format!("{root}/target/debug/examples/l2fwd");
    let status = Command::new(&bin)
        .args(["pcap", &input, &out])
        .current_dir(&root)
        .status()
        .expect("run l2fwd");
    assert!(status.success(), "l2fwd exited non-zero");

    // Verify with the pure-Go netprobe tool (no scapy): each out frame's dst==in src and src==in dst.
    let netprobe = if let Ok(bin) = std::env::var("NETPROBE_BIN") {
        bin
    } else {
        // Build netprobe once into a temp location.
        let tmp = std::env::temp_dir().join("netprobe");
        let e2e_dir = format!("{root}/test/e2e");
        let b = Command::new("go")
            .args(["build", "-o", tmp.to_str().unwrap(), "./cmd/netprobe"])
            .current_dir(&e2e_dir)
            .env("CGO_ENABLED", "0")
            .status()
            .expect("build netprobe");
        assert!(b.success(), "failed to build netprobe");
        tmp.to_str().unwrap().to_owned()
    };
    let s = Command::new(&netprobe)
        .args([
            "pcap-verify",
            "--in",
            &input,
            "--out",
            &out,
            "--mac-swap",
            "--count",
            "4",
        ])
        .status()
        .expect("run netprobe pcap-verify");
    assert!(s.success(), "MAC-swap verification failed");
}
