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

    // Verify with scapy: each out frame's dst==in src and src==in dst.
    let py = format!(
        r#"from scapy.all import rdpcap
i=rdpcap("{input}"); o=rdpcap("{out}")
assert len(o)==len(i)==4, (len(i),len(o))
for a,b in zip(i,o):
    assert b.dst==a.src and b.src==a.dst, (a.summary(),b.summary())
print("OK")"#
    );
    let s = Command::new("python3")
        .arg("-c")
        .arg(&py)
        .status()
        .expect("scapy verify");
    assert!(s.success(), "MAC-swap verification failed");
}
