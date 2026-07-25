//! De-risk: prove DPDK can bring up N af_xdp vdevs in ONE EAL as ethdev ports 0..N-1.
//!
//! This is the highest-unknown of the "DPDK guest egress" feature: the design gives each guest its
//! OWN af_xdp port (VF-style), all preallocated before EAL init and passed as
//! `--vdev=net_af_xdp<i>,iface=<veth>`. If two af_xdp vdevs cannot coexist in a single EAL, the
//! whole approach is invalid. This test creates TWO veth pairs in-process, inits EAL with TWO
//! `net_af_xdp` vdevs, and asserts BOTH `Port::configure` as ports 0 and 1.
//!
//! SKIPS (passes) when unprivileged: af_xdp bind needs CAP_NET_ADMIN and veth creation needs root,
//! so a non-root run cannot exercise the real path — it returns early with a message (mirrors the
//! exit-77 convention of the bash-driven af_xdp harnesses). EAL runs `--no-huge` so no hugepage
//! reservation is required. Keep this in its OWN `--test` binary: EAL is once-per-process.
//!
//! Run: `sudo -E $(command -v cargo) test -p nfkit --test multi_afxdp_port -- --test-threads=1 --nocapture`
use nfkit::{Eal, Mempool, Port};
use std::process::Command;

/// The two host-side veth names this test creates + af_xdp-binds. Unique to avoid colliding with
/// any other harness's devices. Each pair's peer end is `<name>p`.
const HOST0: &str = "nfkitg0";
const HOST1: &str = "nfkitg1";

/// Run an `ip` command, returning whether it succeeded (stderr surfaced on failure for debugging).
fn ip(args: &[&str]) -> bool {
    match Command::new("ip").args(args).output() {
        Ok(o) => {
            if !o.status.success() {
                eprintln!(
                    "  ip {:?} failed: {}",
                    args,
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            o.status.success()
        }
        Err(e) => {
            eprintln!("  spawn ip {args:?} failed: {e}");
            false
        }
    }
}

/// Idempotently delete a veth link (ignores "not found").
fn del_veth(host: &str) {
    let _ = ip(&["link", "del", host]);
}

/// Create `<host>`/`<host>p` veth pair (both ends in the root netns, both `up`). Returns Ok on
/// success. Deletes any stale link with the same name first.
fn create_veth(host: &str) -> Result<(), ()> {
    let peer = format!("{host}p");
    del_veth(host);
    if !ip(&["link", "add", host, "type", "veth", "peer", "name", &peer]) {
        return Err(());
    }
    // Both ends up — af_xdp requires the netdev to be up to bind its rx/tx rings.
    if !ip(&["link", "set", host, "up"]) || !ip(&["link", "set", &peer, "up"]) {
        del_veth(host);
        return Err(());
    }
    Ok(())
}

/// RAII cleanup: delete both veth pairs on drop, even if the test panics mid-way.
struct VethGuard;
impl Drop for VethGuard {
    fn drop(&mut self) {
        del_veth(HOST0);
        del_veth(HOST1);
    }
}

#[test]
fn two_afxdp_vdevs_coexist_in_one_eal() {
    // ── privilege gate ──────────────────────────────────────────────────────────
    // Veth creation + af_xdp bind both need root/CAP_NET_ADMIN. Skip cleanly (pass) otherwise so
    // the unprivileged CI run is green; the privileged job proves the real path.
    // SAFETY: geteuid is always safe (no args, reads the process's effective uid).
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("SKIP two_afxdp_vdevs_coexist_in_one_eal: not root (needs CAP_NET_ADMIN)");
        return;
    }

    // ── two veth pairs (before EAL init) ─────────────────────────────────────────
    // The guard deletes them on any exit path (success, panic, early return below).
    let _guard = VethGuard;
    if create_veth(HOST0).is_err() || create_veth(HOST1).is_err() {
        eprintln!("SKIP two_afxdp_vdevs_coexist_in_one_eal: could not create veth pairs");
        return;
    }

    // ── EAL init with TWO af_xdp vdevs ───────────────────────────────────────────
    // `--no-huge -m 512` avoids any hugepage reservation. `--file-prefix` isolates this EAL's
    // hugepage/runtime files from other privileged nfkit test binaries run in the same session.
    // The two `net_af_xdp` vdevs become ethdev ports 0 and 1.
    let eal = Eal::init([
        "nfkit-test",
        "-l",
        "0-1",
        "--no-huge",
        "-m",
        "512",
        "--file-prefix",
        "nfkit_mafxdp",
        "--vdev",
        &format!("net_af_xdp0,iface={HOST0},start_queue=0,queue_count=1"),
        "--vdev",
        &format!("net_af_xdp1,iface={HOST1},start_queue=0,queue_count=1"),
    ]);
    let eal = match eal {
        Ok(e) => e,
        Err(e) => {
            // If EAL init itself fails on a root host, that is a REAL blocker for the feature — do
            // NOT mask it as a skip. Panic so it's surfaced (this is the whole point of the test).
            panic!(
                "EAL init with two af_xdp vdevs FAILED: {e}. \
                 This would invalidate the per-guest-af_xdp approach — escalate."
            );
        }
    };

    // Both vdevs must have probed as ethdev ports.
    let ports = eal.port_count();
    assert!(
        ports >= 2,
        "expected >= 2 ethdev ports from two af_xdp vdevs, got {ports}"
    );

    // ── configure BOTH ports ─────────────────────────────────────────────────────
    let pool = Mempool::new("mafxdp_pool", 8191, 250, 0).expect("mempool create");
    let p0 = Port::configure(0, 1, &pool).expect("configure af_xdp port 0");
    let p1 = Port::configure(1, 1, &pool).expect("configure af_xdp port 1");
    assert!(p0.n_queues() >= 1, "port 0 got no queues");
    assert!(p1.n_queues() >= 1, "port 1 got no queues");

    eprintln!(
        "OK: two af_xdp vdevs coexist — port0 q={}, port1 q={} (of {ports} probed)",
        p0.n_queues(),
        p1.n_queues()
    );
    // Ports drop (stop+close) here, then the pool, then EAL cleanup — the required teardown order.
    drop(p1);
    drop(p0);
    drop(pool);
    drop(eal);
}
