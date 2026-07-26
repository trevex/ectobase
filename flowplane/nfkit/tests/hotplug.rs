//! DE-RISK GATE for dead-slot live recovery (flowplane-dpdk `VethBackend::recover`, Task 6/G3):
//! prove that a `net_af_xdp` vdev can be ADDED AT RUNTIME (after EAL init) via
//! `rte_eal_hotplug_add`, that its ethdev port `Port::configure`s up, and that it can then be
//! hot-REMOVED. Recovery relies on exactly this: a slot whose backing veth died is recreated and
//! its af_xdp vdev is hot-rebound in place — NOT re-inited (EAL is once-per-process).
//!
//! If this FAILS on a root host, the in-place hotplug rebind is not viable and Task 6 must fall
//! back to the "soft recovery" contingency (add the vdev under a NEW name/port id and grow the
//! poll set). So a failure here PANICS (it is the whole point of the gate) rather than skipping.
//!
//! SKIPS (passes) when unprivileged: veth creation + af_xdp bind need root/CAP_NET_ADMIN.
//! EAL runs `--no-huge` (no hugepage reservation) with a unique `--file-prefix` (EAL is
//! once-per-process; keep this in its OWN `--test` binary).
//!
//! Run: `sudo -E $(command -v cargo) test -p nfkit --test hotplug -- --test-threads=1 --nocapture`
use nfkit::{hotplug_add, hotplug_remove, port_by_name, Eal, Mempool, Port};
use std::process::Command;

/// The host-side veth this test creates + hotplug af_xdp-binds. Unique to avoid colliding with any
/// other harness's devices. The peer end is `<name>p`.
const HOST: &str = "fphp0";
/// The vdev device name (bus `vdev`) the af_xdp PMD is hotplug-added under.
const VDEV: &str = "net_af_xdp9";

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

fn del_veth(host: &str) {
    let _ = ip(&["link", "del", host]);
}

/// Create `<host>`/`<host>p` veth pair (both ends in the root netns, both `up`). af_xdp needs the
/// netdev up to bind its rx/tx rings.
fn create_veth(host: &str) -> Result<(), ()> {
    let peer = format!("{host}p");
    del_veth(host);
    if !ip(&["link", "add", host, "type", "veth", "peer", "name", &peer]) {
        return Err(());
    }
    if !ip(&["link", "set", host, "up"]) || !ip(&["link", "set", &peer, "up"]) {
        del_veth(host);
        return Err(());
    }
    Ok(())
}

struct VethGuard;
impl Drop for VethGuard {
    fn drop(&mut self) {
        del_veth(HOST);
    }
}

#[test]
fn afxdp_vdev_hotplug_add_configure_remove() {
    // SAFETY: geteuid is always safe (no args, reads the process's effective uid).
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("SKIP afxdp_vdev_hotplug_add_configure_remove: not root (needs CAP_NET_ADMIN)");
        return;
    }

    let _guard = VethGuard;
    if create_veth(HOST).is_err() {
        eprintln!("SKIP afxdp_vdev_hotplug_add_configure_remove: could not create veth");
        return;
    }

    // ── EAL init WITHOUT any vdev ─────────────────────────────────────────────────
    // The whole point is that the af_xdp port appears LATER via hotplug, not at init.
    let eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--file-prefix",
        "nfkit_hp",
    ]);
    let eal = match eal {
        Ok(e) => e,
        Err(e) => panic!("EAL init (no vdev) FAILED: {e}"),
    };
    assert_eq!(
        eal.port_count(),
        0,
        "expected 0 ethdev ports before hotplug"
    );

    // ── HOTPLUG-ADD the af_xdp vdev at runtime ────────────────────────────────────
    let devargs = format!("iface={HOST},start_queue=0,queue_count=1");
    if let Err(e) = hotplug_add("vdev", VDEV, &devargs) {
        panic!(
            "rte_eal_hotplug_add(vdev, {VDEV}, {devargs}) FAILED: {e}. \
             In-place af_xdp hotplug rebind is NOT viable on this host — Task 6 must use the \
             soft-recovery contingency (new name/port id, grow the poll set)."
        );
    }
    assert!(
        eal.port_count() >= 1,
        "hotplug_add succeeded but no ethdev port appeared"
    );

    // Resolve the hotplugged port id by device name (recovery re-resolves the port id this way).
    let port_id = port_by_name(VDEV).expect("resolve hotplugged port id by name");
    eprintln!("hotplug-added {VDEV} -> ethdev port id {port_id}");

    // ── Port::configure the hotplugged port ───────────────────────────────────────
    let pool = Mempool::new("hp_pool", 8191, 250, 0).expect("mempool create");
    let port = Port::configure(port_id, 1, &pool).expect("configure hotplugged af_xdp port");
    assert!(
        port.n_queues() >= 1,
        "hotplugged port configured with no queues"
    );
    eprintln!(
        "OK: hotplugged af_xdp port {port_id} up with {} queue(s)",
        port.n_queues()
    );

    // Drop the Port (stop+close) BEFORE removing the device — a live ethdev cannot be hot-removed.
    drop(port);

    // ── HOTPLUG-REMOVE ────────────────────────────────────────────────────────────
    hotplug_remove("vdev", VDEV).expect("hotplug_remove the af_xdp vdev");
    eprintln!("OK: hotplug_remove({VDEV}) succeeded — round-trip complete");

    drop(pool);
    drop(eal);
}
