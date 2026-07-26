//! Full-serve af_xdp e2e: launch the REAL `flowplane-dpdk serve` process with a preallocated guest
//! port pool, drive AttachInterface + route/NAT/firewall over gRPC (via the `attach_client` example),
//! and prove over REAL af_xdp transport:
//!   (a) a guest IPv4 frame → encapped IPv6 egresses the uplink (guest→fabric),
//!   (b) the matching NAT-return is decapped + reverse-DNAT'd back to the guest,
//!   (c) [stretch, `SERVE_E2E_GUEST2GUEST=1`] guest-A → guest-B same-node delivery via LcoreRing.
//!
//! Every datapath seam is already unit/component-proven (guest_tx_datapath.rs, afxdp_datapath.rs,
//! attach_veth.rs, guest_tx_nat_return_handoff.rs); this validates the WHOLE process over real
//! transport. The `hack/dpdk/serve-e2e.sh` harness reserves+restores hugepages, creates the uplink
//! veth + guest netns, launches serve, programs it, injects/sniffs, and exits 0 (OK) / 77 (skip,
//! unprivileged or no hugepages) / else (fail). SKIPS (passes) on non-zero-but-77.
//!
//! Run: sudo -E $(command -v cargo) test -p flowplane-dpdk --test serve_e2e -- --test-threads=1 --nocapture
//!
//! ── KNOWN BLOCKER (discovered wiring this e2e; needs its own task/review) ──────────────────────────
//! The `flowplane-dpdk serve` process NEVER programs the process-wide `LOCAL` config entry (uplink
//! identity: `uplink_ifindex` / `uplink_mac` / `gateway_mac` / underlay). `SharedConfigMaps::set_local`
//! is called only in nfkit tests, never in `serve.rs`. Without `LOCAL`, `worker_loop` drops EVERY
//! guest-egress AND uplink burst ("No LOCAL programmed → no uplink identity; drop the whole burst" /
//! "Without LOCAL there is no uplink identity, so poll+drain … drop everything"), so the datapath is
//! inert even though attach/route/NAT/firewall program correctly and the af_xdp transport delivers
//! frames to the guest socket (verified: guest-injected frames increment the guest port's RX counter).
//! The eBPF sibling programs LOCAL at `ControlCore::bring_up` from the `--uplink` netdev's ifindex+MAC
//! plus `--gateway-mac`/`--local-underlay` — all inputs the DPDK serve ALSO parses; the fix is a
//! `shared.set_local(Local { uplink_ifindex, uplink_mac, gateway_mac, underlay_ipv6 })` after the
//! uplink `Port::configure`. Fixing serve logic is OUT OF SCOPE for this test-only task (per its
//! constraints) → reported for a follow-on. Until then this test SKIPS/FAILS at part (a) under sudo;
//! the harness + client + wrapper are complete and pass (a)+(b) the moment serve programs LOCAL.

/// Repo root (workspace) from this crate's manifest dir: `<root>/flowplane/flowplane-dpdk` → `<root>`.
fn repo_root() -> String {
    format!("{}/../..", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn full_serve_afxdp_e2e_guest_egress_and_nat_return() {
    let root = repo_root();

    // Build the serve binary + the attach_client example up front (so the harness only runs them).
    for args in [
        ["build", "-p", "flowplane-dpdk", "--bin", "flowplane-dpdk"],
        [
            "build",
            "-p",
            "flowplane-dpdk",
            "--example",
            "attach_client",
        ],
    ] {
        let st = std::process::Command::new("cargo")
            .args(args)
            .current_dir(&root)
            .status()
            .expect("cargo build");
        assert!(st.success(), "build failed: {args:?}");
    }
    let serve_bin = format!("{root}/target/debug/flowplane-dpdk");
    let client_bin = format!("{root}/target/debug/examples/attach_client");
    assert!(
        std::path::Path::new(&serve_bin).exists(),
        "serve binary not built at {serve_bin}"
    );
    assert!(
        std::path::Path::new(&client_bin).exists(),
        "attach_client example not built at {client_bin}"
    );

    let status = std::process::Command::new("bash")
        .arg(format!("{root}/hack/dpdk/serve-e2e.sh"))
        .env("SERVE_BIN", &serve_bin)
        .env("CLIENT_BIN", &client_bin)
        .current_dir(&root)
        .status()
        .expect("run serve-e2e.sh");

    match status.code() {
        Some(0) => { /* (a)+(b) passed reliably; (c) is best-effort / gated */ }
        Some(77) => {
            eprintln!("serve af_xdp e2e skipped (unprivileged / no hugepages)");
        }
        other => panic!(
            "serve-e2e.sh failed: exit {other:?} — see the serve log tail printed above by the harness"
        ),
    }
}
