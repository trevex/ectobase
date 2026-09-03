//! Verifier load check for the tcx overlay-ingress programs (`uplink_rx`, `xdp_uplink_v6`,
//! `wan_rx`) — P2 Task 4b converted all three from XDP to `#[classifier]` (tcx), wired `uplink_rx`
//! to `flowplane_core::datapath::process_uplink_rx` (VNI sourced from `get_tunnel_key`, no more
//! `UNDERLAY[outer_dst]`), and `wan_rx` to `process_wan_rx`.
//!
//! This file used to load only `wan_rx` as XDP (checking the `UPLINK_DEV` devmap-redirect path,
//! since removed along with the rest of the custom XDP encap scaffolding — see `xdp_encap.rs`'s
//! deletion). It now loads all three tcx ingress programs: `anchor_uplink`/`anchor_lb`/`anchor_dnat`
//! (Task 7) still call the pre-4a `SimNode` signatures and don't compile, so this is currently the
//! ONLY thing that proves `uplink_rx` (the real fabric-ingress hot path, now calling the shared core
//! orchestrator for the first time from actual eBPF bytecode) passes the kernel verifier.
//!
//! Privileged: needs CAP_BPF + a kernel with tc BPF. Run via `sudo -E cargo test -p flowplane --test
//! verify_edge_wan_rx -- --ignored`.

use aya::programs::SchedClassifier;

#[test]
#[ignore = "requires root/CAP_BPF and a kernel with tc BPF"]
fn tcx_overlay_ingress_programs_verify() {
    // Load the real compiled eBPF object the same way the daemon (and the other anchors) do.
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flowplane-prog"));
    // The state maps are declared `pinned`, so the loader needs a bpffs `map_pin_path`.
    let pin = tempfile::Builder::new()
        .prefix("flowplane-verify-wan-rx-")
        .tempdir_in("/sys/fs/bpf")
        .expect("bpffs tempdir");
    let mut ebpf = aya::EbpfLoader::new()
        .map_pin_path(pin.path())
        .load(bytes)
        .expect("load compiled eBPF object (creates all maps)");

    // Load (= verify) each tcx overlay-ingress program into the kernel. Loading verifies the
    // instructions regardless of map contents, so no map population is needed. `uplink_rx` calling
    // into `flowplane_core::datapath::process_uplink_rx` (LB/firewall/conntrack/decap/meter, plus
    // the `ingress.rs::try_nat64_ingress` peek) is the stack-depth/complexity risk this checkpoint
    // exists to catch; `xdp_uplink_v6` and `wan_rx` are simpler but must verify too (no XDP left in
    // the overlay ingress/WAN-return path).
    for name in ["uplink_rx", "xdp_uplink_v6", "wan_rx"] {
        let prog: &mut SchedClassifier = ebpf
            .program_mut(name)
            .unwrap_or_else(|| panic!("{name} program present"))
            .try_into()
            .unwrap_or_else(|_| panic!("{name} is a SchedClassifier (tcx) program"));
        prog.load()
            .unwrap_or_else(|e| panic!("verify/load {name} (must pass the verifier): {e}"));
    }
}
