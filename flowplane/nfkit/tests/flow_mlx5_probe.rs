// Unprivileged mlx5 rte_flow offload probe → software-fallback proof. On a real mlx5 NIC,
// `probe_raw_flow_offload(port)` returns true and the datapath programs RAW_DECAP/ENCAP (the IPIP
// hot path offloaded to the eSwitch), so `offload_mode` == `HwRawFlow`. Here we init EAL on a
// NON-mlx5 backend (net_null), so the driver-name gate (and/or RAW validate) fails and the probe
// returns false → `offload_mode` == `Software`. That means NOTHING is programmed: the software
// datapath (`process_uplink`/`process_guest_tx`) handles the traffic. This proves the conditional
// gate and graceful fallback on hardware that can't offload — no unconditional offload. --test-threads=1.
use nfkit::{offload_mode, probe_raw_flow_offload, Backend, Eal, Mempool, OffloadMode, Port};

#[test]
fn mlx5_probe_false_on_non_mlx5_yields_software_fallback() {
    // Build the EAL argv from the Null backend (non-mlx5, no hugepages), plus a unique file-prefix
    // (each test binary is its own process; EAL is process-global and inits at most once).
    let mut args = Backend::Null.eal_args("nfkit-flow-mlx5-probe");
    args.push("--file-prefix".into());
    args.push("nfkit_flow_mlx5_probe".into());
    let _eal = Eal::init(args).expect("EAL init");

    let pool = Mempool::new("flow_mlx5_probe_pool", 1023, 250, 0).expect("pool");
    let _port = Port::configure(0, 1, &pool).expect("configure port 0");

    // The decisive gate: net_null is not an mlx5 driver (and has no RAW_DECAP/ENCAP flow support),
    // so the probe must return false. On a real ConnectX (mlx5) NIC this same call returns true.
    let offload = probe_raw_flow_offload(0);
    eprintln!("probe_raw_flow_offload(0) = {offload} (expect false on net_null)");
    assert!(
        !offload,
        "net_null is not mlx5 → probe must be false (no HW RAW offload)"
    );

    // Therefore the datapath's offload decision is the software fallback — nothing is programmed.
    let mode = offload_mode(0);
    eprintln!("offload_mode(0) = {mode:?} (expect Software)");
    assert_eq!(
        mode,
        OffloadMode::Software,
        "non-mlx5 probe false → Software fallback (process_uplink/process_guest_tx handle traffic)"
    );
}
