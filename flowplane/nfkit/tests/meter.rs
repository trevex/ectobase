//! Functional QoS/meter over the DPDK shared-config + per-lcore compose path. EAL inits once, so
//! this is ONE `#[test]` built up in sections. Run with `--ignored --test-threads=1`.
#![cfg(test)]

use flowplane_common::MeterConfig;
use nfkit::{Eal, SharedConfigMaps};

#[test]
#[ignore = "requires EAL --no-huge"]
fn meter_config_and_policing() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_meter",
    ])
    .expect("EAL init");

    // ── (1) Shared meter-config table round-trip ──────────────────────────────
    let shared = SharedConfigMaps::new(0, 1024).expect("shared config");
    let cfg = MeterConfig {
        total_bps: 100,
        total_burst: 200,
        public_bps: 300,
        public_burst: 400,
        ingress_bps: 500,
        ingress_burst: 600,
    };
    assert_eq!(shared.meter_config_get(7), None, "(1) empty before insert");
    assert!(shared.meter_config_insert(7, cfg), "(1) insert ok");
    assert_eq!(
        shared.meter_config_get(7),
        Some(cfg),
        "(1) get returns the inserted config"
    );
    assert!(
        shared.meter_config_remove(7),
        "(1) remove returns true when present"
    );
    assert_eq!(shared.meter_config_get(7), None, "(1) gone after remove");
    // Section (2) — functional policing — is appended in Task 4.
}
