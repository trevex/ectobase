//! DpdkMapWriter::meter_upsert seeds the shared meter-config table. Needs EAL (--no-huge). Its own
//! test binary → own process → own EAL init. Run with `--ignored`.
#![cfg(test)]

use std::sync::Arc;

use flowplane_common::{MeterConfig, MeterState};
use flowplane_control::MapWriter;
use flowplane_dpdk::writer::DpdkMapWriter;
use nfkit::{Eal, SharedConfigMaps};

#[test]
#[ignore = "requires EAL --no-huge"]
fn meter_upsert_seeds_shared_config() {
    let _eal = Eal::init([
        "fp-dpdk-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "fp_meter_wr",
    ])
    .expect("EAL init");

    let shared = Arc::new(SharedConfigMaps::new(0, 1024).expect("shared config"));
    let mut writer = DpdkMapWriter::new(shared.clone());
    // A full MeterState as ConfigureQoS would deliver it (state fields are irrelevant to config).
    let state = MeterState {
        total_bps: 10,
        total_burst: 20,
        total_tokens: 7,
        total_last_ns: 7,
        public_bps: 30,
        public_burst: 40,
        public_tokens: 7,
        public_last_ns: 7,
        ingress_bps: 50,
        ingress_burst: 60,
        ingress_tokens: 7,
        ingress_last_ns: 7,
    };
    writer.meter_upsert(9, state).expect("meter_upsert");
    assert_eq!(
        shared.meter_config_get(9),
        Some(MeterConfig::from_state(&state)),
        "meter_upsert wrote the rate config into the shared table"
    );
    writer.meter_remove(&9).expect("meter_remove");
    assert_eq!(
        shared.meter_config_get(9),
        None,
        "meter_remove cleared the shared config"
    );
}
