//! `flowplane-dpdk` — the DPDK serve-binary crate.
//!
//! The DPDK sibling of the eBPF `flowplane` binary: it runs the SAME `flowplane_control::ControlCore`
//! orchestration, but programs `nfkit::shared_config::SharedConfigMaps` (LF+RCU DPDK config tables)
//! instead of eBPF aya maps. The seam is [`writer::DpdkMapWriter`], the DPDK `MapWriter`
//! implementation — the counterpart to the eBPF `AyaWriter`.
pub mod serve;
pub mod writer;
