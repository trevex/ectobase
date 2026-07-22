//! Backend-agnostic control-plane programming shared by the eBPF and DPDK dataplanes.
#[cfg(feature = "mem-writer")]
pub mod mem;
pub mod writer;

pub use writer::{CtFlushScope, MapWriter};
