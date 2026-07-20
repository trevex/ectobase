//! nfkit — a safe, zero-cost DPDK network-function substrate. Milestone 1: EAL lifecycle only.
mod eal;
pub use eal::{Eal, EalError};
