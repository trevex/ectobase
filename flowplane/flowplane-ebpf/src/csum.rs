//! Re-export the host-tested incremental checksum helpers for use in XDP programs. Both
//! `csum_replace4` and `csum_replace2` are single-sourced in `flowplane_common::csum`.
pub use flowplane_common::csum::{csum_replace2, csum_replace4};
