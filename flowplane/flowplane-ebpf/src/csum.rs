//! Re-export the host-tested incremental checksum helper for use in XDP programs. `csum_replace4`
//! is single-sourced in `flowplane_common::csum`. (`csum_replace2` is now used only inside the
//! shared `flowplane_core` conntrack/NAT rewriters, so it is no longer re-exported here.)
pub use flowplane_common::csum::csum_replace4;
