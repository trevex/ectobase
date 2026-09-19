//! NAT programming — delegated entirely to the backend-agnostic `ControlCore` via
//! `Control::with_core`: `node.rs` calls `handlers::{add_nat_source, withdraw_nat_source,
//! add_neighbor_nat, withdraw_neighbor_nat}`, and `bring_up` rebuilds the neighbor-NAT blocks from
//! the pinned `NAT_OWNERS{,6}` tries with `ControlCore::adopt_nat_owners`. The eBPF backend's part
//! is the map handles `AyaWriter` owns. This file is kept as a placeholder for any future
//! eBPF-specific NAT helpers.
