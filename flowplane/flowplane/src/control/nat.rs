//! NAT programming — delegated entirely to `ControlCore` via `Control::with_core`.
//! The thin `Control` wrapper methods have been removed in Task 5 of the shared-node-seam
//! refactor; `node.rs` now calls `flowplane_node::{add_nat_source, withdraw_nat_source,
//! add_neighbor_nat, withdraw_neighbor_nat}` directly through `with_core`. This file is kept
//! as a placeholder for any future eBPF-specific NAT helpers.
