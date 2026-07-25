//! Route programming — delegated entirely to `ControlCore` via `Control::with_core`.
//! The thin `Control` wrapper methods have been removed in Task 5 of the shared-node-seam
//! refactor; `node.rs` now calls `flowplane_node::{add_route, withdraw_route}` directly through
//! `with_core`. This file is kept as a placeholder for any future eBPF-specific route helpers.
