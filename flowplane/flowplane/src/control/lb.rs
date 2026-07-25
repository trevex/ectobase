//! Load-balancer programming — delegated entirely to `ControlCore` via `Control::with_core`.
//! The thin `Control` wrapper methods have been removed in Task 5 of the shared-node-seam
//! refactor; `node.rs` now calls `flowplane_node::{add_lb_vip, add_lb_backend, del_lb_vip,
//! del_lb_backend}` directly through `with_core`. This file is kept as a placeholder for any
//! future eBPF-specific LB helpers.
