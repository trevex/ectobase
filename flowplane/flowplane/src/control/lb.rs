//! Load-balancer programming — delegated entirely to `ControlCore` via `Control::with_core`.
//! The thin `Control` wrapper methods were removed when LB programming moved into the
//! backend-agnostic `ControlCore`; `node.rs` now calls `handlers::{add_load_balancer, add_lb_backend, del_load_balancer,
//! del_lb_backend}` directly through `with_core`. This file is kept as a placeholder for any
//! future eBPF-specific LB helpers.
