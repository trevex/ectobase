//! Route programming — delegated entirely to `ControlCore` via `Control::with_core`.
//! The thin `Control` wrapper methods were removed when route programming moved into the
//! backend-agnostic `ControlCore`; `node.rs` now calls `handlers::{add_route, withdraw_route}` directly through
//! `with_core`. This file is kept as a placeholder for any future eBPF-specific route helpers.
