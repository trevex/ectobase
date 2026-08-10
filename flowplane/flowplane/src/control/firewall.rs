//! Per-interface firewall rule programming — delegated entirely to `ControlCore` via
//! `Control::with_core`. The thin `Control` wrapper methods were removed when firewall
//! programming moved into the backend-agnostic `ControlCore`; `node.rs` now calls `flowplane_node::add_fw_rule` /
//! `del_fw_rule` directly through `with_core`. This file is kept as a placeholder for any
//! future eBPF-specific firewall helpers.
