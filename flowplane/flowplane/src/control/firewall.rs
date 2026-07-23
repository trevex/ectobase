//! Per-interface firewall rule programming (`FW_RULES`/`FW_META`).
//!
//! The programming logic moved into the backend-agnostic `flowplane-control`
//! `ControlCore` (Task 6); these are thin delegations that keep the `Control`
//! signatures (so `node.rs` is untouched) and take the inner lock.

use flowplane_common::FwRule;

use super::Control;

impl Control {
    /// Add or replace a firewall rule on an interface.
    /// Returns an error with "already exists" if a rule with that ID already exists.
    pub fn add_fw_rule(
        &self,
        interface_id: &[u8],
        rule_id: Vec<u8>,
        rule: FwRule,
    ) -> anyhow::Result<()> {
        self.inner
            .lock()
            .core
            .add_fw_rule(interface_id, rule_id, rule)
    }

    /// Remove a firewall rule by id from an interface.
    /// Returns true if removed, false if not found.
    pub fn del_fw_rule(&self, interface_id: &[u8], rule_id: &[u8]) -> anyhow::Result<bool> {
        self.inner.lock().core.del_fw_rule(interface_id, rule_id)
    }
}
