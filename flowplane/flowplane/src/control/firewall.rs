//! Per-interface firewall rule programming (`FW_RULES`/`FW_META`).
//!
//! Split out of `control.rs`; a child module of `control`, so it reaches
//! `Inner`'s private fields via `super`. Pure code movement — no logic changes.

use flowplane_common::{FwMeta, FwRule, FwRuleKey, FW_DIR_EGRESS, FW_MAX_RULES};

use super::{Control, Inner};

impl Control {
    // -----------------------------------------------------------------------
    // Firewall rule management
    // -----------------------------------------------------------------------

    /// Reprogram all firewall slots for one interface from the in-memory `fw` vec.
    fn fw_reprogram(g: &mut Inner, ifindex: u32) -> anyhow::Result<()> {
        let rules = g.fw.get(&ifindex).cloned().unwrap_or_default();
        // Clear all slots.
        for idx in 0..FW_MAX_RULES {
            let _ = g.fw_rules.remove(&FwRuleKey { ifindex, idx });
        }
        let mut ingress = 0u32;
        let mut egress = 0u32;
        for (i, (_id, r)) in rules.iter().enumerate() {
            g.fw_rules.upsert(
                FwRuleKey {
                    ifindex,
                    idx: i as u32,
                },
                *r,
            )?;
            if r.direction == FW_DIR_EGRESS {
                egress += 1;
            } else {
                ingress += 1;
            }
        }
        g.fw_meta.upsert(
            ifindex,
            FwMeta {
                ingress_count: ingress,
                egress_count: egress,
            },
        )?;
        Ok(())
    }

    /// Add or replace a firewall rule on an interface.
    /// Returns an error with "already exists" if a rule with that ID already exists.
    pub fn add_fw_rule(
        &self,
        interface_id: &[u8],
        rule_id: Vec<u8>,
        rule: FwRule,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        let ifindex = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let entry = g.fw.entry(ifindex).or_default();
        if entry.len() >= FW_MAX_RULES as usize {
            anyhow::bail!(
                "too many firewall rules for interface (max {})",
                FW_MAX_RULES
            );
        }
        // Reject duplicate rule IDs.
        if entry.iter().any(|(id, _)| id == &rule_id) {
            anyhow::bail!("ALREADY_EXISTS: firewall rule already exists");
        }
        entry.push((rule_id, rule));
        Self::fw_reprogram(&mut g, ifindex)
    }

    /// Remove a firewall rule by id from an interface.
    /// Returns true if removed, false if not found.
    pub fn del_fw_rule(&self, interface_id: &[u8], rule_id: &[u8]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let ifindex = *g
            .by_ifindex
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let entry = g.fw.entry(ifindex).or_default();
        let before = entry.len();
        entry.retain(|(id, _)| id.as_slice() != rule_id);
        if entry.len() == before {
            return Ok(false);
        }
        Self::fw_reprogram(&mut g, ifindex)?;
        Ok(true)
    }
}
