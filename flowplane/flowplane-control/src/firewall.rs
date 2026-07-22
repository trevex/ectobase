//! Per-interface firewall rule programming (`FW_RULES`/`FW_META`), backend-agnostic core.
//!
//! Moved verbatim out of the eBPF `Control` (control/firewall.rs), applying the MapWriter transform:
//! `g.by_ifindex.get(id)` -> `self.ifaces_meta.get(id).map(|m| m.ifindex)`, `g.fw` -> `self.fw`,
//! `g.fw_rules.remove/upsert` -> `self.w.fw_rules_remove/fw_rules_upsert`, and `g.fw_meta.upsert`
//! -> `self.w.fw_meta_upsert`.

use crate::{ControlCore, MapWriter};
use flowplane_common::{FwMeta, FwRule, FwRuleKey, FW_DIR_EGRESS, FW_MAX_RULES};

impl<W: MapWriter> ControlCore<W> {
    /// Reprogram all firewall slots for one interface from the in-memory `fw` vec.
    fn fw_reprogram(&mut self, ifindex: u32) -> anyhow::Result<()> {
        let rules = self.fw.get(&ifindex).cloned().unwrap_or_default();
        // Clear all slots.
        for idx in 0..FW_MAX_RULES {
            let _ = self.w.fw_rules_remove(&FwRuleKey { ifindex, idx });
        }
        let mut ingress = 0u32;
        let mut egress = 0u32;
        for (i, (_id, r)) in rules.iter().enumerate() {
            self.w.fw_rules_upsert(
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
        self.w.fw_meta_upsert(
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
        &mut self,
        interface_id: &[u8],
        rule_id: Vec<u8>,
        rule: FwRule,
    ) -> anyhow::Result<()> {
        let ifindex = self
            .ifaces_meta
            .get(interface_id)
            .map(|m| m.ifindex)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let entry = self.fw.entry(ifindex).or_default();
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
        self.fw_reprogram(ifindex)
    }

    /// Remove a firewall rule by id from an interface.
    /// Returns true if removed, false if not found.
    pub fn del_fw_rule(&mut self, interface_id: &[u8], rule_id: &[u8]) -> anyhow::Result<bool> {
        let ifindex = self
            .ifaces_meta
            .get(interface_id)
            .map(|m| m.ifindex)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let entry = self.fw.entry(ifindex).or_default();
        let before = entry.len();
        entry.retain(|(id, _)| id.as_slice() != rule_id);
        if entry.len() == before {
            return Ok(false);
        }
        self.fw_reprogram(ifindex)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::{mem::MemMapWriter, shadow::IfaceMeta, ControlCore};
    use flowplane_common::{FwRule, FwRuleKey, FW_DIR_EGRESS, FW_MAX_RULES};

    fn rule(direction: u8) -> FwRule {
        FwRule {
            direction,
            ..Default::default()
        }
    }

    #[test]
    fn add_and_del_fw_rule_programs_slots_and_rejects_dupes() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let ifindex = 42u32;
        c.register_iface_meta(
            b"if1".to_vec(),
            IfaceMeta {
                vni: 5,
                ipv4: [10, 0, 0, 2],
                ipv6: [0u8; 16],
                underlay: [1u8; 16],
                ifindex,
            },
        );

        // Add two rules (one ingress, one egress).
        c.add_fw_rule(b"if1", b"r0".to_vec(), rule(0)).unwrap();
        c.add_fw_rule(b"if1", b"r1".to_vec(), rule(FW_DIR_EGRESS))
            .unwrap();

        // Two slots written; FW_META reflects the per-direction counts.
        assert!(c.w.fw_rules.contains_key(&FwRuleKey { ifindex, idx: 0 }));
        assert!(c.w.fw_rules.contains_key(&FwRuleKey { ifindex, idx: 1 }));
        let meta = c.w.fw_meta.get(&ifindex).unwrap();
        assert_eq!(meta.ingress_count, 1);
        assert_eq!(meta.egress_count, 1);

        // Duplicate rule-id rejected.
        assert!(c.add_fw_rule(b"if1", b"r0".to_vec(), rule(0)).is_err());

        // Delete one: only slot 0 remains, meta updated.
        assert!(c.del_fw_rule(b"if1", b"r0").unwrap());
        assert!(c.w.fw_rules.contains_key(&FwRuleKey { ifindex, idx: 0 }));
        assert!(!c.w.fw_rules.contains_key(&FwRuleKey { ifindex, idx: 1 }));
        let meta = c.w.fw_meta.get(&ifindex).unwrap();
        assert_eq!(meta.ingress_count, 0);
        assert_eq!(meta.egress_count, 1);

        // Deleting a non-existent rule returns false.
        assert!(!c.del_fw_rule(b"if1", b"nope").unwrap());

        // Unknown interface errors.
        assert!(c.add_fw_rule(b"nope", b"x".to_vec(), rule(0)).is_err());
    }

    #[test]
    fn fw_rules_capped_at_max() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let ifindex = 7u32;
        c.register_iface_meta(
            b"if1".to_vec(),
            IfaceMeta {
                vni: 1,
                ipv4: [10, 0, 0, 1],
                ipv6: [0u8; 16],
                underlay: [1u8; 16],
                ifindex,
            },
        );
        for i in 0..FW_MAX_RULES {
            c.add_fw_rule(b"if1", format!("r{i}").into_bytes(), rule(0))
                .unwrap();
        }
        // One over the cap is rejected.
        assert!(c
            .add_fw_rule(b"if1", b"overflow".to_vec(), rule(0))
            .is_err());
    }
}
