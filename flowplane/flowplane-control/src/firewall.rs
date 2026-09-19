//! Per-interface firewall rule programming (`FW_RULES`/`FW_META`), backend-agnostic core.
//!
//! Moved verbatim out of the eBPF `Control` (control/firewall.rs), applying the MapWriter transform:
//! `g.by_ifindex.get(id)` -> `self.ifaces_meta.get(id).map(|m| m.ifindex)`, `g.fw` -> `self.fw`,
//! `g.fw_rules.remove/upsert` -> `self.w.fw_rules_remove/fw_rules_upsert`, and `g.fw_meta.upsert`
//! -> `self.w.fw_meta_upsert`.

use core::fmt;

use crate::{ControlCore, MapWriter};
use flowplane_common::{FwMeta, FwRule, FwRule6, FwRuleKey, FW_DIR_EGRESS, FW_MAX_RULES};

/// A firewall programming failure, classified so the gRPC layer can return a meaningful status:
/// an unknown interface, a rule-budget overflow and a duplicate rule id are client errors that a
/// retry cannot fix, unlike a failed map write.
#[derive(Debug)]
pub enum FwError {
    /// No interface with this id is attached on this node.
    UnknownInterface,
    /// One family's rule list exceeds the per-interface budget (`FW_MAX_RULES`, shared by ingress
    /// and egress).
    TooManyRules { family: &'static str, count: usize },
    /// A rule with this id is already installed (the imperative `add_fw_rule*` path only).
    AlreadyExists,
    /// The rule uses a match the classifier cannot express (e.g. the interface's own address).
    Unsupported(&'static str),
    /// A direction's rules compile into more classes or policy entries than a scope may hold.
    ScopeTooLarge {
        family: &'static str,
        what: &'static str,
        count: usize,
    },
    /// Programming the maps failed.
    Map(anyhow::Error),
}

impl fmt::Display for FwError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The "NO_VM:" / "ALREADY_EXISTS:" prefixes predate this type; callers grep for them.
            FwError::UnknownInterface => f.write_str("NO_VM: unknown interface"),
            FwError::TooManyRules { family, count } => write!(
                f,
                "too many {family} firewall rules for interface: {count} (max {FW_MAX_RULES} per family)"
            ),
            FwError::AlreadyExists => f.write_str("ALREADY_EXISTS: firewall rule already exists"),
            FwError::Unsupported(what) => write!(f, "firewall rules cannot express {what}"),
            FwError::ScopeTooLarge {
                family,
                what,
                count,
            } => write!(
                f,
                "{family} firewall rules compile to {count} {what}, over the per-direction limit"
            ),
            FwError::Map(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for FwError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FwError::Map(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for FwError {
    fn from(e: anyhow::Error) -> Self {
        FwError::Map(e)
    }
}

fn check_budget(family: &'static str, count: usize) -> Result<(), FwError> {
    if count > FW_MAX_RULES as usize {
        return Err(FwError::TooManyRules { family, count });
    }
    Ok(())
}

impl<W: MapWriter> ControlCore<W> {
    /// Drop the firewall rule shadow for a detaching interface's ifindex (the discarded rules'
    /// map slots are torn down with the interface). Matches the former `Inner.fw.remove(&tap)`.
    pub fn remove_fw_rules(&mut self, ifindex: u32) {
        self.fw.remove(&ifindex);
        self.fw6.remove(&ifindex);
    }

    fn fw_ifindex(&self, interface_id: &[u8]) -> Result<u32, FwError> {
        self.ifaces_meta
            .get(interface_id)
            .map(|m| m.ifindex)
            .ok_or(FwError::UnknownInterface)
    }

    /// Replace an interface's WHOLE firewall, both families, or nothing: the interface and both
    /// families' budgets are checked before either family's maps are touched, so a refusal never
    /// leaves the interface on half of the new policy. (A map write failing midway can still split
    /// the families; closing that needs the atomic inner-map swap of the classifier redesign.)
    pub fn replace_interface_fw(
        &mut self,
        interface_id: &[u8],
        v4: Vec<(Vec<u8>, FwRule)>,
        v6: Vec<(Vec<u8>, FwRule6)>,
    ) -> Result<(), FwError> {
        self.fw_ifindex(interface_id)?;
        check_budget("IPv4", v4.len())?;
        check_budget("IPv6", v6.len())?;
        self.replace_fw_rules(interface_id, v4)?;
        self.replace_fw_rules6(interface_id, v6)
    }

    /// Replace ALL v4 firewall rules for an interface with `rules` (both directions), clearing any
    /// prior rules/slots. Declarative + restart-safe: callers push the complete desired set each
    /// reconcile, so a stale rule can never survive. `rules` is slot-ordered (idx = position).
    pub fn replace_fw_rules(
        &mut self,
        interface_id: &[u8],
        rules: Vec<(Vec<u8>, FwRule)>,
    ) -> Result<(), FwError> {
        let ifindex = self.fw_ifindex(interface_id)?;
        check_budget("IPv4", rules.len())?;
        self.fw.insert(ifindex, rules);
        Ok(self.fw_reprogram(ifindex)?)
    }

    /// Replace ALL v6 firewall rules for an interface with `rules` (both directions), clearing any
    /// prior rules/slots. v6 counterpart of [`replace_fw_rules`].
    pub fn replace_fw_rules6(
        &mut self,
        interface_id: &[u8],
        rules: Vec<(Vec<u8>, FwRule6)>,
    ) -> Result<(), FwError> {
        let ifindex = self.fw_ifindex(interface_id)?;
        check_budget("IPv6", rules.len())?;
        self.fw6.insert(ifindex, rules);
        Ok(self.fw6_reprogram(ifindex)?)
    }

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
    ) -> Result<(), FwError> {
        let ifindex = self.fw_ifindex(interface_id)?;
        let entry = self.fw.entry(ifindex).or_default();
        check_budget("IPv4", entry.len() + 1)?;
        // Reject duplicate rule IDs.
        if entry.iter().any(|(id, _)| id == &rule_id) {
            return Err(FwError::AlreadyExists);
        }
        entry.push((rule_id, rule));
        Ok(self.fw_reprogram(ifindex)?)
    }

    /// Remove a firewall rule by id from an interface. Tries the v4 shadow first, then v6.
    /// Returns true if removed, false if not found.
    pub fn del_fw_rule(&mut self, interface_id: &[u8], rule_id: &[u8]) -> Result<bool, FwError> {
        if self.del_fw_rule_v4(interface_id, rule_id)? {
            return Ok(true);
        }
        self.del_fw_rule6(interface_id, rule_id)
    }

    /// Remove a v4 firewall rule by id from an interface.
    /// Returns true if removed, false if not found.
    fn del_fw_rule_v4(&mut self, interface_id: &[u8], rule_id: &[u8]) -> Result<bool, FwError> {
        let ifindex = self.fw_ifindex(interface_id)?;
        let entry = self.fw.entry(ifindex).or_default();
        let before = entry.len();
        entry.retain(|(id, _)| id.as_slice() != rule_id);
        if entry.len() == before {
            return Ok(false);
        }
        self.fw_reprogram(ifindex)?;
        Ok(true)
    }

    /// Reprogram all v6 firewall slots for one interface from the in-memory `fw6` vec.
    fn fw6_reprogram(&mut self, ifindex: u32) -> anyhow::Result<()> {
        let rules = self.fw6.get(&ifindex).cloned().unwrap_or_default();
        // Clear all slots.
        for idx in 0..FW_MAX_RULES {
            let _ = self.w.fw_rules6_remove(&FwRuleKey { ifindex, idx });
        }
        let mut ingress = 0u32;
        let mut egress = 0u32;
        for (i, (_id, r)) in rules.iter().enumerate() {
            self.w.fw_rules6_upsert(
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
        self.w.fw_meta6_upsert(
            ifindex,
            FwMeta {
                ingress_count: ingress,
                egress_count: egress,
            },
        )?;
        Ok(())
    }

    /// Add or replace a v6 firewall rule on an interface.
    /// Returns an error with "already exists" if a rule with that ID already exists.
    pub fn add_fw_rule6(
        &mut self,
        interface_id: &[u8],
        rule_id: Vec<u8>,
        rule: FwRule6,
    ) -> Result<(), FwError> {
        let ifindex = self.fw_ifindex(interface_id)?;
        let entry = self.fw6.entry(ifindex).or_default();
        check_budget("IPv6", entry.len() + 1)?;
        // Reject duplicate rule IDs.
        if entry.iter().any(|(id, _)| id == &rule_id) {
            return Err(FwError::AlreadyExists);
        }
        entry.push((rule_id, rule));
        Ok(self.fw6_reprogram(ifindex)?)
    }

    /// Remove a v6 firewall rule by id from an interface.
    /// Returns true if removed, false if not found.
    fn del_fw_rule6(&mut self, interface_id: &[u8], rule_id: &[u8]) -> Result<bool, FwError> {
        let ifindex = self.fw_ifindex(interface_id)?;
        let entry = self.fw6.entry(ifindex).or_default();
        let before = entry.len();
        entry.retain(|(id, _)| id.as_slice() != rule_id);
        if entry.len() == before {
            return Ok(false);
        }
        self.fw6_reprogram(ifindex)?;
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
    fn add_fw_rule6_programs_rules6_and_meta6() {
        use flowplane_common::{FwRule6, FW_ACTION_ACCEPT, FW_DIR_INGRESS};
        let mut c = ControlCore::new(MemMapWriter::default());
        let ifindex = 42u32;
        c.register_iface_meta(
            b"if0".to_vec(),
            IfaceMeta {
                vni: 5,
                ipv4: [10, 0, 0, 2],
                ipv6: [0u8; 16],
                underlay: [1u8; 16],
                ifindex,
            },
        );

        let r6 = FwRule6 {
            src_ip: [0; 16],
            src_mask: [0; 16],
            dst_ip: [0; 16],
            dst_mask: [0; 16],
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 0,
            dst_port_max: 65535,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            proto: 0,
            action: FW_ACTION_ACCEPT,
            direction: FW_DIR_INGRESS,
            enabled: 1,
        };
        c.add_fw_rule6(b"if0", b"r1".to_vec(), r6).unwrap();

        // Slot 0 written to FW_RULES6; FW_META6 reflects the ingress count.
        assert!(c.w.fw_rules6.contains_key(&FwRuleKey { ifindex, idx: 0 }));
        let meta = c.w.fw_meta6.get(&ifindex).unwrap();
        assert_eq!(meta.ingress_count, 1);
        assert_eq!(meta.egress_count, 0);

        // Duplicate rule-id rejected.
        assert!(c.add_fw_rule6(b"if0", b"r1".to_vec(), r6).is_err());

        // del_fw_rule (v4-first, then v6) removes the v6 rule and drops the count.
        assert!(c.del_fw_rule(b"if0", b"r1").unwrap());
        assert!(!c.w.fw_rules6.contains_key(&FwRuleKey { ifindex, idx: 0 }));
        let meta = c.w.fw_meta6.get(&ifindex).unwrap();
        assert_eq!(meta.ingress_count, 0);
        assert_eq!(meta.egress_count, 0);

        // Deleting a non-existent rule returns false (misses both v4 and v6).
        assert!(!c.del_fw_rule(b"if0", b"nope").unwrap());
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

    #[test]
    fn replace_fw_rules_clears_stale_slots_on_shrink() {
        use flowplane_common::FW_DIR_INGRESS;
        let mut c = ControlCore::new(MemMapWriter::default());
        let ifindex = 9u32;
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
        // Start with two rules at slots 0,1.
        c.replace_fw_rules(
            b"if1",
            vec![
                (b"a".to_vec(), rule(FW_DIR_INGRESS)),
                (b"b".to_vec(), rule(FW_DIR_INGRESS)),
            ],
        )
        .unwrap();
        assert!(c.w.fw_rules.contains_key(&FwRuleKey { ifindex, idx: 1 }));
        // Replace with ONE rule: slot 1 must be cleared, meta ingress_count == 1.
        c.replace_fw_rules(b"if1", vec![(b"a".to_vec(), rule(FW_DIR_INGRESS))])
            .unwrap();
        assert!(c.w.fw_rules.contains_key(&FwRuleKey { ifindex, idx: 0 }));
        assert!(!c.w.fw_rules.contains_key(&FwRuleKey { ifindex, idx: 1 }));
        assert_eq!(c.w.fw_meta.get(&ifindex).unwrap().ingress_count, 1);
    }

    #[test]
    fn replace_fw_rules_overwrites_same_id_content_and_empty_clears() {
        use flowplane_common::{FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_INGRESS};
        let mut c = ControlCore::new(MemMapWriter::default());
        let ifindex = 11u32;
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
        let deny = FwRule {
            direction: FW_DIR_INGRESS,
            action: FW_ACTION_DROP,
            ..Default::default()
        };
        let allow = FwRule {
            direction: FW_DIR_INGRESS,
            action: FW_ACTION_ACCEPT,
            ..Default::default()
        };
        // Program a deny at rule-id "fw-in-0".
        c.replace_fw_rules(b"if1", vec![(b"fw-in-0".to_vec(), deny)])
            .unwrap();
        assert_eq!(
            c.w.fw_rules
                .get(&FwRuleKey { ifindex, idx: 0 })
                .unwrap()
                .action,
            FW_ACTION_DROP
        );
        // Replace the SAME id with an allow: slot 0 now holds accept (no ALREADY_EXISTS rejection).
        c.replace_fw_rules(b"if1", vec![(b"fw-in-0".to_vec(), allow)])
            .unwrap();
        assert_eq!(
            c.w.fw_rules
                .get(&FwRuleKey { ifindex, idx: 0 })
                .unwrap()
                .action,
            FW_ACTION_ACCEPT
        );
        // Empty replace clears the interface: no slot, meta counts zero.
        c.replace_fw_rules(b"if1", vec![]).unwrap();
        assert!(!c.w.fw_rules.contains_key(&FwRuleKey { ifindex, idx: 0 }));
        assert_eq!(c.w.fw_meta.get(&ifindex).unwrap().ingress_count, 0);
    }
}
