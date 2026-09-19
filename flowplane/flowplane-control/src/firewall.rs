//! Per-interface firewall rule programming (`FW_RULES`/`FW_META`), backend-agnostic core.
//!
//! Moved verbatim out of the eBPF `Control` (control/firewall.rs), applying the MapWriter transform:
//! `g.by_ifindex.get(id)` -> `self.ifaces_meta.get(id).map(|m| m.ifindex)`, `g.fw` -> `self.fw`,
//! `g.fw_rules.remove/upsert` -> `self.w.fw_rules_remove/fw_rules_upsert`, and `g.fw_meta.upsert`
//! -> `self.w.fw_meta_upsert`.

use core::fmt;

use crate::fwclass::{compile_scope, Scope};
use crate::{ControlCore, MapWriter};
use flowplane_common::{
    FwBind, FwMeta, FwRule, FwRule6, FwRuleKey, FW_DIR_EGRESS, FW_DIR_INGRESS, FW_MAX_RULES,
    FW_SCOPE_NONE,
};

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

/// Compile an interface's rule lists (both families, both directions mixed, first-match order) into
/// its ingress and egress scopes. Pure: fails before anything is written.
fn compile_iface<'a>(
    v4: impl Iterator<Item = &'a FwRule> + Clone,
    v6: impl Iterator<Item = &'a FwRule6> + Clone,
) -> Result<(Option<Scope>, Option<Scope>), FwError> {
    Ok((
        compile_scope(FW_DIR_INGRESS, v4.clone(), v6.clone())?,
        compile_scope(FW_DIR_EGRESS, v4, v6)?,
    ))
}

fn check_budget(family: &'static str, count: usize) -> Result<(), FwError> {
    if count > FW_MAX_RULES as usize {
        return Err(FwError::TooManyRules { family, count });
    }
    Ok(())
}

impl<W: MapWriter> ControlCore<W> {
    /// Drop the firewall state of a detaching interface's ifindex: the rule shadows, and its
    /// classifier binding — so an interface that later reuses the ifindex starts unbound (deny)
    /// instead of inheriting these rules — freeing any scope nothing else references.
    pub fn remove_fw_rules(&mut self, ifindex: u32) {
        self.fw.remove(&ifindex);
        self.fw6.remove(&ifindex);
        if let Some(old) = self.fw_binds.remove(&ifindex) {
            let _ = self.w.fw_bind_remove(ifindex);
            self.fw_release_scopes(&old);
        }
    }

    /// Point `ifindex` at the given scopes: create the ones not yet present (fully built before
    /// they are reachable), then ONE binding write cuts the interface over — both directions, both
    /// families — and bumps its policy generation, then scopes no longer referenced are deleted.
    /// An unchanged binding writes nothing. A failure before the binding write removes the scopes
    /// it created and leaves the old binding in force.
    fn fw_bind_scopes(
        &mut self,
        ifindex: u32,
        ingress: Option<Scope>,
        egress: Option<Scope>,
    ) -> Result<(), FwError> {
        let id = |s: &Option<Scope>| s.as_ref().map_or(FW_SCOPE_NONE, |s| s.id);
        let (in_id, eg_id) = (id(&ingress), id(&egress));
        let old = self.fw_binds.get(&ifindex).copied();
        if old.is_some_and(|b| (b.ingress_scope, b.egress_scope) == (in_id, eg_id)) {
            return Ok(());
        }
        let mut created = Vec::new();
        for s in [&ingress, &egress].into_iter().flatten() {
            if self.fw_scope_refs.contains_key(&s.id) || created.contains(&s.id) {
                continue;
            }
            if let Err(e) = self.w.fw_scope_create(s) {
                self.fw_discard_scopes(&created);
                return Err(e.into());
            }
            created.push(s.id);
        }
        let bind = FwBind {
            ingress_scope: in_id,
            egress_scope: eg_id,
            gen: old.map_or(0, |b| b.gen).wrapping_add(1),
            _pad: [0; 7],
        };
        if let Err(e) = self.w.fw_bind_upsert(ifindex, bind) {
            self.fw_discard_scopes(&created);
            return Err(e.into());
        }
        self.fw_binds.insert(ifindex, bind);
        for id in [in_id, eg_id] {
            if id != FW_SCOPE_NONE {
                *self.fw_scope_refs.entry(id).or_insert(0) += 1;
            }
        }
        if let Some(old) = old {
            self.fw_release_scopes(&old);
        }
        Ok(())
    }

    fn fw_discard_scopes(&mut self, ids: &[u64]) {
        for &id in ids {
            let _ = self.w.fw_scope_delete(id);
        }
    }

    /// Drop one reference per direction of a no-longer-current binding; delete scopes at zero.
    fn fw_release_scopes(&mut self, old: &FwBind) {
        for id in [old.ingress_scope, old.egress_scope] {
            if id == FW_SCOPE_NONE {
                continue;
            }
            if let Some(n) = self.fw_scope_refs.get_mut(&id) {
                *n -= 1;
                if *n == 0 {
                    self.fw_scope_refs.remove(&id);
                    let _ = self.w.fw_scope_delete(id);
                }
            }
        }
    }

    /// Recompile `ifindex`'s classifier scopes from the rule shadows and rebind.
    fn fw_reclassify(&mut self, ifindex: u32) -> Result<(), FwError> {
        let v4 = self.fw.get(&ifindex).map(Vec::as_slice).unwrap_or_default();
        let v6 = self
            .fw6
            .get(&ifindex)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let (ingress, egress) =
            compile_iface(v4.iter().map(|(_, r)| r), v6.iter().map(|(_, r)| r))?;
        self.fw_bind_scopes(ifindex, ingress, egress)
    }

    /// Adopt after a restart: the pinned `FW_BIND` entries and scopes survived but the in-memory
    /// bookkeeping did not. Rebuild the bindings and scope references from the maps, and delete
    /// scopes nothing binds (leaked by a process that died between a create and its binding).
    pub fn adopt_fw_classifier(&mut self) {
        self.fw_binds = self.w.fw_bind_entries().into_iter().collect();
        self.fw_scope_refs.clear();
        for b in self.fw_binds.values() {
            for id in [b.ingress_scope, b.egress_scope] {
                if id != FW_SCOPE_NONE {
                    *self.fw_scope_refs.entry(id).or_insert(0) += 1;
                }
            }
        }
        for id in self.w.fw_scope_ids() {
            if !self.fw_scope_refs.contains_key(&id) {
                let _ = self.w.fw_scope_delete(id);
            }
        }
    }

    fn fw_ifindex(&self, interface_id: &[u8]) -> Result<u32, FwError> {
        self.ifaces_meta
            .get(interface_id)
            .map(|m| m.ifindex)
            .ok_or(FwError::UnknownInterface)
    }

    /// Replace an interface's WHOLE firewall, both families, or nothing: the interface, both
    /// families' budgets and the classifier compile are checked before anything is written, so a
    /// refusal never leaves the interface on half of the new policy. The classifier then cuts over
    /// with one binding write. (The legacy rule slots are still written first, and a map write
    /// failing midway can still split them; they go away with the old evaluator.)
    pub fn replace_interface_fw(
        &mut self,
        interface_id: &[u8],
        v4: Vec<(Vec<u8>, FwRule)>,
        v6: Vec<(Vec<u8>, FwRule6)>,
    ) -> Result<(), FwError> {
        let ifindex = self.fw_ifindex(interface_id)?;
        check_budget("IPv4", v4.len())?;
        check_budget("IPv6", v6.len())?;
        let (ingress, egress) =
            compile_iface(v4.iter().map(|(_, r)| r), v6.iter().map(|(_, r)| r))?;
        self.replace_fw_rules(interface_id, v4)?;
        self.replace_fw_rules6(interface_id, v6)?;
        self.fw_bind_scopes(ifindex, ingress, egress)
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
        let v6 = self
            .fw6
            .get(&ifindex)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let entry = self.fw.get(&ifindex).map(Vec::as_slice).unwrap_or_default();
        compile_iface(
            entry.iter().map(|(_, r)| r).chain(core::iter::once(&rule)),
            v6.iter().map(|(_, r)| r),
        )?;
        self.fw.entry(ifindex).or_default().push((rule_id, rule));
        self.fw_reprogram(ifindex)?;
        self.fw_reclassify(ifindex)
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
        self.fw_reclassify(ifindex)?;
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
        let v4 = self.fw.get(&ifindex).map(Vec::as_slice).unwrap_or_default();
        let entry = self
            .fw6
            .get(&ifindex)
            .map(Vec::as_slice)
            .unwrap_or_default();
        compile_iface(
            v4.iter().map(|(_, r)| r),
            entry.iter().map(|(_, r)| r).chain(core::iter::once(&rule)),
        )?;
        self.fw6.entry(ifindex).or_default().push((rule_id, rule));
        self.fw6_reprogram(ifindex)?;
        self.fw_reclassify(ifindex)
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
        self.fw_reclassify(ifindex)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::{mem::MemMapWriter, shadow::IfaceMeta, ControlCore, FwError, MapWriter};
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

    // ---- classifier programming (FW_BIND + scopes) -------------------------------------------

    fn core_with(ifaces: &[(&[u8], u32)]) -> ControlCore<MemMapWriter> {
        let mut c = ControlCore::new(MemMapWriter::default());
        for &(id, ifindex) in ifaces {
            c.register_iface_meta(
                id.to_vec(),
                IfaceMeta {
                    vni: 1,
                    ipv4: [10, 0, 0, 1],
                    ipv6: [0u8; 16],
                    underlay: [1u8; 16],
                    ifindex,
                },
            );
        }
        c
    }

    /// Allow the peer 10.<net>.0.0/16: the source of an ingress rule, the destination of an egress.
    fn allow_from(net: u8, direction: u8) -> FwRule {
        let (peer, mask) = ([10, net, 0, 0], [255, 255, 0, 0]);
        let (src_ip, src_mask, dst_ip, dst_mask) = if direction == FW_DIR_EGRESS {
            ([0; 4], [0; 4], peer, mask)
        } else {
            (peer, mask, [0; 4], [0; 4])
        };
        FwRule {
            src_ip,
            src_mask,
            dst_ip,
            dst_mask,
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_max: 65535,
            icmp_type: 0xffff,
            icmp_code: 0xffff,
            action: flowplane_common::FW_ACTION_ACCEPT,
            direction,
            enabled: 1,
            ..Default::default()
        }
    }

    fn replace(
        c: &mut ControlCore<MemMapWriter>,
        id: &[u8],
        rules: &[FwRule],
    ) -> Result<(), FwError> {
        let v4 = rules.iter().map(|r| (b"r".to_vec(), *r)).collect();
        c.replace_interface_fw(id, v4, vec![])
    }

    #[test]
    fn identical_rule_sets_share_one_scope() {
        let mut c = core_with(&[(b"a", 1), (b"b", 2)]);
        replace(&mut c, b"a", &[allow_from(1, 0)]).unwrap();
        replace(&mut c, b"b", &[allow_from(1, 0)]).unwrap();
        let (a, b) = (c.w.fw_bind[&1], c.w.fw_bind[&2]);
        assert_ne!(a.ingress_scope, 0);
        assert_eq!(a.ingress_scope, b.ingress_scope, "same rules, same scope");
        assert_eq!(
            (a.egress_scope, b.egress_scope),
            (0, 0),
            "no egress rules: scope 0"
        );
        assert_eq!(c.w.fw_scopes.len(), 1);
        assert_eq!(c.w.fw_scope_creates, 1, "created once, bound twice");
    }

    #[test]
    fn a_changed_rule_set_rebinds_and_frees_the_unreferenced_scope() {
        let mut c = core_with(&[(b"a", 1), (b"b", 2)]);
        replace(&mut c, b"a", &[allow_from(1, 0)]).unwrap();
        replace(&mut c, b"b", &[allow_from(1, 0)]).unwrap();
        let shared = c.w.fw_bind[&1].ingress_scope;
        let gen = c.w.fw_bind[&1].gen;

        replace(&mut c, b"a", &[allow_from(2, 0)]).unwrap();
        let a = c.w.fw_bind[&1];
        assert_ne!(a.ingress_scope, shared);
        assert_eq!(
            a.gen,
            gen.wrapping_add(1),
            "a rebind bumps the policy generation"
        );
        assert!(
            c.w.fw_scopes.contains_key(&shared),
            "b still uses the old scope"
        );

        replace(&mut c, b"b", &[allow_from(2, 0)]).unwrap();
        assert!(
            !c.w.fw_scopes.contains_key(&shared),
            "last reference gone: scope deleted"
        );
        assert_eq!(c.w.fw_scopes.len(), 1);
    }

    #[test]
    fn an_unchanged_replace_writes_nothing() {
        let mut c = core_with(&[(b"a", 1)]);
        replace(
            &mut c,
            b"a",
            &[allow_from(1, 0), allow_from(1, FW_DIR_EGRESS)],
        )
        .unwrap();
        let (bind, creates, binds) = (c.w.fw_bind[&1], c.w.fw_scope_creates, c.w.fw_bind_writes);
        replace(
            &mut c,
            b"a",
            &[allow_from(1, 0), allow_from(1, FW_DIR_EGRESS)],
        )
        .unwrap();
        assert_eq!(c.w.fw_bind[&1], bind, "same scopes, same generation");
        assert_eq!((c.w.fw_scope_creates, c.w.fw_bind_writes), (creates, binds));
    }

    #[test]
    fn an_empty_replace_binds_no_scopes() {
        let mut c = core_with(&[(b"a", 1)]);
        replace(&mut c, b"a", &[allow_from(1, 0)]).unwrap();
        replace(&mut c, b"a", &[]).unwrap();
        let b = c.w.fw_bind[&1];
        assert_eq!((b.ingress_scope, b.egress_scope), (0, 0));
        assert!(c.w.fw_scopes.is_empty());
    }

    // A rule the classifier cannot express refuses the whole replace BEFORE any write: the old
    // rule slots and the old binding both stay.
    #[test]
    fn an_unsupported_rule_changes_nothing() {
        let mut c = core_with(&[(b"a", 1)]);
        replace(&mut c, b"a", &[allow_from(1, 0)]).unwrap();
        let bind = c.w.fw_bind[&1];
        let mut local = allow_from(2, 0);
        local.dst_mask = [255; 4];
        let err = replace(&mut c, b"a", &[local]).unwrap_err();
        assert!(matches!(err, FwError::Unsupported(_)), "{err}");
        assert_eq!(c.w.fw_bind[&1], bind);
        assert_eq!(
            c.w.fw_rules[&FwRuleKey { ifindex: 1, idx: 0 }].src_ip,
            [10, 1, 0, 0]
        );
    }

    #[test]
    fn detach_unbinds_and_frees_the_scope() {
        let mut c = core_with(&[(b"a", 1)]);
        replace(&mut c, b"a", &[allow_from(1, 0)]).unwrap();
        c.remove_fw_rules(1);
        assert!(
            !c.w.fw_bind.contains_key(&1),
            "a reused ifindex must not inherit the binding"
        );
        assert!(c.w.fw_scopes.is_empty());
    }

    // After a restart the pinned bindings and scopes survive but the in-memory refcounts do not:
    // adopt rebuilds them from the maps, deletes scopes nothing binds, and a re-push of the same
    // rules then finds its scope already there.
    #[test]
    fn adopt_rebuilds_references_from_the_maps() {
        let mut before = core_with(&[(b"a", 1)]);
        replace(&mut before, b"a", &[allow_from(1, 0)]).unwrap();
        let mut w = before.w;
        let orphan = crate::fwclass::Scope {
            id: 0xdead,
            ..Default::default()
        };
        w.fw_scope_create(&orphan).unwrap();

        let mut c = ControlCore::new(w);
        c.register_iface_meta(
            b"a".to_vec(),
            IfaceMeta {
                vni: 1,
                ipv4: [10, 0, 0, 1],
                ipv6: [0u8; 16],
                underlay: [1u8; 16],
                ifindex: 1,
            },
        );
        c.adopt_fw_classifier();
        assert!(
            !c.w.fw_scopes.contains_key(&0xdead),
            "unbound scope collected"
        );
        let creates = c.w.fw_scope_creates;
        replace(&mut c, b"a", &[allow_from(1, 0)]).unwrap();
        assert_eq!(
            c.w.fw_scope_creates, creates,
            "re-push reuses the adopted scope"
        );
        replace(&mut c, b"a", &[allow_from(2, 0)]).unwrap();
        assert_eq!(
            c.w.fw_scopes.len(),
            1,
            "the adopted scope is freed once unreferenced"
        );
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
