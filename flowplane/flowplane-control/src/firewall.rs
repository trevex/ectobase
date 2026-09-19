//! Per-interface firewall programming, backend-agnostic core: an interface's first-match rule lists
//! are compiled into classifier scopes ([`crate::fwclass`]), created under their content-addressed
//! ids, shared by every interface with the same rules, and bound with one `FW_BIND` write.

use core::fmt;

use crate::fwclass::{compile_scope, Scope};
use crate::{ControlCore, MapWriter};
use flowplane_common::{FwBind, FwRule, FwRule6, FW_DIR_EGRESS, FW_DIR_INGRESS, FW_SCOPE_NONE};

/// A firewall programming failure, classified so the gRPC layer can return a meaningful status:
/// an unknown interface, an oversized rule list and an inexpressible rule are client errors that a
/// retry cannot fix, unlike a failed map write.
#[derive(Debug)]
pub enum FwError {
    /// No interface with this id is attached on this node.
    UnknownInterface,
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

impl<W: MapWriter> ControlCore<W> {
    /// Drop the firewall state of a detaching interface's ifindex: its classifier binding — so an
    /// interface that later reuses the ifindex starts unbound (deny) instead of inheriting these
    /// rules — freeing any scope nothing else references.
    pub fn remove_fw_rules(&mut self, ifindex: u32) {
        if let Some(old) = self.fw_binds.remove(&ifindex) {
            let _ = self.w.fw_bind_remove(ifindex);
            let _ = self.w.fw_epoch_bump();
            self.fw_release_scopes(&old);
        }
    }

    /// Point `ifindex` at the given scopes: create the ones not yet present (fully built before
    /// they are reachable), then ONE binding write cuts the interface over — both directions, both
    /// families — for new flows; the epoch bump that follows makes established flows meet the new
    /// policy on their next packet (the binding must be written first: see
    /// `flowplane_core::conntrack::ct_needs_recheck`). Then scopes no longer referenced are
    /// deleted. An unchanged binding writes nothing. A failure before the binding write removes the
    /// scopes it created and leaves the old binding in force; a failed bump leaves the new binding
    /// in force for new flows and is reported.
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
        let bumped = self.w.fw_epoch_bump();
        if let Some(old) = old {
            self.fw_release_scopes(&old);
        }
        bumped.map_err(Into::into)
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

    /// Replace an interface's WHOLE firewall, both families, or nothing: the interface and the
    /// classifier compile (whose scope-size limits are the only bound on a rule list) are checked
    /// before anything is written, so a refusal leaves the interface on its previous rules. The
    /// interface then cuts over with one binding write. Rule ids ride along for the caller's
    /// bookkeeping; the order of each list is its first-match order.
    pub fn replace_interface_fw(
        &mut self,
        interface_id: &[u8],
        v4: Vec<(Vec<u8>, FwRule)>,
        v6: Vec<(Vec<u8>, FwRule6)>,
    ) -> Result<(), FwError> {
        let ifindex = self.fw_ifindex(interface_id)?;
        let (ingress, egress) =
            compile_iface(v4.iter().map(|(_, r)| r), v6.iter().map(|(_, r)| r))?;
        self.fw_bind_scopes(ifindex, ingress, egress)
    }
}

#[cfg(test)]
mod tests {
    use crate::{mem::MemMapWriter, shadow::IfaceMeta, ControlCore, FwError, MapWriter};
    use flowplane_common::{FwRule, FW_DIR_EGRESS};

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
        let epoch = c.w.fw_epoch;

        replace(&mut c, b"a", &[allow_from(2, 0)]).unwrap();
        let a = c.w.fw_bind[&1];
        assert_ne!(a.ingress_scope, shared);
        assert_eq!(
            c.w.fw_epoch,
            epoch + 1,
            "a rebind bumps the epoch: established flows meet the new rules"
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
        let epoch = c.w.fw_epoch;
        replace(
            &mut c,
            b"a",
            &[allow_from(1, 0), allow_from(1, FW_DIR_EGRESS)],
        )
        .unwrap();
        assert_eq!(c.w.fw_bind[&1], bind, "same scopes");
        assert_eq!((c.w.fw_scope_creates, c.w.fw_bind_writes), (creates, binds));
        assert_eq!(
            c.w.fw_epoch, epoch,
            "nothing changed: established flows keep going"
        );
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
    // binding and its scope stay.
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
        assert!(c.w.fw_scopes.contains_key(&bind.ingress_scope));
    }

    #[test]
    fn detach_unbinds_and_frees_the_scope() {
        let mut c = core_with(&[(b"a", 1)]);
        replace(&mut c, b"a", &[allow_from(1, 0)]).unwrap();
        let epoch = c.w.fw_epoch;
        c.remove_fw_rules(1);
        assert!(
            !c.w.fw_bind.contains_key(&1),
            "a reused ifindex must not inherit the binding"
        );
        assert!(c.w.fw_scopes.is_empty());
        assert_eq!(
            c.w.fw_epoch,
            epoch + 1,
            "flows of the detached interface are re-evaluated"
        );
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
}
