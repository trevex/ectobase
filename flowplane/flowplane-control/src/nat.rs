//! NAT: guest source-NAT + distributed neighbor-NAT return (backend-agnostic core).
//!
//! Moved verbatim out of the eBPF `Control` (control/nat.rs), applying the MapWriter transform:
//! `g.by_id` -> `self.ifaces_meta`, `g.lbs` -> `self.lbs`, `g.nat`/`g.nat_ips`/`g.neigh_nat*`
//! map ops -> `self.w.<map>_<op>`, and the CT flush -> `self.w.conntrack_flush(scope)`.

use crate::natowner::{owner_prefixes4, owner_prefixes6};
use crate::{ControlCore, CtFlushScope, CtFlushScope6, MapWriter, NeighborNatError};
use flowplane_common::{
    NatKey, NatKey6, NatValue, NatValue6, NeighborNat6Entry, NeighborNatEntry, NAT_OWNERS_MAX,
};

impl<W: MapWriter> ControlCore<W> {
    /// Program a guest's NAT config: (vni, guest_ip) -> (nat_ip, port_min, port_max).
    /// Returns the underlay route on success.
    pub fn create_nat(
        &mut self,
        interface_id: &[u8],
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let rec = self
            .ifaces_meta
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        let underlay = rec.underlay;

        // Check for existing NAT on this interface (any NAT IP).
        if self.w.nat_get(&NatKey { vni, ipv4: gip }).is_some() {
            anyhow::bail!("SNAT_EXISTS: NAT already configured for this interface");
        }

        // Check for overlapping port range across all interfaces in this VNI with the same nat_ip.
        for r in self.ifaces_meta.values() {
            if r.vni == vni {
                if let Some(v) = self.w.nat_get(&NatKey { vni, ipv4: r.ipv4 }) {
                    if v.nat_ipv4 == nat_ip {
                        // Overlapping port range?
                        if port_min < v.port_max && port_max > v.port_min {
                            anyhow::bail!("SNAT_EXISTS: overlapping NAT port range");
                        }
                    }
                }
            }
        }

        // Check preferred underlay collision.
        if let Some(pul) = preferred_ul {
            if self.ifaces_meta.values().any(|r| r.underlay == pul)
                || self.lbs.values().any(|lb| lb.lb_underlay == pul)
            {
                anyhow::bail!("VNF_INSERT: preferred underlay collision");
            }
        }

        self.w.nat_upsert(
            NatKey { vni, ipv4: gip },
            NatValue {
                nat_ipv4: nat_ip,
                port_min,
                port_max,
            },
        )?;
        // Mark this nat_ip in NAT_IPS for peer-independent NAT-return demux (Maps::is_nat_ip).
        let _ = self.w.nat_ips_set(vni, nat_ip);
        Ok(preferred_ul.unwrap_or(underlay))
    }

    /// Remove a guest's NAT config. Returns true if found and deleted, false if no NAT was set.
    pub fn delete_nat(&mut self, interface_id: &[u8]) -> anyhow::Result<bool> {
        let (vni, gip, nat_ip, port_min, port_max) = {
            let rec = self
                .ifaces_meta
                .get(interface_id)
                .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
            let (vni, gip) = (rec.vni, rec.ipv4);
            let nat_val = match self.w.nat_get(&NatKey { vni, ipv4: gip }) {
                Some(v) => v,
                None => return Ok(false),
            };
            let nat_ip = nat_val.nat_ipv4;
            let port_min = nat_val.port_min;
            let port_max = nat_val.port_max;
            let _ = self.w.nat_remove(&NatKey { vni, ipv4: gip });
            // Remove the NAT_IPS marker if no other interface in this VNI uses the same nat_ip.
            let still_used = self.ifaces_meta.iter().any(|(other_id, r)| {
                other_id.as_slice() != interface_id
                    && r.vni == vni
                    && self
                        .w
                        .nat_get(&NatKey {
                            vni: r.vni,
                            ipv4: r.ipv4,
                        })
                        .map(|v| v.nat_ipv4 == nat_ip)
                        .unwrap_or(false)
            });
            if !still_used {
                let _ = self.w.nat_ips_remove(vni, nat_ip);
            }
            (vni, gip, nat_ip, port_min, port_max)
        };
        // Flush CT entries for this guest: in eBPF this scans+removes matching CONNTRACK map
        // entries. The scope carries the same values the former `ct_flush_for_guest` matched on.
        self.w.conntrack_flush(CtFlushScope {
            vni,
            guest_ip: gip,
            nat_ip,
            port_min,
            port_max,
        })?;
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Neighbor NAT management (distributed NAT return)
    // -----------------------------------------------------------------------

    /// Add a neighbor-NAT block: `[port_min, port_max)` of `nat_ip` is owned by the node at
    /// `underlay`, in `vni`. Refused whole — nothing written — if the range is empty, overlaps
    /// another block on the same nat_ip (in any VNI: blocks are keyed without one), or would not
    /// fit the trie. A failed write removes the prefixes already written.
    pub fn add_neighbor_nat(
        &mut self,
        vni: u32,
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
        underlay: [u8; 16],
    ) -> Result<(), NeighborNatError> {
        if port_min >= port_max {
            return Err(NeighborNatError::EmptyRange);
        }
        if self
            .neigh_nats
            .iter()
            .any(|e| e.nat_ip == nat_ip && e.port_min < port_max && e.port_max > port_min)
        {
            return Err(NeighborNatError::Overlap);
        }
        let b = NeighborNatEntry {
            underlay,
            nat_ip,
            vni,
            port_min,
            port_max,
            enabled: 1,
            _pad: [0; 3],
        };
        let entries = owner_prefixes4(&b);
        if self.nat_owner_count4 + entries.len() > NAT_OWNERS_MAX as usize {
            return Err(NeighborNatError::Full {
                needed: entries.len(),
                max: NAT_OWNERS_MAX,
            });
        }
        for (i, (plen, key, owner)) in entries.iter().enumerate() {
            if let Err(e) = self.w.nat_owner_upsert(*plen, *key, *owner) {
                for (plen, key, _) in &entries[..i] {
                    let _ = self.w.nat_owner_remove(*plen, key);
                }
                return Err(e.into());
            }
        }
        self.nat_owner_count4 += entries.len();
        self.neigh_nats.push(b);
        Ok(())
    }

    /// Remove the block `(vni, nat_ip, [port_min, port_max))`. `Ok(false)` if there is none. Every
    /// prefix is tried even after a failure — stopping would strand the rest in the trie with the
    /// block already gone from the list — and the first error is returned.
    pub fn del_neighbor_nat(
        &mut self,
        vni: u32,
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
    ) -> Result<bool, NeighborNatError> {
        let Some(i) = self.neigh_nats.iter().position(|e| {
            e.vni == vni && e.nat_ip == nat_ip && e.port_min == port_min && e.port_max == port_max
        }) else {
            return Ok(false);
        };
        let b = self.neigh_nats.remove(i);
        let entries = owner_prefixes4(&b);
        self.nat_owner_count4 -= entries.len();
        let mut first_err = None;
        for (plen, key, _) in &entries {
            if let Err(e) = self.w.nat_owner_remove(*plen, key) {
                first_err.get_or_insert(e);
            }
        }
        match first_err {
            Some(e) => Err(e.into()),
            None => Ok(true),
        }
    }

    // -----------------------------------------------------------------------
    // NAT66 (v6) — faithful siblings of the v4 fns above, over the v6 structs/maps and `rec.ipv6`.
    // -----------------------------------------------------------------------

    /// Program a guest's NAT66 config: (vni, guest_ipv6) -> (nat_ipv6, port_min, port_max).
    /// Returns the underlay route on success.
    pub fn create_nat6(
        &mut self,
        interface_id: &[u8],
        nat_ip: [u8; 16],
        port_min: u16,
        port_max: u16,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let rec = self
            .ifaces_meta
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv6);
        let underlay = rec.underlay;

        // Check for existing NAT66 on this interface (any nat_ip).
        if self.w.nat6_get(&NatKey6 { vni, ipv6: gip }).is_some() {
            anyhow::bail!("SNAT_EXISTS: NAT already configured for this interface");
        }

        // Check for overlapping port range across all interfaces in this VNI with the same nat_ip.
        for r in self.ifaces_meta.values() {
            if r.vni == vni {
                if let Some(v) = self.w.nat6_get(&NatKey6 { vni, ipv6: r.ipv6 }) {
                    if v.nat_ipv6 == nat_ip && port_min < v.port_max && port_max > v.port_min {
                        anyhow::bail!("SNAT_EXISTS: overlapping NAT port range");
                    }
                }
            }
        }

        // Check preferred underlay collision.
        if let Some(pul) = preferred_ul {
            if self.ifaces_meta.values().any(|r| r.underlay == pul)
                || self.lbs.values().any(|lb| lb.lb_underlay == pul)
            {
                anyhow::bail!("VNF_INSERT: preferred underlay collision");
            }
        }

        self.w.nat6_upsert(
            NatKey6 { vni, ipv6: gip },
            NatValue6 {
                nat_ipv6: nat_ip,
                port_min,
                port_max,
            },
        )?;
        // Mark this nat_ip in NAT_IPS6 for peer-independent NAT-return demux (Maps::is_nat_ip6).
        let _ = self.w.nat_ips6_set(vni, nat_ip);
        Ok(preferred_ul.unwrap_or(underlay))
    }

    /// Remove a guest's NAT66 config. Returns true if found and deleted, false if none was set.
    pub fn delete_nat6(&mut self, interface_id: &[u8]) -> anyhow::Result<bool> {
        let (vni, gip, nat_ip, port_min, port_max) = {
            let rec = self
                .ifaces_meta
                .get(interface_id)
                .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
            let (vni, gip) = (rec.vni, rec.ipv6);
            let nat_val = match self.w.nat6_get(&NatKey6 { vni, ipv6: gip }) {
                Some(v) => v,
                None => return Ok(false),
            };
            let nat_ip = nat_val.nat_ipv6;
            let port_min = nat_val.port_min;
            let port_max = nat_val.port_max;
            let _ = self.w.nat6_remove(&NatKey6 { vni, ipv6: gip });
            // Remove the NAT_IPS6 marker if no other interface in this VNI uses the same nat_ip.
            let still_used = self.ifaces_meta.iter().any(|(other_id, r)| {
                other_id.as_slice() != interface_id
                    && r.vni == vni
                    && self
                        .w
                        .nat6_get(&NatKey6 {
                            vni: r.vni,
                            ipv6: r.ipv6,
                        })
                        .map(|v| v.nat_ipv6 == nat_ip)
                        .unwrap_or(false)
            });
            if !still_used {
                let _ = self.w.nat_ips6_remove(vni, nat_ip);
            }
            (vni, gip, nat_ip, port_min, port_max)
        };
        self.w.conntrack6_flush(CtFlushScope6 {
            vni,
            guest_ip6: gip,
            nat_ip6: nat_ip,
            port_min,
            port_max,
        })?;
        Ok(true)
    }

    /// IPv6 sibling of [`Self::add_neighbor_nat`].
    pub fn add_neighbor_nat6(
        &mut self,
        vni: u32,
        nat_ip: [u8; 16],
        port_min: u16,
        port_max: u16,
        underlay: [u8; 16],
    ) -> Result<(), NeighborNatError> {
        if port_min >= port_max {
            return Err(NeighborNatError::EmptyRange);
        }
        if self
            .neigh_nats6
            .iter()
            .any(|e| e.nat_ip6 == nat_ip && e.port_min < port_max && e.port_max > port_min)
        {
            return Err(NeighborNatError::Overlap);
        }
        let b = NeighborNat6Entry {
            underlay,
            nat_ip6: nat_ip,
            vni,
            port_min,
            port_max,
            enabled: 1,
            _pad: [0; 3],
        };
        let entries = owner_prefixes6(&b);
        if self.nat_owner_count6 + entries.len() > NAT_OWNERS_MAX as usize {
            return Err(NeighborNatError::Full {
                needed: entries.len(),
                max: NAT_OWNERS_MAX,
            });
        }
        for (i, (plen, key, owner)) in entries.iter().enumerate() {
            if let Err(e) = self.w.nat_owner6_upsert(*plen, *key, *owner) {
                for (plen, key, _) in &entries[..i] {
                    let _ = self.w.nat_owner6_remove(*plen, key);
                }
                return Err(e.into());
            }
        }
        self.nat_owner_count6 += entries.len();
        self.neigh_nats6.push(b);
        Ok(())
    }

    /// IPv6 sibling of [`Self::del_neighbor_nat`].
    pub fn del_neighbor_nat6(
        &mut self,
        vni: u32,
        nat_ip: [u8; 16],
        port_min: u16,
        port_max: u16,
    ) -> Result<bool, NeighborNatError> {
        let Some(i) = self.neigh_nats6.iter().position(|e| {
            e.vni == vni && e.nat_ip6 == nat_ip && e.port_min == port_min && e.port_max == port_max
        }) else {
            return Ok(false);
        };
        let b = self.neigh_nats6.remove(i);
        let entries = owner_prefixes6(&b);
        self.nat_owner_count6 -= entries.len();
        let mut first_err = None;
        for (plen, key, _) in &entries {
            if let Err(e) = self.w.nat_owner6_remove(*plen, key) {
                first_err.get_or_insert(e);
            }
        }
        match first_err {
            Some(e) => Err(e.into()),
            None => Ok(true),
        }
    }

    /// Adopt after a restart: the pinned owner tries survived, the block lists did not. Rebuild
    /// them from the tries' values (each prefix carries its whole block), then rewrite each
    /// block's full prefix set, since a crash between two prefix writes can leave a block partial.
    /// A block a crash left half-withdrawn so comes back whole; the next declarative sync prunes it.
    pub fn adopt_nat_owners(&mut self) {
        let mut v4: Vec<NeighborNatEntry> = self
            .w
            .nat_owner_entries()
            .into_iter()
            .map(|(_, key, o)| NeighborNatEntry {
                underlay: o.underlay,
                nat_ip: key.nat_ip,
                vni: o.vni,
                port_min: o.port_min,
                port_max: o.port_max,
                enabled: 1,
                _pad: [0; 3],
            })
            .collect();
        // Each prefix repeats its block: sort on every field so the repeats are adjacent for
        // dedup (a `contains` scan would be quadratic in a full trie).
        v4.sort_unstable_by_key(|b| (b.nat_ip, b.port_min, b.port_max, b.vni, b.underlay));
        v4.dedup();
        self.nat_owner_count4 = 0;
        for b in &v4 {
            let entries = owner_prefixes4(b);
            self.nat_owner_count4 += entries.len();
            for (plen, key, owner) in entries {
                let _ = self.w.nat_owner_upsert(plen, key, owner);
            }
        }
        self.neigh_nats = v4;

        let mut v6: Vec<NeighborNat6Entry> = self
            .w
            .nat_owner6_entries()
            .into_iter()
            .map(|(_, key, o)| NeighborNat6Entry {
                underlay: o.underlay,
                nat_ip6: key.nat_ip6,
                vni: o.vni,
                port_min: o.port_min,
                port_max: o.port_max,
                enabled: 1,
                _pad: [0; 3],
            })
            .collect();
        v6.sort_unstable_by_key(|b| (b.nat_ip6, b.port_min, b.port_max, b.vni, b.underlay));
        v6.dedup();
        self.nat_owner_count6 = 0;
        for b in &v6 {
            let entries = owner_prefixes6(b);
            self.nat_owner_count6 += entries.len();
            for (plen, key, owner) in entries {
                let _ = self.w.nat_owner6_upsert(plen, key, owner);
            }
        }
        self.neigh_nats6 = v6;
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        mem::MemMapWriter,
        natowner::{owner_prefixes4, owner_prefixes6},
        shadow::IfaceMeta,
        ControlCore, NeighborNatError,
    };
    use flowplane_common::{
        NatOwner, NatOwnerKey, NatOwnerKey6, NeighborNat6Entry, NeighborNatEntry,
    };
    use std::collections::HashMap;

    /// The `MemMapWriter::nat_owners` contents that store exactly `blocks`.
    fn prefixes4(blocks: &[NeighborNatEntry]) -> HashMap<(u32, NatOwnerKey), NatOwner> {
        blocks
            .iter()
            .flat_map(owner_prefixes4)
            .map(|(p, k, o)| ((p, k), o))
            .collect()
    }

    /// IPv6 sibling of [`prefixes4`].
    fn prefixes6(blocks: &[NeighborNat6Entry]) -> HashMap<(u32, NatOwnerKey6), NatOwner> {
        blocks
            .iter()
            .flat_map(owner_prefixes6)
            .map(|(p, k, o)| ((p, k), o))
            .collect()
    }

    #[test]
    fn add_and_del_neighbor_nat_programs_maps_and_rejects_overlap() {
        let mut c = ControlCore::new(MemMapWriter::default());

        let vni: u32 = 10;
        let nat_ip: [u8; 4] = [203, 0, 113, 1];
        let nat_ip2: [u8; 4] = [203, 0, 113, 2];
        let underlay: [u8; 16] = [2u8; 16];
        let block = |nat_ip, underlay| NeighborNatEntry {
            underlay,
            nat_ip,
            vni,
            port_min: 1024,
            port_max: 2048,
            enabled: 1,
            _pad: [0; 3],
        };

        c.add_neighbor_nat(vni, nat_ip, 1024, 2048, underlay)
            .unwrap();
        let first = prefixes4(&[block(nat_ip, underlay)]);
        assert_eq!(c.w.nat_owners, first);

        // Exact duplicate (same vni + nat_ip + ports) must be rejected.
        assert!(matches!(
            c.add_neighbor_nat(vni, nat_ip, 1024, 2048, underlay),
            Err(NeighborNatError::Overlap)
        ));

        // Overlapping port range on the same nat_ip (different vni) must also be rejected.
        // [1500, 3000) overlaps [1024, 2048).
        assert!(matches!(
            c.add_neighbor_nat(vni + 1, nat_ip, 1500, 3000, underlay),
            Err(NeighborNatError::Overlap)
        ));
        assert_eq!(c.w.nat_owners, first, "a refused block writes nothing");

        // Non-overlapping range on a different nat_ip is fine (different nat_ip → no conflict).
        c.add_neighbor_nat(vni, nat_ip2, 1024, 2048, [3u8; 16])
            .unwrap();
        assert_eq!(
            c.w.nat_owners,
            prefixes4(&[block(nat_ip, underlay), block(nat_ip2, [3u8; 16])])
        );

        // Delete the first block: only the second's prefixes remain, and it returns true.
        assert!(c.del_neighbor_nat(vni, nat_ip, 1024, 2048).unwrap());
        assert_eq!(c.w.nat_owners, prefixes4(&[block(nat_ip2, [3u8; 16])]));

        // Deleting a non-existent entry returns false.
        assert!(!c.del_neighbor_nat(vni, nat_ip, 1024, 2048).unwrap());
    }

    #[test]
    fn create_and_delete_nat_programs_maps_and_flushes_ct() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.register_iface_meta(
            b"if1".to_vec(),
            IfaceMeta {
                vni: 5,
                ipv4: [10, 0, 0, 2],
                ipv6: [0u8; 16],
                underlay: [1u8; 16],
                ifindex: 1,
            },
        );
        let ul = c
            .create_nat(b"if1", [1, 2, 3, 4], 1024, 2048, None)
            .unwrap();
        assert_eq!(ul, [1u8; 16]);
        assert!(c.w.nat.contains_key(&flowplane_common::NatKey {
            vni: 5,
            ipv4: [10, 0, 0, 2]
        }));
        assert!(c.w.nat_ips.contains(&(5, [1, 2, 3, 4])));
        // duplicate NAT on same iface rejected
        assert!(c
            .create_nat(b"if1", [1, 2, 3, 4], 1024, 2048, None)
            .is_err());
        assert!(c.delete_nat(b"if1").unwrap());
        assert_eq!(c.w.ct_flushes.len(), 1);
        assert!(!c.w.nat.contains_key(&flowplane_common::NatKey {
            vni: 5,
            ipv4: [10, 0, 0, 2]
        }));
    }

    // v6 sibling of the two tests above.
    const G6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]; // fd00::2 (guest ULA)
    const NAT6_A: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0x2b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]; // 2001:db8:2b::1
    const NAT6_B: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0x2b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ]; // 2001:db8:2b::2

    #[test]
    fn add_and_del_neighbor_nat6_programs_maps_and_rejects_overlap() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let vni: u32 = 10;
        let underlay: [u8; 16] = [2u8; 16];
        let block = |nat_ip6, underlay| NeighborNat6Entry {
            underlay,
            nat_ip6,
            vni,
            port_min: 1024,
            port_max: 2048,
            enabled: 1,
            _pad: [0; 3],
        };

        c.add_neighbor_nat6(vni, NAT6_A, 1024, 2048, underlay)
            .unwrap();
        let first = prefixes6(&[block(NAT6_A, underlay)]);
        assert_eq!(c.w.nat_owners6, first);

        // Exact duplicate rejected.
        assert!(matches!(
            c.add_neighbor_nat6(vni, NAT6_A, 1024, 2048, underlay),
            Err(NeighborNatError::Overlap)
        ));
        // Overlapping range on the same nat_ip (different vni) rejected.
        assert!(matches!(
            c.add_neighbor_nat6(vni + 1, NAT6_A, 1500, 3000, underlay),
            Err(NeighborNatError::Overlap)
        ));
        assert_eq!(c.w.nat_owners6, first, "a refused block writes nothing");
        // Non-overlapping range on a different nat_ip is fine.
        c.add_neighbor_nat6(vni, NAT6_B, 1024, 2048, [3u8; 16])
            .unwrap();
        assert_eq!(
            c.w.nat_owners6,
            prefixes6(&[block(NAT6_A, underlay), block(NAT6_B, [3u8; 16])])
        );

        assert!(c.del_neighbor_nat6(vni, NAT6_A, 1024, 2048).unwrap());
        assert_eq!(c.w.nat_owners6, prefixes6(&[block(NAT6_B, [3u8; 16])]));
        assert!(!c.del_neighbor_nat6(vni, NAT6_A, 1024, 2048).unwrap());
    }

    #[test]
    fn create_and_delete_nat6_programs_maps_and_flushes_ct() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.register_iface_meta(
            b"if1".to_vec(),
            IfaceMeta {
                vni: 5,
                ipv4: [0u8; 4],
                ipv6: G6,
                underlay: [1u8; 16],
                ifindex: 1,
            },
        );
        let ul = c.create_nat6(b"if1", NAT6_A, 1024, 2048, None).unwrap();
        assert_eq!(ul, [1u8; 16]);
        assert!(c
            .w
            .nat6
            .contains_key(&flowplane_common::NatKey6 { vni: 5, ipv6: G6 }));
        assert!(c.w.nat_ips6.contains(&(5, NAT6_A)));
        // duplicate NAT on same iface rejected
        assert!(c.create_nat6(b"if1", NAT6_A, 1024, 2048, None).is_err());
        assert!(c.delete_nat6(b"if1").unwrap());
        assert_eq!(c.w.ct6_flushes.len(), 1);
        assert!(!c
            .w
            .nat6
            .contains_key(&flowplane_common::NatKey6 { vni: 5, ipv6: G6 }));
    }
}

#[cfg(test)]
mod neighbor_nat_tests {
    use crate::{mem::MemMapWriter, natowner::owner_prefixes4, ControlCore, NeighborNatError};
    use flowplane_common::{NatOwner, NatOwnerKey, NeighborNatEntry};

    const IP: [u8; 4] = [203, 0, 113, 9];

    fn entry(vni: u32, lo: u16, hi: u16, owner: u8) -> NeighborNatEntry {
        NeighborNatEntry {
            underlay: [owner; 16],
            nat_ip: IP,
            vni,
            port_min: lo,
            port_max: hi,
            enabled: 1,
            _pad: [0; 3],
        }
    }

    fn sorted(mut v: Vec<(u32, NatOwnerKey, NatOwner)>) -> Vec<(u32, NatOwnerKey, NatOwner)> {
        v.sort_by_key(|(p, k, _)| (u16::from_be_bytes(k.port), *p));
        v
    }

    fn stored(c: &ControlCore<MemMapWriter>) -> Vec<(u32, NatOwnerKey, NatOwner)> {
        sorted(
            c.w.nat_owners
                .iter()
                .map(|((p, k), o)| (*p, *k, *o))
                .collect(),
        )
    }

    /// The capacity check trusts the counters; they must track the tries exactly.
    fn assert_counted(c: &ControlCore<MemMapWriter>) {
        assert_eq!(c.nat_owner_count4, c.w.nat_owners.len(), "v4 prefix count");
        assert_eq!(c.nat_owner_count6, c.w.nat_owners6.len(), "v6 prefix count");
    }

    #[test]
    fn a_block_is_stored_as_its_prefixes() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat(7, IP, 20000, 30000, [3; 16]).unwrap();
        assert_eq!(
            stored(&c),
            sorted(owner_prefixes4(&entry(7, 20000, 30000, 3)))
        );
        assert_counted(&c);
    }

    #[test]
    fn an_overlap_on_the_same_nat_ip_is_refused_in_any_vni() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat(7, IP, 20000, 30000, [3; 16]).unwrap();
        let before = stored(&c);
        let err = c
            .add_neighbor_nat(8, IP, 29999, 31000, [4; 16])
            .unwrap_err();
        assert!(matches!(err, NeighborNatError::Overlap), "{err}");
        assert_eq!(stored(&c), before, "nothing written");
        assert_counted(&c);
    }

    #[test]
    fn an_empty_range_is_refused() {
        let mut c = ControlCore::new(MemMapWriter::default());
        assert!(matches!(
            c.add_neighbor_nat(7, IP, 5, 5, [3; 16]),
            Err(NeighborNatError::EmptyRange)
        ));
    }

    #[test]
    fn withdraw_removes_exactly_its_prefixes() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat(7, IP, 20000, 30000, [3; 16]).unwrap();
        c.add_neighbor_nat(7, IP, 1024, 2048, [4; 16]).unwrap();
        assert_counted(&c);
        assert!(c.del_neighbor_nat(7, IP, 20000, 30000).unwrap());
        assert_eq!(stored(&c), owner_prefixes4(&entry(7, 1024, 2048, 4)));
        assert_counted(&c);
        assert!(
            !c.del_neighbor_nat(7, IP, 20000, 30000).unwrap(),
            "already gone"
        );
        assert_counted(&c);
    }

    // Worst-case blocks (30 prefixes each, [1, 65535)) on distinct nat_ips fill the trie at
    // floor(65536 / 30) = 2184 blocks; the next is refused whole.
    #[test]
    fn the_table_refuses_a_block_it_cannot_hold() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let ip = |i: u32| [10, (i >> 16) as u8, (i >> 8) as u8, i as u8];
        for i in 0..2184 {
            c.add_neighbor_nat(7, ip(i), 1, 65535, [1; 16]).unwrap();
        }
        assert_counted(&c);
        let n = c.w.nat_owners.len();
        let err = c
            .add_neighbor_nat(7, ip(2184), 1, 65535, [1; 16])
            .unwrap_err();
        assert!(matches!(err, NeighborNatError::Full { .. }), "{err}");
        assert_eq!(c.w.nat_owners.len(), n, "nothing written");
        assert_counted(&c);
    }

    // After a restart the pinned trie survives and the block list does not: adopt rebuilds it, so
    // a re-announce is idempotent and a withdraw still finds its block.
    #[test]
    fn adopt_rebuilds_the_blocks_from_the_trie() {
        let mut before = ControlCore::new(MemMapWriter::default());
        before
            .add_neighbor_nat(7, IP, 20000, 30000, [3; 16])
            .unwrap();
        before
            .add_neighbor_nat6(9, [9; 16], 1024, 2048, [5; 16])
            .unwrap();
        let mut c = ControlCore::new(before.w);
        c.adopt_nat_owners();
        assert_counted(&c);
        assert!(c.del_neighbor_nat(7, IP, 20000, 30000).unwrap());
        assert!(c.w.nat_owners.is_empty());
        assert!(c.del_neighbor_nat6(9, [9; 16], 1024, 2048).unwrap());
        assert!(c.w.nat_owners6.is_empty());
        assert_counted(&c);
    }

    // A crash between two prefix writes leaves part of a block in the pinned trie. Adopt must make
    // it whole again, or its missing ports have no owner and the prefix count disagrees with the
    // trie.
    #[test]
    fn adopt_completes_a_block_a_crash_left_partial() {
        const IP6: [u8; 16] = [9; 16];
        let mut before = ControlCore::new(MemMapWriter::default());
        before
            .add_neighbor_nat(7, IP, 20000, 30000, [3; 16])
            .unwrap();
        before
            .add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16])
            .unwrap();
        let full4 = stored(&before);
        let full6 = before.w.nat_owners6.clone();
        assert!(full4.len() > 1 && full6.len() > 1, "multi-prefix blocks");
        let (p, k, _) = full4[full4.len() / 2];
        before.w.nat_owners.remove(&(p, k));
        let k6 = *full6.keys().next().unwrap();
        before.w.nat_owners6.remove(&k6);

        let mut c = ControlCore::new(before.w);
        c.adopt_nat_owners();
        assert_eq!(stored(&c), full4);
        assert_eq!(c.w.nat_owners6, full6);
        assert_counted(&c);

        assert!(c.del_neighbor_nat(7, IP, 20000, 30000).unwrap());
        assert!(c.del_neighbor_nat6(7, IP6, 20000, 30000).unwrap());
        assert!(c.w.nat_owners.is_empty() && c.w.nat_owners6.is_empty());
        assert_eq!((c.nat_owner_count4, c.nat_owner_count6), (0, 0));
    }
}
