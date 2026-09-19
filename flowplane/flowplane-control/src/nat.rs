//! NAT: guest source-NAT + distributed neighbor-NAT return (backend-agnostic core).
//!
//! Guest NAT moved verbatim out of the eBPF `Control`, applying the MapWriter
//! transform: `g.by_id` -> `self.ifaces_meta`, `g.lbs` -> `self.lbs`, `g.nat`/`g.nat_ips` map ops
//! -> `self.w.<map>_<op>`, and the CT flush -> `self.w.conntrack_flush(scope)`. Neighbor-NAT blocks
//! are listed in `neigh_nats{,6}` and stored in the `NAT_OWNERS{,6}` tries as their port prefixes
//! (see [`crate::natowner`]); every prefix in a trie belongs to a listed block.

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
    /// fit the trie. A failed write removes the prefixes already written; if a removal fails too,
    /// the block is listed anyway (and the write error returned), so what it left in the trie
    /// belongs to a listed block that a withdraw, or adopt, completes.
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
                let mut stranded = false;
                for (plen, key, _) in &entries[..i] {
                    stranded |= self.w.nat_owner_remove(*plen, key).is_err();
                }
                if stranded {
                    self.nat_owner_count4 += entries.len();
                    self.neigh_nats.push(b);
                }
                return Err(e.into());
            }
        }
        self.nat_owner_count4 += entries.len();
        self.neigh_nats.push(b);
        Ok(())
    }

    /// Remove the block `(vni, nat_ip, [port_min, port_max))`. `Ok(false)` if there is none. Every
    /// prefix removal is tried; if any fails, the first error is returned and the block stays
    /// listed and counted, so a retry redoes them all. Until then its count reads high, refusing
    /// adds early, never low.
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
        let entries = owner_prefixes4(&self.neigh_nats[i]);
        let mut first_err = None;
        for (plen, key, _) in &entries {
            if let Err(e) = self.w.nat_owner_remove(*plen, key) {
                first_err.get_or_insert(e);
            }
        }
        if let Some(e) = first_err {
            return Err(e.into());
        }
        self.neigh_nats.remove(i);
        self.nat_owner_count4 -= entries.len();
        Ok(true)
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
                let mut stranded = false;
                for (plen, key, _) in &entries[..i] {
                    stranded |= self.w.nat_owner6_remove(*plen, key).is_err();
                }
                if stranded {
                    self.nat_owner_count6 += entries.len();
                    self.neigh_nats6.push(b);
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
        let entries = owner_prefixes6(&self.neigh_nats6[i]);
        let mut first_err = None;
        for (plen, key, _) in &entries {
            if let Err(e) = self.w.nat_owner6_remove(*plen, key) {
                first_err.get_or_insert(e);
            }
        }
        if let Some(e) = first_err {
            return Err(e.into());
        }
        self.neigh_nats6.remove(i);
        self.nat_owner_count6 -= entries.len();
        Ok(true)
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
    use crate::{mem::MemMapWriter, shadow::IfaceMeta, ControlCore};

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

    // v6 sibling of the test above.
    const G6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]; // fd00::2 (guest ULA)
    const NAT6_A: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0x2b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]; // 2001:db8:2b::1

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
    use crate::{
        mem::MemMapWriter,
        natowner::{owner_prefixes4, owner_prefixes6},
        ControlCore, MapWriter, NeighborNatError,
    };
    use flowplane_common::{
        NatOwner, NatOwnerKey, NatOwnerKey6, NeighborNat6Entry, NeighborNatEntry, NAT_OWNERS_MAX,
    };

    const IP: [u8; 4] = [203, 0, 113, 9];
    const IP6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0x2b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]; // 2001:db8:2b::9

    type Entries = Vec<(u32, NatOwnerKey, NatOwner)>;
    type Entries6 = Vec<(u32, NatOwnerKey6, NatOwner)>;

    fn block(nat_ip: [u8; 4], vni: u32, lo: u16, hi: u16, owner: u8) -> NeighborNatEntry {
        NeighborNatEntry {
            underlay: [owner; 16],
            nat_ip,
            vni,
            port_min: lo,
            port_max: hi,
            enabled: 1,
            _pad: [0; 3],
        }
    }

    fn block6(nat_ip6: [u8; 16], vni: u32, lo: u16, hi: u16, owner: u8) -> NeighborNat6Entry {
        NeighborNat6Entry {
            underlay: [owner; 16],
            nat_ip6,
            vni,
            port_min: lo,
            port_max: hi,
            enabled: 1,
            _pad: [0; 3],
        }
    }

    /// Trie entries in one canonical order, to compare as lists.
    fn sorted(mut v: Entries) -> Entries {
        v.sort_by_key(|(p, k, _)| (k.nat_ip, k.port, *p));
        v
    }

    fn sorted6(mut v: Entries6) -> Entries6 {
        v.sort_by_key(|(p, k, _)| (k.nat_ip6, k.port, *p));
        v
    }

    /// What the trie holds.
    fn stored(c: &ControlCore<MemMapWriter>) -> Entries {
        sorted(c.w.nat_owner_entries())
    }

    fn stored6(c: &ControlCore<MemMapWriter>) -> Entries6 {
        sorted6(c.w.nat_owner6_entries())
    }

    /// What the trie holds when it stores exactly `blocks`.
    fn prefixes(blocks: &[NeighborNatEntry]) -> Entries {
        sorted(blocks.iter().flat_map(owner_prefixes4).collect())
    }

    fn prefixes6(blocks: &[NeighborNat6Entry]) -> Entries6 {
        sorted6(blocks.iter().flat_map(owner_prefixes6).collect())
    }

    /// Prefix `i` of a block, as the fault knob names it.
    fn nth(b: &NeighborNatEntry, i: usize) -> (u32, NatOwnerKey) {
        let (p, k, _) = owner_prefixes4(b)[i];
        (p, k)
    }

    fn nth6(b: &NeighborNat6Entry, i: usize) -> (u32, NatOwnerKey6) {
        let (p, k, _) = owner_prefixes6(b)[i];
        (p, k)
    }

    /// Everything the core and its writer hold for neighbor NAT, to assert an operation changed
    /// nothing.
    #[derive(Debug, PartialEq)]
    struct State {
        tries: (Entries, Entries6),
        blocks: (Vec<NeighborNatEntry>, Vec<NeighborNat6Entry>),
        counts: (usize, usize),
    }

    fn state(c: &ControlCore<MemMapWriter>) -> State {
        State {
            tries: (stored(c), stored6(c)),
            blocks: (c.neigh_nats.clone(), c.neigh_nats6.clone()),
            counts: (c.nat_owner_count4, c.nat_owner_count6),
        }
    }

    /// While the block lists and the tries agree, the counters are the tries' sizes.
    fn assert_counted(c: &ControlCore<MemMapWriter>) {
        assert_eq!(c.nat_owner_count4, c.w.nat_owners.len(), "v4 prefix count");
        assert_eq!(c.nat_owner_count6, c.w.nat_owners6.len(), "v6 prefix count");
    }

    #[test]
    fn a_block_is_stored_as_its_prefixes() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat(7, IP, 20000, 30000, [3; 16]).unwrap();
        c.add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16]).unwrap();
        assert_eq!(stored(&c), prefixes(&[block(IP, 7, 20000, 30000, 3)]));
        assert_eq!(stored6(&c), prefixes6(&[block6(IP6, 7, 20000, 30000, 3)]));
        assert_counted(&c);
    }

    // Blocks are keyed without a VNI, so an overlap on the same nat_ip is refused in any VNI; an
    // exact duplicate is an overlap. The same range on another nat_ip is not.
    #[test]
    fn an_overlap_on_the_same_nat_ip_is_refused_in_any_vni() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat(7, IP, 20000, 30000, [3; 16]).unwrap();
        let before = state(&c);
        for (vni, lo, hi) in [(7, 20000, 30000), (8, 29999, 31000)] {
            let err = c.add_neighbor_nat(vni, IP, lo, hi, [4; 16]).unwrap_err();
            assert!(
                matches!(err, NeighborNatError::Overlap),
                "{vni} {lo}..{hi}: {err}"
            );
        }
        assert_eq!(state(&c), before, "nothing written");
        let other = [203, 0, 113, 10];
        c.add_neighbor_nat(7, other, 20000, 30000, [4; 16]).unwrap();
        assert_eq!(
            stored(&c),
            prefixes(&[
                block(IP, 7, 20000, 30000, 3),
                block(other, 7, 20000, 30000, 4)
            ])
        );
        assert_counted(&c);
    }

    #[test]
    fn a_v6_overlap_on_the_same_nat_ip_is_refused_in_any_vni() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16]).unwrap();
        let before = state(&c);
        for (vni, lo, hi) in [(7, 20000, 30000), (8, 29999, 31000)] {
            let err = c.add_neighbor_nat6(vni, IP6, lo, hi, [4; 16]).unwrap_err();
            assert!(
                matches!(err, NeighborNatError::Overlap),
                "{vni} {lo}..{hi}: {err}"
            );
        }
        assert_eq!(state(&c), before, "nothing written");
        let mut other = IP6;
        other[15] = 10;
        c.add_neighbor_nat6(7, other, 20000, 30000, [4; 16])
            .unwrap();
        assert_eq!(
            stored6(&c),
            prefixes6(&[
                block6(IP6, 7, 20000, 30000, 3),
                block6(other, 7, 20000, 30000, 4)
            ])
        );
        assert_counted(&c);
    }

    #[test]
    fn an_empty_range_is_refused() {
        let mut c = ControlCore::new(MemMapWriter::default());
        assert!(matches!(
            c.add_neighbor_nat(7, IP, 5, 5, [3; 16]),
            Err(NeighborNatError::EmptyRange)
        ));
        assert!(matches!(
            c.add_neighbor_nat6(7, IP6, 5, 4, [3; 16]),
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
        assert_eq!(stored(&c), prefixes(&[block(IP, 7, 1024, 2048, 4)]));
        assert_counted(&c);
        assert!(
            !c.del_neighbor_nat(7, IP, 20000, 30000).unwrap(),
            "already gone"
        );
        assert_counted(&c);
    }

    #[test]
    fn a_v6_withdraw_removes_exactly_its_prefixes() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16]).unwrap();
        c.add_neighbor_nat6(7, IP6, 1024, 2048, [4; 16]).unwrap();
        assert_counted(&c);
        assert!(c.del_neighbor_nat6(7, IP6, 20000, 30000).unwrap());
        assert_eq!(stored6(&c), prefixes6(&[block6(IP6, 7, 1024, 2048, 4)]));
        assert_counted(&c);
        assert!(
            !c.del_neighbor_nat6(7, IP6, 20000, 30000).unwrap(),
            "already gone"
        );
        assert_counted(&c);
    }

    // 2184 worst-case blocks ([1, 65535): 30 prefixes each) on distinct nat_ips hold 65,520
    // prefixes; 16 one-prefix blocks fill the trie to exactly its capacity, and the next block is
    // refused whole.
    #[test]
    fn the_table_takes_exactly_its_capacity() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let ip = |i: u32| [10, (i >> 16) as u8, (i >> 8) as u8, i as u8];
        assert_eq!(owner_prefixes4(&block(IP, 7, 1, 65535, 1)).len(), 30);
        for i in 0..2184 {
            c.add_neighbor_nat(7, ip(i), 1, 65535, [1; 16]).unwrap();
        }
        for i in 2184..2200 {
            c.add_neighbor_nat(7, ip(i), 1024, 2048, [1; 16]).unwrap();
        }
        assert_eq!(c.w.nat_owners.len(), NAT_OWNERS_MAX as usize);
        assert_counted(&c);
        let err = c
            .add_neighbor_nat(7, ip(2200), 1024, 2048, [1; 16])
            .unwrap_err();
        assert!(
            matches!(
                err,
                NeighborNatError::Full {
                    needed: 1,
                    max: NAT_OWNERS_MAX
                }
            ),
            "{err}"
        );
        assert_eq!(
            c.w.nat_owners.len(),
            NAT_OWNERS_MAX as usize,
            "nothing written"
        );
        assert_counted(&c);
    }

    #[test]
    fn the_v6_table_takes_exactly_its_capacity() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let ip = |i: u32| {
            let mut a = IP6;
            a[12..].copy_from_slice(&i.to_be_bytes());
            a
        };
        assert_eq!(owner_prefixes6(&block6(IP6, 7, 1, 65535, 1)).len(), 30);
        for i in 0..2184 {
            c.add_neighbor_nat6(7, ip(i), 1, 65535, [1; 16]).unwrap();
        }
        for i in 2184..2200 {
            c.add_neighbor_nat6(7, ip(i), 1024, 2048, [1; 16]).unwrap();
        }
        assert_eq!(c.w.nat_owners6.len(), NAT_OWNERS_MAX as usize);
        assert_counted(&c);
        let err = c
            .add_neighbor_nat6(7, ip(2200), 1024, 2048, [1; 16])
            .unwrap_err();
        assert!(
            matches!(
                err,
                NeighborNatError::Full {
                    needed: 1,
                    max: NAT_OWNERS_MAX
                }
            ),
            "{err}"
        );
        assert_eq!(
            c.w.nat_owners6.len(),
            NAT_OWNERS_MAX as usize,
            "nothing written"
        );
        assert_counted(&c);
    }

    // A write failing partway through an add removes what the add wrote: nothing changes.
    #[test]
    fn an_add_that_fails_midway_changes_nothing() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat(7, IP, 1024, 2048, [4; 16]).unwrap();
        c.add_neighbor_nat6(7, IP6, 1024, 2048, [4; 16]).unwrap();
        let before = state(&c);
        let (b, b6) = (
            block(IP, 7, 20000, 30000, 3),
            block6(IP6, 7, 20000, 30000, 3),
        );
        c.w.nat_owner_fault.upsert = Some(nth(&b, 3));
        c.w.nat_owner6_fault.upsert = Some(nth6(&b6, 3));
        assert!(matches!(
            c.add_neighbor_nat(7, IP, 20000, 30000, [3; 16]),
            Err(NeighborNatError::Map(_))
        ));
        assert!(matches!(
            c.add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16]),
            Err(NeighborNatError::Map(_))
        ));
        assert_eq!(state(&c), before);
    }

    // If the rollback fails too, the block is listed and counted anyway: the prefix it left in the
    // trie belongs to a listed block, and a withdraw removes it.
    #[test]
    fn an_add_whose_rollback_fails_stays_listed() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let (b, b6) = (
            block(IP, 7, 20000, 30000, 3),
            block6(IP6, 7, 20000, 30000, 3),
        );
        c.w.nat_owner_fault.upsert = Some(nth(&b, 3));
        c.w.nat_owner_fault.remove = Some(nth(&b, 1));
        c.w.nat_owner6_fault.upsert = Some(nth6(&b6, 3));
        c.w.nat_owner6_fault.remove = Some(nth6(&b6, 1));
        assert!(matches!(
            c.add_neighbor_nat(7, IP, 20000, 30000, [3; 16]),
            Err(NeighborNatError::Map(_))
        ));
        assert!(matches!(
            c.add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16]),
            Err(NeighborNatError::Map(_))
        ));
        assert_eq!(
            state(&c),
            State {
                tries: (vec![owner_prefixes4(&b)[1]], vec![owner_prefixes6(&b6)[1]]),
                blocks: (vec![b], vec![b6]),
                counts: (owner_prefixes4(&b).len(), owner_prefixes6(&b6).len()),
            }
        );

        c.w.nat_owner_fault = Default::default();
        c.w.nat_owner6_fault = Default::default();
        assert!(c.del_neighbor_nat(7, IP, 20000, 30000).unwrap());
        assert!(c.del_neighbor_nat6(7, IP6, 20000, 30000).unwrap());
        assert_eq!(state(&c), state(&ControlCore::new(MemMapWriter::default())));
    }

    // A withdraw whose removal fails still removes every other prefix, and keeps the block listed
    // and counted so a retry finds it: no prefix outlives its listed block.
    #[test]
    fn a_withdraw_that_fails_keeps_the_block_for_a_retry() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat(7, IP, 20000, 30000, [3; 16]).unwrap();
        c.add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16]).unwrap();
        let (b, b6) = (
            block(IP, 7, 20000, 30000, 3),
            block6(IP6, 7, 20000, 30000, 3),
        );
        c.w.nat_owner_fault.remove = Some(nth(&b, 0));
        c.w.nat_owner6_fault.remove = Some(nth6(&b6, 0));
        assert!(matches!(
            c.del_neighbor_nat(7, IP, 20000, 30000),
            Err(NeighborNatError::Map(_))
        ));
        assert!(matches!(
            c.del_neighbor_nat6(7, IP6, 20000, 30000),
            Err(NeighborNatError::Map(_))
        ));
        assert_eq!(
            state(&c),
            State {
                tries: (vec![owner_prefixes4(&b)[0]], vec![owner_prefixes6(&b6)[0]]),
                blocks: (vec![b], vec![b6]),
                counts: (owner_prefixes4(&b).len(), owner_prefixes6(&b6).len()),
            }
        );

        c.w.nat_owner_fault = Default::default();
        c.w.nat_owner6_fault = Default::default();
        assert!(c.del_neighbor_nat(7, IP, 20000, 30000).unwrap());
        assert!(c.del_neighbor_nat6(7, IP6, 20000, 30000).unwrap());
        assert_eq!(state(&c), state(&ControlCore::new(MemMapWriter::default())));
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
            .add_neighbor_nat6(9, IP6, 1024, 2048, [5; 16])
            .unwrap();
        let want = state(&before);
        let mut c = ControlCore::new(before.w);
        c.adopt_nat_owners();
        assert_eq!(state(&c), want);

        // A re-announce, as the handler does it: withdraw, then add the same block.
        assert!(c.del_neighbor_nat(7, IP, 20000, 30000).unwrap());
        c.add_neighbor_nat(7, IP, 20000, 30000, [3; 16]).unwrap();
        assert!(c.del_neighbor_nat6(9, IP6, 1024, 2048).unwrap());
        c.add_neighbor_nat6(9, IP6, 1024, 2048, [5; 16]).unwrap();
        assert_eq!(state(&c), want, "a re-announce changes nothing");

        assert!(c.del_neighbor_nat(7, IP, 20000, 30000).unwrap());
        assert!(c.del_neighbor_nat6(9, IP6, 1024, 2048).unwrap());
        assert!(c.w.nat_owners.is_empty() && c.w.nat_owners6.is_empty());
        assert_counted(&c);
    }

    // A crash between two prefix writes leaves part of a block in the pinned trie. Adopt must make
    // it whole again, or its missing ports have no owner and the prefix count disagrees with the
    // trie.
    #[test]
    fn adopt_completes_a_block_a_crash_left_partial() {
        let mut before = ControlCore::new(MemMapWriter::default());
        before
            .add_neighbor_nat(7, IP, 20000, 30000, [3; 16])
            .unwrap();
        before
            .add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16])
            .unwrap();
        let want = state(&before);
        let (full4, full6) = want.tries.clone();
        assert!(full4.len() > 1 && full6.len() > 1, "multi-prefix blocks");
        let (p, k, _) = full4[full4.len() / 2];
        before.w.nat_owners.remove(&(p, k));
        let (p6, k6, _) = full6[0];
        before.w.nat_owners6.remove(&(p6, k6));

        let mut c = ControlCore::new(before.w);
        c.adopt_nat_owners();
        assert_eq!(state(&c), want);

        assert!(c.del_neighbor_nat(7, IP, 20000, 30000).unwrap());
        assert!(c.del_neighbor_nat6(7, IP6, 20000, 30000).unwrap());
        assert!(c.w.nat_owners.is_empty() && c.w.nat_owners6.is_empty());
        assert_eq!((c.nat_owner_count4, c.nat_owner_count6), (0, 0));
    }
}
