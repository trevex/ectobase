//! NAT: guest source-NAT + distributed neighbor-NAT return (backend-agnostic core).
//!
//! Guest NAT moved verbatim out of the eBPF `Control`, applying the MapWriter
//! transform: `g.by_id` -> `self.ifaces_meta`, `g.lbs` -> `self.lbs`, `g.nat`/`g.nat_ips` map ops
//! -> `self.w.<map>_<op>`, and the CT flush -> `self.w.conntrack_flush(scope)`. Neighbor-NAT blocks
//! are listed in `neigh_nats{,6}` and stored in the `NAT_OWNERS{,6}` tries as their port prefixes
//! (see [`crate::natowner`]); every prefix in a trie belongs to a listed block.

use std::collections::HashSet;

use crate::natowner::{owner_prefixes4, owner_prefixes6};
use crate::ports::port_prefix_count;
use crate::{
    BlockKey4, BlockKey6, ControlCore, CtFlushScope, CtFlushScope6, MapWriter, NeighborNatError,
};
use flowplane_common::{
    NatKey, NatKey6, NatOwnerKey, NatOwnerKey6, NatValue, NatValue6, NeighborNat6Entry,
    NeighborNatEntry, NAT_OWNERS_MAX,
};

/// What a replace did, block by block.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReplaceCounts {
    pub added: u32,
    pub kept: u32,
    pub removed: u32,
}

/// A block's identity for a replace: an owner change is a different block.
type BlockId4 = (u32, [u8; 4], u16, u16, [u8; 16]);
type BlockId6 = (u32, [u8; 16], u16, u16, [u8; 16]);

fn id4(b: &NeighborNatEntry) -> BlockId4 {
    (b.vni, b.nat_ip, b.port_min, b.port_max, b.underlay)
}

fn id6(b: &NeighborNat6Entry) -> BlockId6 {
    (b.vni, b.nat_ip6, b.port_min, b.port_max, b.underlay)
}

/// Refuse a block set no replace could store: an empty range, two blocks overlapping on one
/// nat_ip (in any VNI), or more prefixes than the trie holds. Items are (nat_ip, port_min,
/// port_max, prefix count).
fn check_block_set<A: Ord + Copy>(
    blocks: impl Iterator<Item = (A, u16, u16, usize)>,
) -> Result<(), NeighborNatError> {
    let mut ranges = Vec::new();
    let mut needed = 0usize;
    for (ip, lo, hi, n) in blocks {
        if lo >= hi {
            return Err(NeighborNatError::EmptyRange);
        }
        ranges.push((ip, lo, hi));
        needed += n;
    }
    if needed > NAT_OWNERS_MAX as usize {
        return Err(NeighborNatError::Full {
            needed,
            max: NAT_OWNERS_MAX,
        });
    }
    // Sorted by start, any overlap shows up between neighbours.
    ranges.sort_unstable();
    if ranges
        .windows(2)
        .any(|w| w[0].0 == w[1].0 && w[1].1 < w[0].2)
    {
        return Err(NeighborNatError::Overlap);
    }
    Ok(())
}

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
        if self.overlaps4(nat_ip, port_min, port_max) {
            return Err(NeighborNatError::Overlap);
        }
        self.store_block4(NeighborNatEntry {
            underlay,
            nat_ip,
            vni,
            port_min,
            port_max,
        })
    }

    /// Announce a block, refreshing one that is already there instead of replacing it: the agent
    /// replays every block it knows on each reconnect, and a delete-then-add would leave the
    /// range unprogrammed in between. A block with this exact range (any VNI, any owner) has its
    /// prefixes rewritten in place — the prefix set of a range is the range, so nothing is ever
    /// removed, and each upsert is atomic in the kernel, so a return packet always finds an owner.
    /// Anything else is [`Self::add_neighbor_nat`], overlap check included. A failed upsert leaves
    /// the block listed with a mix of old and new owners on its prefixes; the next replay, or the
    /// next adopt, rewrites them all.
    pub fn upsert_neighbor_nat(
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
        let key = (nat_ip, port_min);
        let listed = self.neigh_nats.get(&key).map(|b| b.port_max) == Some(port_max);
        if !listed {
            return self.add_neighbor_nat(vni, nat_ip, port_min, port_max, underlay);
        }
        let b = NeighborNatEntry {
            underlay,
            nat_ip,
            vni,
            port_min,
            port_max,
        };
        for (plen, k, owner) in owner_prefixes4(&b) {
            self.w.nat_owner_upsert(plen, k, owner)?;
        }
        self.neigh_nats.insert(key, b);
        Ok(())
    }

    /// True if `[lo, hi)` on `nat_ip` overlaps a listed block. Blocks never overlap each other, so
    /// only two can reach into the range: the one that starts at or before `lo`, and the first one
    /// that starts at or after it.
    fn overlaps4(&self, nat_ip: [u8; 4], lo: u16, hi: u16) -> bool {
        if let Some(((ip, _), b)) = self.neigh_nats.range(..=(nat_ip, lo)).next_back() {
            if *ip == nat_ip && b.port_max > lo {
                return true;
            }
        }
        if let Some(((ip, start), _)) = self.neigh_nats.range((nat_ip, lo)..).next() {
            if *ip == nat_ip && *start < hi {
                return true;
            }
        }
        false
    }

    /// Write a block its caller has checked (non-empty, overlapping nothing listed); the capacity
    /// check and the failure contract are [`Self::add_neighbor_nat`]'s.
    fn store_block4(&mut self, b: NeighborNatEntry) -> Result<(), NeighborNatError> {
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
                    self.neigh_nats.insert((b.nat_ip, b.port_min), b);
                }
                return Err(e.into());
            }
        }
        self.nat_owner_count4 += entries.len();
        self.neigh_nats.insert((b.nat_ip, b.port_min), b);
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
        let key = (nat_ip, port_min);
        let Some(b) = self.neigh_nats.get(&key) else {
            return Ok(false);
        };
        // The key names a start; the caller has to name the whole block.
        if b.vni != vni || b.port_max != port_max {
            return Ok(false);
        }
        let entries = owner_prefixes4(b);
        let mut first_err = None;
        for (plen, key, _) in &entries {
            if let Err(e) = self.w.nat_owner_remove(*plen, key) {
                first_err.get_or_insert(e);
            }
        }
        if let Some(e) = first_err {
            return Err(e.into());
        }
        self.neigh_nats.remove(&key);
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
        if self.overlaps6(nat_ip, port_min, port_max) {
            return Err(NeighborNatError::Overlap);
        }
        self.store_block6(NeighborNat6Entry {
            underlay,
            nat_ip6: nat_ip,
            vni,
            port_min,
            port_max,
        })
    }

    /// IPv6 sibling of [`Self::upsert_neighbor_nat`].
    pub fn upsert_neighbor_nat6(
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
        let key = (nat_ip, port_min);
        let listed = self.neigh_nats6.get(&key).map(|b| b.port_max) == Some(port_max);
        if !listed {
            return self.add_neighbor_nat6(vni, nat_ip, port_min, port_max, underlay);
        }
        let b = NeighborNat6Entry {
            underlay,
            nat_ip6: nat_ip,
            vni,
            port_min,
            port_max,
        };
        for (plen, k, owner) in owner_prefixes6(&b) {
            self.w.nat_owner6_upsert(plen, k, owner)?;
        }
        self.neigh_nats6.insert(key, b);
        Ok(())
    }

    /// IPv6 sibling of [`Self::overlaps4`].
    fn overlaps6(&self, nat_ip: [u8; 16], lo: u16, hi: u16) -> bool {
        if let Some(((ip, _), b)) = self.neigh_nats6.range(..=(nat_ip, lo)).next_back() {
            if *ip == nat_ip && b.port_max > lo {
                return true;
            }
        }
        if let Some(((ip, start), _)) = self.neigh_nats6.range((nat_ip, lo)..).next() {
            if *ip == nat_ip && *start < hi {
                return true;
            }
        }
        false
    }

    /// IPv6 sibling of [`Self::store_block4`].
    fn store_block6(&mut self, b: NeighborNat6Entry) -> Result<(), NeighborNatError> {
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
                    self.neigh_nats6.insert((b.nat_ip6, b.port_min), b);
                }
                return Err(e.into());
            }
        }
        self.nat_owner_count6 += entries.len();
        self.neigh_nats6.insert((b.nat_ip6, b.port_min), b);
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
        let key = (nat_ip, port_min);
        let Some(b) = self.neigh_nats6.get(&key) else {
            return Ok(false);
        };
        // The key names a start; the caller has to name the whole block.
        if b.vni != vni || b.port_max != port_max {
            return Ok(false);
        }
        let entries = owner_prefixes6(b);
        let mut first_err = None;
        for (plen, key, _) in &entries {
            if let Err(e) = self.w.nat_owner6_remove(*plen, key) {
                first_err.get_or_insert(e);
            }
        }
        if let Some(e) = first_err {
            return Err(e.into());
        }
        self.neigh_nats6.remove(&key);
        self.nat_owner_count6 -= entries.len();
        Ok(true)
    }

    /// Make the neighbor-NAT blocks exactly `v4` and `v6` — the whole set a complete route-bus
    /// snapshot carries. A block already listed (same VNI, nat_ip, range and owner) is left alone,
    /// so its return traffic never sees a gap. Blocks not in the set are removed first, then new
    /// ones added, so a block that moved to a new range or owner replaces its predecessor in one
    /// call — and a block adopted after a restart that no agent will ever withdraw goes too. The set
    /// is checked whole before anything is written. A map failure part way returns the error with
    /// the invariant intact (every trie prefix belongs to a listed block); the next replace
    /// finishes the job.
    pub fn replace_neighbor_nats(
        &mut self,
        v4: &[NeighborNatEntry],
        v6: &[NeighborNat6Entry],
    ) -> Result<ReplaceCounts, NeighborNatError> {
        // The empty range `check_block_set` refuses is guarded here too: it gets the count first,
        // and `port_max - 1` would underflow on `port_max == 0`.
        let count = |lo: u16, hi: u16| {
            if lo >= hi {
                0
            } else {
                port_prefix_count(lo, hi - 1)
            }
        };
        check_block_set(v4.iter().map(|b| {
            (
                b.nat_ip,
                b.port_min,
                b.port_max,
                count(b.port_min, b.port_max),
            )
        }))?;
        check_block_set(v6.iter().map(|b| {
            (
                b.nat_ip6,
                b.port_min,
                b.port_max,
                count(b.port_min, b.port_max),
            )
        }))?;
        let mut n = ReplaceCounts::default();

        let want4: HashSet<BlockId4> = v4.iter().map(id4).collect();
        let stale4: Vec<NeighborNatEntry> = self
            .neigh_nats
            .values()
            .filter(|b| !want4.contains(&id4(b)))
            .copied()
            .collect();
        for b in stale4 {
            self.del_neighbor_nat(b.vni, b.nat_ip, b.port_min, b.port_max)?;
            n.removed += 1;
        }
        let want6: HashSet<BlockId6> = v6.iter().map(id6).collect();
        let stale6: Vec<NeighborNat6Entry> = self
            .neigh_nats6
            .values()
            .filter(|b| !want6.contains(&id6(b)))
            .copied()
            .collect();
        for b in stale6 {
            self.del_neighbor_nat6(b.vni, b.nat_ip6, b.port_min, b.port_max)?;
            n.removed += 1;
        }

        // Every block still listed is in the set, and the set overlaps nothing in itself, so the
        // overlap scan add_neighbor_nat makes would find nothing: store directly.
        let have4: HashSet<BlockId4> = self.neigh_nats.values().map(id4).collect();
        for b in v4 {
            if have4.contains(&id4(b)) {
                n.kept += 1;
            } else {
                self.store_block4(*b)?;
                n.added += 1;
            }
        }
        let have6: HashSet<BlockId6> = self.neigh_nats6.values().map(id6).collect();
        for b in v6 {
            if have6.contains(&id6(b)) {
                n.kept += 1;
            } else {
                self.store_block6(*b)?;
                n.added += 1;
            }
        }
        Ok(n)
    }

    /// Adopt after a restart: the pinned owner tries survived, the block lists did not. Rebuild
    /// them from the tries' values (each prefix carries its whole block), then rewrite each
    /// block's full prefix set, since a crash between two prefix writes can leave a block partial.
    /// A block a crash left half-withdrawn so comes back whole, and a prefix no rebuilt block owns
    /// is removed, so the invariant holds both ways. Nothing here knows whether an adopted block is
    /// still wanted: if the agent restarted too, it withdraws only what it installed itself, so a
    /// block withdrawn or reassigned while both were down stays listed (and refuses an overlapping
    /// successor) until a declarative sync replaces the set.
    ///
    /// A rebuilt list can hold blocks that overlap, which no listed set ever may: a prefix an
    /// older decomposition or a writer outside this core left can describe a range starting inside
    /// a real block. Those are dropped, keeping the one that starts first — arbitrary but
    /// deterministic, and the next [`Self::replace_neighbor_nats`] corrects the set anyway.
    pub fn adopt_nat_owners(&mut self) {
        // One walk per family: on the aya writer `nat_owner_entries` reads the whole trie by
        // syscall, so the sweep below reuses this list rather than walking it again.
        let walked4 = self.w.nat_owner_entries();
        // Each prefix repeats its block; the index dedups them by key as it is built.
        let mut v4: std::collections::BTreeMap<BlockKey4, NeighborNatEntry> = Default::default();
        for (_, key, o) in &walked4 {
            let b = NeighborNatEntry {
                underlay: o.underlay,
                nat_ip: key.nat_ip,
                vni: o.vni,
                port_min: o.port_min,
                port_max: o.port_max,
            };
            v4.insert((b.nat_ip, b.port_min), b);
        }
        // The map is sorted by (nat_ip, port_min), so one pass over neighbours finds every block
        // that starts inside the last one kept on its nat_ip.
        let mut prev: Option<([u8; 4], u16)> = None; // (nat_ip, port_max)
        v4.retain(|(ip, start), b| {
            let keep = !matches!(prev, Some((p_ip, p_max)) if p_ip == *ip && *start < p_max);
            if keep {
                prev = Some((*ip, b.port_max));
            }
            keep
        });
        self.nat_owner_count4 = 0;
        for b in v4.values() {
            let entries = owner_prefixes4(b);
            self.nat_owner_count4 += entries.len();
            for (plen, key, owner) in entries {
                let _ = self.w.nat_owner_upsert(plen, key, owner);
            }
        }
        self.neigh_nats = v4;
        // Every prefix in the trie must belong to a listed block. Adopt has just rebuilt the list
        // from the trie, so anything left over came from an older decomposition, a writer outside
        // this core (the lab CLI), or a block the overlap pass dropped: remove it rather than
        // relay traffic no block accounts for. Errors are ignored like the repairs above — the
        // next adopt retries. Sweeping the walk instead of re-reading the trie is the same set of
        // candidates: the repairs only ever wrote keys that are in `want4`, so none of them can be
        // one, and a dropped block's prefixes are still in the walk.
        let want4: HashSet<(u32, NatOwnerKey)> = self
            .neigh_nats
            .values()
            .flat_map(owner_prefixes4)
            .map(|(p, k, _)| (p, k))
            .collect();
        for (plen, key, _) in walked4 {
            if !want4.contains(&(plen, key)) {
                let _ = self.w.nat_owner_remove(plen, &key);
            }
        }

        let walked6 = self.w.nat_owner6_entries();
        let mut v6: std::collections::BTreeMap<BlockKey6, NeighborNat6Entry> = Default::default();
        for (_, key, o) in &walked6 {
            let b = NeighborNat6Entry {
                underlay: o.underlay,
                nat_ip6: key.nat_ip6,
                vni: o.vni,
                port_min: o.port_min,
                port_max: o.port_max,
            };
            v6.insert((b.nat_ip6, b.port_min), b);
        }
        let mut prev6: Option<([u8; 16], u16)> = None;
        v6.retain(|(ip, start), b| {
            let keep = !matches!(prev6, Some((p_ip, p_max)) if p_ip == *ip && *start < p_max);
            if keep {
                prev6 = Some((*ip, b.port_max));
            }
            keep
        });
        self.nat_owner_count6 = 0;
        for b in v6.values() {
            let entries = owner_prefixes6(b);
            self.nat_owner_count6 += entries.len();
            for (plen, key, owner) in entries {
                let _ = self.w.nat_owner6_upsert(plen, key, owner);
            }
        }
        self.neigh_nats6 = v6;
        let want6: HashSet<(u32, NatOwnerKey6)> = self
            .neigh_nats6
            .values()
            .flat_map(owner_prefixes6)
            .map(|(p, k, _)| (p, k))
            .collect();
        for (plen, key, _) in walked6 {
            if !want6.contains(&(plen, key)) {
                let _ = self.w.nat_owner6_remove(plen, &key);
            }
        }
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
        ControlCore, MapWriter, NeighborNatError, ReplaceCounts,
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
        }
    }

    fn block6(nat_ip6: [u8; 16], vni: u32, lo: u16, hi: u16, owner: u8) -> NeighborNat6Entry {
        NeighborNat6Entry {
            underlay: [owner; 16],
            nat_ip6,
            vni,
            port_min: lo,
            port_max: hi,
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
            blocks: (
                c.neigh_nats.values().copied().collect::<Vec<_>>(),
                c.neigh_nats6.values().copied().collect::<Vec<_>>(),
            ),
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

    fn counts(added: u32, kept: u32, removed: u32) -> ReplaceCounts {
        ReplaceCounts {
            added,
            kept,
            removed,
        }
    }

    fn add(c: &mut ControlCore<MemMapWriter>, b: NeighborNatEntry) {
        c.add_neighbor_nat(b.vni, b.nat_ip, b.port_min, b.port_max, b.underlay)
            .unwrap();
    }

    // A replace leaves the blocks in the set, removes the ones not in it, and adds the new ones.
    #[test]
    fn replace_adds_keeps_and_removes_by_block() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let a = block(IP, 7, 1024, 2048, 3);
        let b = block(IP, 7, 20000, 30000, 3);
        let d = block([198, 51, 100, 1], 9, 4096, 5000, 4);
        add(&mut c, a);
        add(&mut c, b);
        assert_eq!(
            c.replace_neighbor_nats(&[b, d], &[]).unwrap(),
            counts(1, 1, 1)
        );
        assert_eq!(stored(&c), prefixes(&[b, d]));
        assert_counted(&c);
    }

    // An unchanged block is never rewritten, so its return traffic sees no gap: a fault on
    // rewriting any of its prefixes would fail the replace if it were touched.
    #[test]
    fn replace_leaves_an_unchanged_block_untouched() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let a = block(IP, 7, 20000, 30000, 3);
        add(&mut c, a);
        c.w.nat_owner_fault.upsert = Some(nth(&a, 0));
        c.w.nat_owner_fault.remove = Some(nth(&a, 0));
        let d = block([198, 51, 100, 1], 9, 4096, 5000, 4);
        assert_eq!(
            c.replace_neighbor_nats(&[a, d], &[]).unwrap(),
            counts(1, 1, 0)
        );
        assert_eq!(stored(&c), prefixes(&[a, d]));
    }

    // A block that changed owner is the old block removed and the new one added.
    #[test]
    fn replace_moves_a_block_to_its_new_owner() {
        let mut c = ControlCore::new(MemMapWriter::default());
        add(&mut c, block(IP, 7, 20000, 30000, 3));
        let moved = block(IP, 7, 20000, 30000, 4);
        assert_eq!(
            c.replace_neighbor_nats(&[moved], &[]).unwrap(),
            counts(1, 0, 1)
        );
        assert_eq!(stored(&c), prefixes(&[moved]));
        assert_counted(&c);
    }

    // The set is checked whole before anything is written.
    #[test]
    fn replace_refuses_a_set_it_cannot_store_and_changes_nothing() {
        let mut c = ControlCore::new(MemMapWriter::default());
        add(&mut c, block(IP, 7, 1024, 2048, 3));
        let before = state(&c);

        let overlapping = [block(IP, 7, 20000, 30000, 3), block(IP, 8, 29999, 31000, 4)];
        assert!(matches!(
            c.replace_neighbor_nats(&overlapping, &[]),
            Err(NeighborNatError::Overlap)
        ));
        let empty = [block(IP, 7, 5, 5, 3)];
        assert!(matches!(
            c.replace_neighbor_nats(&empty, &[]),
            Err(NeighborNatError::EmptyRange)
        ));
        let v6_overlap = [block6(IP6, 7, 100, 200, 3), block6(IP6, 7, 150, 250, 3)];
        assert!(matches!(
            c.replace_neighbor_nats(&[], &v6_overlap),
            Err(NeighborNatError::Overlap)
        ));
        // A block overlaps itself, so a set listing one twice is refused like any other overlap.
        let twice = [block(IP, 7, 20000, 30000, 3); 2];
        assert!(matches!(
            c.replace_neighbor_nats(&twice, &[]),
            Err(NeighborNatError::Overlap)
        ));
        // 2185 worst-case blocks ([1, 65535) is 30 prefixes) need 65,550 > 65,536 prefixes.
        let ip = |i: u32| [10, (i >> 16) as u8, (i >> 8) as u8, i as u8];
        let too_many: Vec<_> = (0..2185).map(|i| block(ip(i), 7, 1, 65535, 1)).collect();
        assert!(matches!(
            c.replace_neighbor_nats(&too_many, &[]),
            Err(NeighborNatError::Full { .. })
        ));

        assert_eq!(state(&c), before);
    }

    // Increment 1's gap: after the dataplane AND the agent restarted, a block withdrawn in between
    // is adopted from the pinned trie and no agent will withdraw it. The first complete snapshot's
    // replace removes it, and the block that took its range is admitted.
    #[test]
    fn replace_after_adopt_removes_a_block_no_one_withdrew() {
        let mut before = ControlCore::new(MemMapWriter::default());
        add(&mut before, block(IP, 7, 20000, 30000, 3));
        let mut c = ControlCore::new(before.w);
        c.adopt_nat_owners();
        let successor = block(IP, 8, 25000, 35000, 4);
        assert_eq!(
            c.replace_neighbor_nats(&[successor], &[]).unwrap(),
            counts(1, 0, 1)
        );
        assert_eq!(stored(&c), prefixes(&[successor]));
        assert_counted(&c);
    }

    // A compute node's set is empty: the replace clears whatever an older agent installed.
    #[test]
    fn replace_with_the_empty_set_clears_both_families() {
        let mut c = ControlCore::new(MemMapWriter::default());
        add(&mut c, block(IP, 7, 20000, 30000, 3));
        c.add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16]).unwrap();
        assert_eq!(c.replace_neighbor_nats(&[], &[]).unwrap(), counts(0, 0, 2));
        assert!(stored(&c).is_empty() && stored6(&c).is_empty());
        assert_counted(&c);
    }

    #[test]
    fn replace_handles_the_v6_family() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat6(7, IP6, 1024, 2048, [3; 16]).unwrap();
        let keep = block6(IP6, 7, 1024, 2048, 3);
        let new = block6(IP6, 7, 20000, 30000, 4);
        assert_eq!(
            c.replace_neighbor_nats(&[], &[keep, new]).unwrap(),
            counts(1, 1, 0)
        );
        assert_eq!(stored6(&c), prefixes6(&[keep, new]));
        assert_counted(&c);
    }

    // A snapshot's blocks arrive in no particular order, and the overlap scan only compares
    // neighbours: sorted by start port that finds every overlap and invents none, unsorted it does
    // neither.
    #[test]
    fn replace_judges_an_unsorted_set_by_range_not_arrival_order() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let apart = [
            block(IP, 7, 1024, 2048, 3),
            block(IP, 7, 20000, 30000, 3),
            block(IP, 7, 4096, 5000, 4),
        ];
        assert_eq!(
            c.replace_neighbor_nats(&apart, &[]).unwrap(),
            counts(3, 0, 0)
        );
        assert_counted(&c);
        let before = state(&c);
        let overlapping = [
            block(IP, 7, 1024, 2048, 3),
            block(IP, 7, 20000, 30000, 3),
            block(IP, 7, 1500, 1600, 4),
        ];
        assert!(matches!(
            c.replace_neighbor_nats(&overlapping, &[]),
            Err(NeighborNatError::Overlap)
        ));
        assert_eq!(state(&c), before);
    }

    // A map failure part way through a replace stops it: removals it got to are done, nothing from
    // the set is written, and the block it could not remove is still listed, so every trie prefix
    // still belongs to a listed block. The same call retried once the map works finishes the job.
    #[test]
    fn replace_that_fails_midway_leaves_the_set_for_a_retry() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let stale = block(IP, 7, 20000, 30000, 3);
        add(&mut c, stale);
        c.w.nat_owner_fault.remove = Some(nth(&stale, 0));

        let new = block([198, 51, 100, 1], 9, 4096, 5000, 4);
        assert!(matches!(
            c.replace_neighbor_nats(&[new], &[]),
            Err(NeighborNatError::Map(_))
        ));
        assert_eq!(
            state(&c),
            State {
                tries: (vec![owner_prefixes4(&stale)[0]], Vec::new()),
                blocks: (vec![stale], Vec::new()),
                counts: (owner_prefixes4(&stale).len(), 0),
            },
            "the stale block stays listed and counted; nothing of the set was written"
        );

        c.w.nat_owner_fault = Default::default();
        assert_eq!(
            c.replace_neighbor_nats(&[new], &[]).unwrap(),
            counts(1, 0, 1)
        );
        assert_eq!(stored(&c), prefixes(&[new]));
        assert_counted(&c);
    }

    // v6 sibling of `replace_moves_a_block_to_its_new_owner`: the owner is part of a v6 block's
    // identity too, so a re-announce under a new one is a remove plus an add, not a keep.
    #[test]
    fn replace_moves_a_v6_block_to_its_new_owner() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16]).unwrap();
        let moved = block6(IP6, 7, 20000, 30000, 4);
        assert_eq!(
            c.replace_neighbor_nats(&[], &[moved]).unwrap(),
            counts(1, 0, 1)
        );
        assert_eq!(stored6(&c), prefixes6(&[moved]));
        assert_counted(&c);
    }

    // The VNI is part of a block's identity in both families: the same nat_ip and range under a new
    // VNI is a different block — its trie entries carry the VNI the datapath delivers with.
    #[test]
    fn replace_tells_two_vnis_apart() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let (keep, keep6) = (block(IP, 7, 1024, 2048, 3), block6(IP6, 7, 1024, 2048, 3));
        add(&mut c, keep);
        add(&mut c, block(IP, 8, 20000, 30000, 3));
        c.add_neighbor_nat6(7, IP6, 1024, 2048, [3; 16]).unwrap();
        c.add_neighbor_nat6(8, IP6, 20000, 30000, [3; 16]).unwrap();

        // Only the second block of each family moves VNI; the first is untouched.
        let (revni, revni6) = (
            block(IP, 9, 20000, 30000, 3),
            block6(IP6, 9, 20000, 30000, 3),
        );
        assert_eq!(
            c.replace_neighbor_nats(&[keep, revni], &[keep6, revni6])
                .unwrap(),
            counts(2, 2, 2)
        );
        assert_eq!(stored(&c), prefixes(&[keep, revni]));
        assert_eq!(stored6(&c), prefixes6(&[keep6, revni6]));
        assert_counted(&c);
    }

    // The index is keyed by (nat_ip, port_min), so an overlap check is two neighbour lookups
    // instead of a scan. Pin the shapes those two lookups have to catch: a block that starts
    // before ours and reaches into it, one that starts inside ours, an exact duplicate, and the
    // adjacent ranges that must still be allowed.
    #[test]
    fn the_index_catches_every_overlap_shape() {
        let mut c = ControlCore::new(MemMapWriter::default());
        add(&mut c, block(IP, 7, 20000, 30000, 3));
        for (lo, hi) in [
            (15000, 20001),
            (25000, 26000),
            (20000, 30000),
            (29999, 40000),
            (10000, 40000),
        ] {
            assert!(
                matches!(
                    c.add_neighbor_nat(7, IP, lo, hi, [4; 16]),
                    Err(NeighborNatError::Overlap)
                ),
                "{lo}..{hi} overlaps the listed block"
            );
        }
        // Adjacent on both sides, and the same range on another nat_ip, are not overlaps.
        c.add_neighbor_nat(7, IP, 10000, 20000, [4; 16]).unwrap();
        c.add_neighbor_nat(7, IP, 30000, 40000, [4; 16]).unwrap();
        c.add_neighbor_nat(7, [198, 51, 100, 1], 20000, 30000, [4; 16])
            .unwrap();
        assert_counted(&c);
    }

    // v6 sibling of the test above: the v6 index is its own pair of lookups, and the one that
    // finds a block starting inside the new range is only reached by the shapes the lookup behind
    // it misses.
    #[test]
    fn the_v6_index_catches_every_overlap_shape() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16]).unwrap();
        for (lo, hi) in [
            (15000, 20001),
            (25000, 26000),
            (20000, 30000),
            (29999, 40000),
            (10000, 40000),
        ] {
            assert!(
                matches!(
                    c.add_neighbor_nat6(7, IP6, lo, hi, [4; 16]),
                    Err(NeighborNatError::Overlap)
                ),
                "{lo}..{hi} overlaps the listed block"
            );
        }
        let mut other = IP6;
        other[15] = 1;
        c.add_neighbor_nat6(7, IP6, 10000, 20000, [4; 16]).unwrap();
        c.add_neighbor_nat6(7, IP6, 30000, 40000, [4; 16]).unwrap();
        c.add_neighbor_nat6(7, other, 20000, 30000, [4; 16])
            .unwrap();
        assert_counted(&c);
    }

    // A re-announce refreshes a block that is already there — the agent replays one on every
    // reconnect. Rewriting its prefixes in place keeps the return path programmed throughout; the
    // old delete-then-add left up to 30 prefixes missing in between.
    #[test]
    fn a_reannounce_rewrites_the_block_in_place() {
        let mut c = ControlCore::new(MemMapWriter::default());
        add(&mut c, block(IP, 7, 20000, 30000, 3));
        // A removal of any of its prefixes would fail: the rewrite must not remove anything.
        c.w.nat_owner_fault.remove = Some(nth(&block(IP, 7, 20000, 30000, 3), 0));
        c.upsert_neighbor_nat(9, IP, 20000, 30000, [4; 16]).unwrap();
        assert_eq!(stored(&c), prefixes(&[block(IP, 9, 20000, 30000, 4)]));
        assert_counted(&c);
    }

    #[test]
    fn a_v6_reannounce_rewrites_the_block_in_place() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16]).unwrap();
        c.w.nat_owner6_fault.remove = Some(nth6(&block6(IP6, 7, 20000, 30000, 3), 0));
        c.upsert_neighbor_nat6(9, IP6, 20000, 30000, [4; 16])
            .unwrap();
        assert_eq!(stored6(&c), prefixes6(&[block6(IP6, 9, 20000, 30000, 4)]));
        assert_counted(&c);
    }

    // A block whose range does not exist yet is just an add — including the overlap refusal.
    #[test]
    fn an_upsert_of_a_new_range_is_an_add() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.upsert_neighbor_nat(7, IP, 20000, 30000, [3; 16]).unwrap();
        assert_eq!(stored(&c), prefixes(&[block(IP, 7, 20000, 30000, 3)]));
        assert!(matches!(
            c.upsert_neighbor_nat(7, IP, 25000, 35000, [4; 16]),
            Err(NeighborNatError::Overlap)
        ));
        c.upsert_neighbor_nat6(7, IP6, 20000, 30000, [3; 16])
            .unwrap();
        assert_eq!(stored6(&c), prefixes6(&[block6(IP6, 7, 20000, 30000, 3)]));
        assert!(matches!(
            c.upsert_neighbor_nat6(7, IP6, 25000, 35000, [4; 16]),
            Err(NeighborNatError::Overlap)
        ));
        assert_counted(&c);

        // A block that starts where a listed one does but ends elsewhere is a different block, so
        // it is an add too — and the add overlaps. Refreshing it in place instead would leave the
        // prefixes outside the new range in the trie, owned by nothing listed.
        let before = state(&c);
        assert!(matches!(
            c.upsert_neighbor_nat(7, IP, 20000, 25000, [9; 16]),
            Err(NeighborNatError::Overlap)
        ));
        assert!(matches!(
            c.upsert_neighbor_nat6(7, IP6, 20000, 25000, [9; 16]),
            Err(NeighborNatError::Overlap)
        ));
        assert_eq!(state(&c), before, "nothing written");
    }

    // Adopt rebuilds the blocks from the trie and repairs them — and now also removes what no
    // rebuilt block owns, so a prefix left by an older decomposition or a foreign writer cannot
    // keep relaying traffic that no listed block accounts for. Such a prefix carries a listed
    // block's owner but sits at a port that block's decomposition never produces; one whose owner
    // describes a block of its own is adopted AS that block, which is what adopt is for.
    #[test]
    fn adopt_removes_a_prefix_no_block_owns() {
        let mut before = ControlCore::new(MemMapWriter::default());
        add(&mut before, block(IP, 7, 20000, 30000, 3));
        before
            .add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16])
            .unwrap();
        let (plen, mut key, owner) = owner_prefixes4(&block(IP, 7, 20000, 30000, 3))[0];
        key.port = 40000u16.to_be_bytes();
        before.w.nat_owner_upsert(plen, key, owner).unwrap();
        let (plen6, mut key6, owner6) = owner_prefixes6(&block6(IP6, 7, 20000, 30000, 3))[0];
        key6.port = 40000u16.to_be_bytes();
        before.w.nat_owner6_upsert(plen6, key6, owner6).unwrap();

        let mut c = ControlCore::new(before.w);
        c.adopt_nat_owners();
        assert_eq!(stored(&c), prefixes(&[block(IP, 7, 20000, 30000, 3)]));
        assert_eq!(stored6(&c), prefixes6(&[block6(IP6, 7, 20000, 30000, 3)]));
        assert_counted(&c);
    }

    // Adopt rebuilds the block list from the trie's values, so a prefix a foreign writer left —
    // the lab CLI writes NAT_OWNERS directly — can describe a range starting inside a real block
    // and become a second, overlapping listed block. That breaks the invariant the overlap check
    // rests on (blocks never overlap on one nat_ip), and a later add lands inside a listed block.
    // Adopt keeps the one that starts first and sweeps the other's prefixes.
    #[test]
    fn adopt_never_lists_two_overlapping_blocks() {
        let mut before = ControlCore::new(MemMapWriter::default());
        let real = block(IP, 7, 20000, 30000, 3);
        add(&mut before, real);
        let (plen, mut key, _) = owner_prefixes4(&real)[0];
        key.port = 25000u16.to_be_bytes();
        before
            .w
            .nat_owner_upsert(
                plen,
                key,
                NatOwner {
                    underlay: [9; 16],
                    vni: 7,
                    port_min: 25000,
                    port_max: 26000,
                },
            )
            .unwrap();

        let mut c = ControlCore::new(before.w);
        c.adopt_nat_owners();
        assert_eq!(c.neigh_nats.len(), 1, "one block listed");
        assert_eq!(stored(&c), prefixes(&[real]));
        assert_counted(&c);
        assert!(
            matches!(
                c.add_neighbor_nat(7, IP, 29000, 29500, [4; 16]),
                Err(NeighborNatError::Overlap)
            ),
            "an add inside the surviving block is still refused"
        );
    }

    #[test]
    fn adopt_never_lists_two_overlapping_v6_blocks() {
        let mut before = ControlCore::new(MemMapWriter::default());
        let real = block6(IP6, 7, 20000, 30000, 3);
        before
            .add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16])
            .unwrap();
        let (plen, mut key, _) = owner_prefixes6(&real)[0];
        key.port = 25000u16.to_be_bytes();
        before
            .w
            .nat_owner6_upsert(
                plen,
                key,
                NatOwner {
                    underlay: [9; 16],
                    vni: 7,
                    port_min: 25000,
                    port_max: 26000,
                },
            )
            .unwrap();

        let mut c = ControlCore::new(before.w);
        c.adopt_nat_owners();
        assert_eq!(c.neigh_nats6.len(), 1, "one block listed");
        assert_eq!(stored6(&c), prefixes6(&[real]));
        assert_counted(&c);
        assert!(
            matches!(
                c.add_neighbor_nat6(7, IP6, 29000, 29500, [4; 16]),
                Err(NeighborNatError::Overlap)
            ),
            "an add inside the surviving block is still refused"
        );
    }

    // Deleting names the block by (vni, nat_ip, range): a different VNI or a different end is a
    // different block, and must not remove the one that is there.
    #[test]
    fn a_delete_only_matches_the_whole_block() {
        let mut c = ControlCore::new(MemMapWriter::default());
        add(&mut c, block(IP, 7, 20000, 30000, 3));
        assert!(
            !c.del_neighbor_nat(8, IP, 20000, 30000).unwrap(),
            "another VNI"
        );
        assert!(
            !c.del_neighbor_nat(7, IP, 20000, 29000).unwrap(),
            "another end"
        );
        assert!(
            !c.del_neighbor_nat(7, IP, 21000, 30000).unwrap(),
            "another start"
        );
        assert_eq!(stored(&c), prefixes(&[block(IP, 7, 20000, 30000, 3)]));
        assert!(c.del_neighbor_nat(7, IP, 20000, 30000).unwrap());
        assert!(stored(&c).is_empty());
        assert_counted(&c);
    }

    #[test]
    fn a_v6_delete_only_matches_the_whole_block() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.add_neighbor_nat6(7, IP6, 20000, 30000, [3; 16]).unwrap();
        assert!(
            !c.del_neighbor_nat6(8, IP6, 20000, 30000).unwrap(),
            "another VNI"
        );
        assert!(
            !c.del_neighbor_nat6(7, IP6, 20000, 29000).unwrap(),
            "another end"
        );
        assert!(
            !c.del_neighbor_nat6(7, IP6, 21000, 30000).unwrap(),
            "another start"
        );
        assert_eq!(stored6(&c), prefixes6(&[block6(IP6, 7, 20000, 30000, 3)]));
        assert!(c.del_neighbor_nat6(7, IP6, 20000, 30000).unwrap());
        assert!(stored6(&c).is_empty());
        assert_counted(&c);
    }
}
