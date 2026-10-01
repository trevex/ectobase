//! Load-balancer (`LB`/`MAGLEV`) programming (backend-agnostic core).
//!
//! Moved verbatim out of the eBPF `Control` (control/lb.rs), applying the MapWriter transform:
//! `g.lbs` -> `self.lbs`, `g.next_table_id` -> `self.next_table_id`, `g.lb`/`g.maglev`/`g.underlay`
//! map ops -> `self.w.<map>_<op>`, and `crate::maglev::build` -> `crate::maglev::build`.

use std::collections::{BTreeMap, BTreeSet};

use crate::shadow::{LbEntry, LbIp, LbIpBytes};
use crate::{ControlCore, MapWriter};
use flowplane_common::{LbBackend, LbKey, LbKey6, LbValue, MaglevKey};

/// An LB's (port, proto) service rows, by the table each points at.
type RowsByTable = BTreeMap<u32, Vec<(u16, u8)>>;

/// One LB service row, in whichever family map owns it. The two families live in separate maps
/// (`LB` keyed on 4 bytes, `LB6` on the full 16) so a v6 address is never truncated into a v4 key;
/// this keeps the register/unwind/delete paths from having to branch at every call site.
#[derive(Copy, Clone)]
enum LbRowKey {
    V4(LbKey),
    V6(LbKey6),
}

impl LbRowKey {
    fn new(ip: &LbIp, vni: u32, port: u16, proto: u8) -> Self {
        match ip {
            LbIp::Ipv4(a) => LbRowKey::V4(LbKey {
                vni,
                ipv4: *a,
                port,
                proto,
                _pad: 0,
            }),
            LbIp::Ipv6(a) => LbRowKey::V6(LbKey6 {
                vni,
                ipv6: *a,
                port,
                proto,
                _pad: 0,
            }),
        }
    }

    fn upsert<W: MapWriter>(&self, w: &mut W, val: LbValue) -> anyhow::Result<()> {
        match self {
            LbRowKey::V4(k) => w.lb_upsert(*k, val),
            LbRowKey::V6(k) => w.lb6_upsert(*k, val),
        }
    }

    fn remove<W: MapWriter>(&self, w: &mut W) -> anyhow::Result<()> {
        match self {
            LbRowKey::V4(k) => w.lb_remove(k),
            LbRowKey::V6(k) => w.lb6_remove(k),
        }
    }
}

impl<W: MapWriter> ControlCore<W> {
    /// Whether any registered load balancer still lives on `vni` (the eBPF `detach_interface`
    /// VNI-reset half of the "is this VNI still in use?" decision). Adopted ones count: their rows
    /// still answer.
    pub fn vni_has_lb(&self, vni: u32) -> bool {
        self.lbs
            .values()
            .chain(&self.adopted_lbs)
            .any(|lb| lb.vni == vni)
    }

    /// Adopt after a restart: the pinned `LB`, `LB6` and `MAGLEV` maps survived, `lbs` and the
    /// table-id counter did not. A counter back at 1 hands a new LB a table a live LB still points
    /// at, and the new LB's backends take over the old one's traffic; an LB missing from `lbs`
    /// can be neither deleted nor given a backend. Returns how many LBs came back.
    ///
    /// The maps hold everything but an LB's id: its service rows name its address, VNI, ports and
    /// table, and each table slot is a whole backend. So the LBs wait in `adopted_lbs` until a call
    /// names one by its address (`claim_lb`). The backends come back in the order their first slot
    /// comes up: the order `maglev::build` was given is not in the maps, and any order rebuilds to
    /// nearly the same table on the next change.
    ///
    /// An LB is an address in a VNI. The counter reset could re-create one under a new table while
    /// some of its ports kept the old: its rows then point at two tables. It is adopted as one LB
    /// on the table most of its rows use (the lowest id on a tie, arbitrary but deterministic);
    /// the other rows keep forwarding as they were, and the delete takes every table.
    ///
    /// The counter resumes above every table id either map still holds, so no id is handed out
    /// twice. Repairs, as the other adopts do: a table no row points at (a delete cut between its
    /// rows and its slots) is removed, a table missing slots (a rebuild cut short) is rewritten
    /// whole, and an address sharing its table with another (left by the counter reset) gets a
    /// copy of its own, so it forwards as before but no longer changes with the other.
    ///
    /// A walk a read error cut short makes live rows and slots look missing, and every repair
    /// would act on that. So then nothing is repaired: what was read is adopted, and the error is
    /// returned. The counter only clears the ids that were read.
    pub fn adopt_lbs(&mut self) -> anyhow::Result<usize> {
        let (lb, lb6, maglev) = (
            self.w.lb_entries(),
            self.w.lb6_entries(),
            self.w.maglev_entries(),
        );
        // Service rows by LB (one address in one VNI), then by the table each row points at.
        let mut rows: BTreeMap<(u32, LbIp), RowsByTable> = BTreeMap::new();
        let v4 = lb.entries.into_iter().map(|(k, v)| {
            let row = (k.port, k.proto);
            ((k.vni, LbIp::Ipv4(k.ipv4)), v.table_id, row)
        });
        let v6 = lb6.entries.into_iter().map(|(k, v)| {
            let row = (k.port, k.proto);
            ((k.vni, LbIp::Ipv6(k.ipv6)), v.table_id, row)
        });
        for (lb, table_id, row) in v4.chain(v6) {
            let on = rows.entry(lb).or_default();
            on.entry(table_id).or_default().push(row);
        }
        let mut tables: BTreeMap<u32, BTreeMap<u32, LbBackend>> = BTreeMap::new();
        for (k, b) in maglev.entries {
            tables.entry(k.table_id).or_default().insert(k.slot, b);
        }
        let error = lb.error.or(lb6.error).or(maglev.error);
        let whole = error.is_none();

        let referenced: BTreeSet<u32> = rows.values().flat_map(|on| on.keys().copied()).collect();
        let top = referenced
            .iter()
            .chain(tables.keys())
            .copied()
            .max()
            .unwrap_or(0);
        self.next_table_id = self.next_table_id.max(top.saturating_add(1));

        if whole {
            for (&table_id, slots) in &tables {
                if !referenced.contains(&table_id) {
                    for &slot in slots.keys() {
                        let _ = self.w.maglev_remove(&MaglevKey { table_id, slot });
                    }
                }
            }
        }

        self.adopted_lbs.clear();
        let mut owned = BTreeSet::new();
        for ((vni, ip), on) in rows {
            let mut ports = Vec::new();
            // (table id, rows on it, its backends) per table this LB's rows point at.
            let mut its: Vec<(u32, usize, Vec<LbBackend>)> = Vec::new();
            for (mut table_id, on_table) in on {
                let slots = tables.get(&table_id).cloned().unwrap_or_default();
                let mut backends: Vec<LbBackend> = Vec::new();
                for b in slots.values() {
                    if !backends
                        .iter()
                        .any(|x| x.node_vtep == b.node_vtep && x.overlay_ip == b.overlay_ip)
                    {
                        backends.push(*b);
                    }
                }
                if whole && !owned.insert(table_id) {
                    if let Some(copy) = self.copy_table(&slots) {
                        for &(port, proto) in &on_table {
                            let val = LbValue {
                                table_id: copy,
                                size: crate::maglev::TABLE_SIZE,
                            };
                            let _ = LbRowKey::new(&ip, vni, port, proto).upsert(&mut self.w, val);
                        }
                        table_id = copy;
                    }
                }
                if whole
                    && !backends.is_empty()
                    && slots.len() != crate::maglev::TABLE_SIZE as usize
                {
                    let _ = self.write_table(table_id, &backends);
                }
                its.push((table_id, on_table.len(), backends));
                ports.extend(on_table);
            }
            ports.sort_unstable();
            its.sort_by_key(|&(table_id, n, _)| (std::cmp::Reverse(n), table_id));
            let mut its = its.into_iter();
            let Some((table_id, _, backends)) = its.next() else {
                continue;
            };
            self.adopted_lbs.push(LbEntry {
                vni,
                ip,
                lb_underlay: [0; 16],
                ports,
                table_id,
                other_tables: its.map(|t| t.0).collect(),
                backends,
            });
        }
        match error {
            None => Ok(self.adopted_lbs.len()),
            Some(e) => Err(e.context(format!(
                "a walk was cut short: adopted the {} load balancer(s) read, repaired nothing",
                self.adopted_lbs.len()
            ))),
        }
    }

    /// Copy a table's slots under a fresh id. A copy that fails part-way is removed again, and
    /// `None` leaves the address on the shared table.
    fn copy_table(&mut self, slots: &BTreeMap<u32, LbBackend>) -> Option<u32> {
        let table_id = self.next_table_id;
        for (&slot, &b) in slots {
            if self
                .w
                .maglev_upsert(MaglevKey { table_id, slot }, b)
                .is_err()
            {
                for &slot in slots.keys() {
                    let _ = self.w.maglev_remove(&MaglevKey { table_id, slot });
                }
                return None;
            }
        }
        self.next_table_id += 1;
        Some(table_id)
    }

    /// Whether `id` names a load balancer, claiming an adopted one on first use. The maps record
    /// no id, but the mesh agent, the one production caller, names an LB by its address: an id
    /// that parses as the address of exactly one adopted LB becomes that LB's id, whatever its
    /// spelling. More than one (the same address in two VNIs) is refused rather than guessed.
    fn claim_lb(&mut self, id: &[u8]) -> bool {
        if self.lbs.contains_key(id) {
            return true;
        }
        let ip = match std::str::from_utf8(id).map(str::parse) {
            Ok(Ok(std::net::IpAddr::V4(a))) => LbIp::Ipv4(a.octets()),
            Ok(Ok(std::net::IpAddr::V6(a))) => LbIp::Ipv6(a.octets()),
            _ => return false,
        };
        let hits: Vec<usize> = (0..self.adopted_lbs.len())
            .filter(|&i| self.adopted_lbs[i].ip == ip)
            .collect();
        let [i] = hits[..] else {
            return false;
        };
        let lb = self.adopted_lbs.swap_remove(i);
        self.lbs.insert(id.to_vec(), lb);
        true
    }

    /// Write `backends`' Maglev table into every slot of `table_id`.
    fn write_table(&mut self, table_id: u32, backends: &[LbBackend]) -> anyhow::Result<()> {
        let table = crate::maglev::build(backends);
        for (slot, &bi) in table.iter().enumerate() {
            self.w.maglev_upsert(
                MaglevKey {
                    table_id,
                    slot: slot as u32,
                },
                backends[bi as usize],
            )?;
        }
        Ok(())
    }

    /// Remove an LB's service rows and each of its tables no other LB still points at.
    fn clear_lb(&mut self, lb: &LbEntry) {
        for &(port, proto) in &lb.ports {
            let _ = LbRowKey::new(&lb.ip, lb.vni, port, proto).remove(&mut self.w);
        }
        for &table_id in std::iter::once(&lb.table_id).chain(&lb.other_tables) {
            if self
                .lbs
                .values()
                .chain(&self.adopted_lbs)
                .any(|o| o.table_id == table_id || o.other_tables.contains(&table_id))
            {
                continue;
            }
            for slot in 0..crate::maglev::TABLE_SIZE {
                let _ = self.w.maglev_remove(&MaglevKey { table_id, slot });
            }
        }
    }

    /// Register a load balancer: allocate a Maglev table id and program the `LB` map for each
    /// (port, proto) service. Backends are added later via `add_lb_target`.
    pub fn create_lb(
        &mut self,
        id: &[u8],
        vni: u32,
        ip: LbIpBytes,
        lb_underlay: [u8; 16],
        ports: Vec<(u16, u8)>,
    ) -> anyhow::Result<()> {
        if self.claim_lb(id) {
            anyhow::bail!("load balancer already exists");
        }
        let table_id = self.next_table_id;

        let lb_ip = match &ip {
            LbIpBytes::Ipv4(a) => LbIp::Ipv4(*a),
            LbIpBytes::Ipv6(a) => LbIp::Ipv6(*a),
        };
        // An adopted LB on this address the id did not name: this create's rows land on its keys.
        // Replace it, or it stays listed against rows it no longer owns, its table left behind.
        let (stale, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.adopted_lbs)
            .into_iter()
            .partition(|lb| lb.vni == vni && lb.ip == lb_ip);
        self.adopted_lbs = kept;
        for lb in stale {
            self.clear_lb(&lb);
        }
        // Write the per-port LB rows, tracking each so a partial failure can be unwound. Otherwise an
        // upsert error part-way left orphaned LB map rows (and a burned table_id) with NO `lbs`
        // bookkeeping — DelLoadBalancer iterates entry.ports, so it could never reach or remove them.
        let mut written: Vec<LbRowKey> = Vec::with_capacity(ports.len());
        let mut result: anyhow::Result<()> = Ok(());
        for &(port, proto) in &ports {
            let key = LbRowKey::new(&lb_ip, vni, port, proto);
            if let Err(e) = key.upsert(
                &mut self.w,
                LbValue {
                    table_id,
                    size: crate::maglev::TABLE_SIZE,
                },
            ) {
                result = Err(e);
                break;
            }
            written.push(key);
        }
        // Program the LB's own underlay /128 into UNDERLAY so ingress can identify it — but ONLY for
        // overlay (relay) LBs. The WAN edge (vni==0) reaches the LB via wan_rx on a raw WAN frame and
        // never resolves UNDERLAY[lb_underlay]; writing it there would clobber the edge's
        // LOCAL_DELIVER egress entry (attach_edge). So skip the write for vni==0.
        // tap_ifindex=0 and guest_mac=[0;6] because the LB address is anycast (no local tap).
        if result.is_ok() && vni != 0 {
            result = self.w.underlay_upsert(
                lb_underlay,
                flowplane_common::UnderlayValue {
                    vni,
                    tap_ifindex: 0,
                    guest_mac: [0; 6],
                    _pad: [0; 2],
                },
            );
        }
        if let Err(e) = result {
            for key in &written {
                let _ = key.remove(&mut self.w); // unwind the partial LB rows
            }
            return Err(e);
        }
        // All datapath writes succeeded — commit table_id + bookkeeping.
        self.next_table_id += 1;
        self.lbs.insert(
            id.to_vec(),
            LbEntry {
                vni,
                ip: lb_ip,
                lb_underlay,
                ports,
                table_id,
                other_tables: Vec::new(),
                backends: Vec::new(),
            },
        );
        Ok(())
    }

    /// Append a backend to a registered LB and rebuild + write its Maglev table. The backend is
    /// self-describing (`node_vtep` for local-vs-remote + reforward; `overlay_ip`/`vni`/`is_v6` for
    /// local INTERFACES delivery).
    pub fn add_lb_target(
        &mut self,
        id: &[u8],
        backend: flowplane_common::LbBackend,
    ) -> anyhow::Result<()> {
        self.claim_lb(id);
        let entry = self
            .lbs
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("unknown load balancer"))?;
        // Reject duplicates (same node + same overlay IP == same backend).
        if entry
            .backends
            .iter()
            .any(|b| b.overlay_ip == backend.overlay_ip && b.node_vtep == backend.node_vtep)
        {
            anyhow::bail!("load balancer target already exists");
        }
        entry.backends.push(backend);
        let table_id = entry.table_id;
        let backends = entry.backends.clone();
        let table = crate::maglev::build(&backends);
        for (slot, &bi) in table.iter().enumerate() {
            self.w.maglev_upsert(
                MaglevKey {
                    table_id,
                    slot: slot as u32,
                },
                backends[bi as usize],
            )?;
        }
        Ok(())
    }

    /// Remove a backend from an LB, identified by its owner node's underlay `node_vtep` AND its
    /// overlay IP. The overlay IP disambiguates two backends that share the same `node_vtep` — two
    /// guests (pods) backing the same LB address on the SAME node, the normal K8s Service-with-2-pods-on-
    /// one-node case. Matching on `node_vtep` alone (the pre-fix behavior) would remove BOTH such
    /// backends, or whichever happened to match first, on a single-backend withdraw.
    ///
    /// `backend_overlay_ip == [0; 16]` is treated as "not set" (legacy/CLI callers that predate the
    /// overlay-IP disambiguation and never set it): an all-zero overlay IP is never a real guest
    /// overlay address (0.0.0.0 / :: are both unroutable/unspecified), so this falls back to the OLD
    /// node_vtep-only match, removing every backend on that node. Returns true if found, false if
    /// not.
    pub fn del_lb_target(
        &mut self,
        id: &[u8],
        backend_node_vtep: [u8; 16],
        backend_overlay_ip: [u8; 16],
    ) -> anyhow::Result<bool> {
        self.claim_lb(id);
        let entry = self
            .lbs
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("unknown load balancer"))?;
        let before = entry.backends.len();
        let match_overlay_too = backend_overlay_ip != [0u8; 16];
        entry.backends.retain(|b| {
            if match_overlay_too {
                !(b.node_vtep == backend_node_vtep && b.overlay_ip == backend_overlay_ip)
            } else {
                b.node_vtep != backend_node_vtep
            }
        });
        if entry.backends.len() == before {
            return Ok(false);
        }
        // Rebuild Maglev table.
        let table_id = entry.table_id;
        let backends = entry.backends.clone();
        if backends.is_empty() {
            // Clear all Maglev slots.
            for slot in 0..crate::maglev::TABLE_SIZE {
                let _ = self.w.maglev_remove(&MaglevKey { table_id, slot });
            }
        } else {
            let table = crate::maglev::build(&backends);
            for (slot, &bi) in table.iter().enumerate() {
                self.w.maglev_upsert(
                    MaglevKey {
                        table_id,
                        slot: slot as u32,
                    },
                    backends[bi as usize],
                )?;
            }
        }
        Ok(true)
    }

    /// Remove a load balancer: clear its `LB` service entries and `MAGLEV` slots.
    /// Returns true if found and deleted, false if not found.
    pub fn delete_lb(&mut self, id: &[u8]) -> anyhow::Result<bool> {
        if !self.claim_lb(id) {
            return Ok(false);
        }
        let Some(entry) = self.lbs.remove(id) else {
            return Ok(false);
        };
        self.clear_lb(&entry);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::{mem::MemMapWriter, shadow::LbIpBytes, ControlCore, MapWriter};
    use flowplane_common::MaglevKey;

    /// vni==0 (WAN edge) must NOT program UNDERLAY[lb_underlay]; vni!=0 (overlay relay) MUST.
    /// Ported from `control/mod.rs`'s `create_lb_skips_underlay_write_for_wan_edge` (which needed
    /// CAP_BPF); runs here over `MemMapWriter` with no privileges.
    #[test]
    fn create_lb_skips_underlay_write_for_wan_edge() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let lb_ul = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];

        // WAN edge (vni==0): create_lb must NOT program UNDERLAY[lb_underlay].
        c.create_lb(
            b"lb_ip-a",
            0,
            LbIpBytes::Ipv4([203, 0, 113, 50]),
            lb_ul,
            vec![(443, 6)],
        )
        .expect("create_lb vni=0");
        assert!(
            c.writer().underlay_get(&lb_ul).is_none(),
            "vni=0 must NOT write UNDERLAY[lb_underlay]"
        );

        // Overlay relay LB (vni!=0): create_lb MUST program UNDERLAY[lb_underlay].
        c.create_lb(
            b"lb_ip-b",
            100,
            LbIpBytes::Ipv4([10, 0, 100, 1]),
            lb_ul,
            vec![(443, 6)],
        )
        .expect("create_lb vni=100");
        assert!(
            c.writer().underlay_get(&lb_ul).is_some(),
            "vni!=0 must write UNDERLAY[lb_underlay]"
        );
    }

    /// Add/del backend round-trip: adding backends fills all TABLE_SIZE Maglev slots; removing the
    /// last backend clears them.
    #[test]
    fn add_del_backend_programs_maglev_slots() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let lb_ul = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
        c.create_lb(
            b"lb_ip",
            100,
            LbIpBytes::Ipv4([10, 0, 100, 2]),
            lb_ul,
            vec![(443, 6)],
        )
        .expect("create_lb");
        // table_id allocated is 1 (next_table_id starts at 1).
        let table_id = 1u32;

        let node0 = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let node1 = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
        let b0 = flowplane_common::LbBackend {
            node_vtep: node0,
            overlay_ip: [10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vni: 100,
            is_v6: 0,
            _pad: [0; 3],
        };
        let b1 = flowplane_common::LbBackend {
            node_vtep: node1,
            overlay_ip: [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vni: 100,
            is_v6: 0,
            _pad: [0; 3],
        };
        c.add_lb_target(b"lb_ip", b0).expect("add b0");
        c.add_lb_target(b"lb_ip", b1).expect("add b1");
        // All TABLE_SIZE slots filled for this table_id.
        let filled = (0..crate::maglev::TABLE_SIZE)
            .filter(|&slot| {
                c.writer()
                    .maglev
                    .contains_key(&MaglevKey { table_id, slot })
            })
            .count();
        assert_eq!(filled, crate::maglev::TABLE_SIZE as usize);

        // Duplicate backend rejected.
        assert!(c.add_lb_target(b"lb_ip", b0).is_err());

        // Remove one (by node_vtep + overlay_ip): still filled (one backend remains).
        assert!(c
            .del_lb_target(b"lb_ip", node0, b0.overlay_ip)
            .expect("del b0"));
        let filled = (0..crate::maglev::TABLE_SIZE)
            .filter(|&slot| {
                c.writer()
                    .maglev
                    .contains_key(&MaglevKey { table_id, slot })
            })
            .count();
        assert_eq!(filled, crate::maglev::TABLE_SIZE as usize);

        // Remove the last backend: all slots cleared.
        assert!(c
            .del_lb_target(b"lb_ip", node1, b1.overlay_ip)
            .expect("del b1"));
        let filled = (0..crate::maglev::TABLE_SIZE)
            .filter(|&slot| {
                c.writer()
                    .maglev
                    .contains_key(&MaglevKey { table_id, slot })
            })
            .count();
        assert_eq!(filled, 0);

        // delete_lb removes the LB rows.
        assert!(c.delete_lb(b"lb_ip").expect("delete_lb"));
        assert!(!c.delete_lb(b"lb_ip").expect("delete_lb again"));
    }

    /// Two backends behind one LB address on the SAME node (same node_vtep) but with DIFFERENT overlay IPs
    /// — the normal K8s Service-with-2-pods-on-one-node case — must both be addable, and removing one
    /// by (node_vtep, overlay_ip) must leave the other intact. Before this fix, del_lb_target matched
    /// by node_vtep alone and would have deleted BOTH (or, since the first match is removed via
    /// retain, silently removed the wrong one).
    #[test]
    fn del_lb_target_disambiguates_same_node_backends_by_overlay_ip() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let lb_ul = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xcc];
        c.create_lb(
            b"lb_ip",
            100,
            LbIpBytes::Ipv4([10, 0, 100, 3]),
            lb_ul,
            vec![(443, 6)],
        )
        .expect("create_lb");

        // Both backends live on the SAME node (same node_vtep) but back different pods (different
        // overlay_ip).
        let node = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09];
        let first = flowplane_common::LbBackend {
            node_vtep: node,
            overlay_ip: [10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vni: 100,
            is_v6: 0,
            _pad: [0; 3],
        };
        let second = flowplane_common::LbBackend {
            node_vtep: node,
            overlay_ip: [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vni: 100,
            is_v6: 0,
            _pad: [0; 3],
        };
        c.add_lb_target(b"lb_ip", first).expect("add first");
        c.add_lb_target(b"lb_ip", second).expect("add second");
        assert_eq!(c.lbs.get(b"lb_ip".as_slice()).unwrap().backends.len(), 2);

        // Remove ONLY the first backend (same node_vtep as the second, distinct overlay_ip).
        assert!(c
            .del_lb_target(b"lb_ip", node, first.overlay_ip)
            .expect("del first"));

        let entry = c.lbs.get(b"lb_ip".as_slice()).unwrap();
        assert_eq!(
            entry.backends.len(),
            1,
            "removing one same-node backend must not remove the other"
        );
        assert_eq!(
            entry.backends[0].overlay_ip, second.overlay_ip,
            "the surviving backend must be the SECOND one, not the first"
        );
    }

    /// Legacy/CLI callers that don't set an overlay IP pass an all-zero `backend_overlay_ip`. That
    /// must fall back to the OLD node_vtep-only match (removing every backend on that node), so older
    /// callers keep working exactly as before this fix — it must NOT touch a backend on another node.
    #[test]
    fn del_lb_target_zero_overlay_falls_back_to_node_vtep_match_removing_all() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let lb_ul = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xdd];
        c.create_lb(
            b"lb_ip",
            100,
            LbIpBytes::Ipv4([10, 0, 100, 4]),
            lb_ul,
            vec![(443, 6)],
        )
        .expect("create_lb");

        let node = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a];
        let other_node = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b];
        let a = flowplane_common::LbBackend {
            node_vtep: node,
            overlay_ip: [10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vni: 100,
            is_v6: 0,
            _pad: [0; 3],
        };
        let b = flowplane_common::LbBackend {
            node_vtep: node,
            overlay_ip: [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vni: 100,
            is_v6: 0,
            _pad: [0; 3],
        };
        let elsewhere = flowplane_common::LbBackend {
            node_vtep: other_node,
            overlay_ip: [10, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vni: 100,
            is_v6: 0,
            _pad: [0; 3],
        };
        c.add_lb_target(b"lb_ip", a).expect("add a");
        c.add_lb_target(b"lb_ip", b).expect("add b");
        c.add_lb_target(b"lb_ip", elsewhere).expect("add elsewhere");

        assert!(c
            .del_lb_target(b"lb_ip", node, [0u8; 16])
            .expect("legacy del by node_vtep"));

        let entry = c.lbs.get(b"lb_ip".as_slice()).unwrap();
        assert_eq!(
            entry.backends.len(),
            1,
            "legacy zero-overlay del must remove ALL backends on the targeted node"
        );
        assert_eq!(
            entry.backends[0].node_vtep, other_node,
            "a backend on a DIFFERENT node must survive"
        );
    }
    // ---- Adopt after a restart: the pinned LB, LB6 and MAGLEV maps survive, `lbs` and the
    // table-id counter do not.

    use flowplane_common::{LbBackend, LbKey, LbKey6, LbValue};
    use std::collections::{BTreeMap, BTreeSet};

    const UL: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe0];
    const A4: [u8; 4] = [203, 0, 113, 50];
    const A6: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50];

    fn backend(node: u8, ip: u8) -> LbBackend {
        LbBackend {
            node_vtep: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, node],
            overlay_ip: [10, 0, 0, ip, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vni: 100,
            is_v6: 0,
            _pad: [0; 3],
        }
    }

    fn key4(ip: [u8; 4], port: u16) -> LbKey {
        LbKey {
            vni: 0,
            ipv4: ip,
            port,
            proto: 6,
            _pad: 0,
        }
    }

    fn key6(ip: [u8; 16], port: u16) -> LbKey6 {
        LbKey6 {
            vni: 0,
            ipv6: ip,
            port,
            proto: 6,
            _pad: 0,
        }
    }

    /// The process exits and a new one adopts the pinned maps.
    fn restart(c: ControlCore<MemMapWriter>) -> ControlCore<MemMapWriter> {
        let mut c = ControlCore::new(c.w);
        c.adopt_lbs().expect("adopt");
        c
    }

    /// One LB per family on the WAN edge (vni 0, id == its address, as the mesh agent registers
    /// them), each with backends.
    fn two_lbs() -> ControlCore<MemMapWriter> {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.create_lb(
            b"203.0.113.50",
            0,
            LbIpBytes::Ipv4(A4),
            UL,
            vec![(80, 6), (443, 6)],
        )
        .unwrap();
        c.add_lb_target(b"203.0.113.50", backend(1, 5)).unwrap();
        c.add_lb_target(b"203.0.113.50", backend(2, 6)).unwrap();
        c.create_lb(b"2001:db8::50", 0, LbIpBytes::Ipv6(A6), UL, vec![(443, 6)])
            .unwrap();
        c.add_lb_target(b"2001:db8::50", backend(3, 7)).unwrap();
        c
    }

    fn slots(c: &ControlCore<MemMapWriter>, table_id: u32) -> BTreeMap<u32, LbBackend> {
        c.w.maglev
            .iter()
            .filter(|(k, _)| k.table_id == table_id)
            .map(|(k, v)| (k.slot, *v))
            .collect()
    }

    fn tables(c: &ControlCore<MemMapWriter>) -> BTreeSet<u32> {
        c.w.maglev.keys().map(|k| k.table_id).collect()
    }

    /// The distinct backends a table hashes to, by the last byte of their overlay IP.
    fn backends_in(c: &ControlCore<MemMapWriter>, table_id: u32) -> BTreeSet<u8> {
        slots(c, table_id)
            .values()
            .map(|b| b.overlay_ip[3])
            .collect()
    }

    // The counter restarting at 1 handed a new LB the table id a live, pre-restart LB still points
    // at: the new LB's backends overwrote that table and the old LB's traffic went to them.
    #[test]
    fn adopt_never_hands_out_a_live_table_id() {
        let c = two_lbs();
        let before = c.w.maglev.clone();
        let mut c = restart(c);

        let ip = [198, 51, 100, 1];
        c.create_lb(b"198.51.100.1", 0, LbIpBytes::Ipv4(ip), UL, vec![(80, 6)])
            .unwrap();
        c.add_lb_target(b"198.51.100.1", backend(4, 8)).unwrap();
        let new = c.w.lb[&key4(ip, 80)].table_id;
        assert!(
            before.keys().all(|k| k.table_id != new),
            "table {new} is already live"
        );
        for (k, v) in &before {
            assert_eq!(c.w.maglev.get(k), Some(v), "an adopted table changed");
        }
    }

    // A delete for an LB created before the restart found nothing in the empty `lbs`, so its rows
    // kept answering and its table leaked. The mesh agent names an LB by its address, in whatever
    // spelling the address came in.
    #[test]
    fn adopted_lb_is_deleted_by_its_address() {
        let mut c = restart(two_lbs());
        let (t4, t6) = (
            c.w.lb[&key4(A4, 80)].table_id,
            c.w.lb6[&key6(A6, 443)].table_id,
        );

        assert!(!c.delete_lb(b"lb-unknown").unwrap());
        assert!(c.delete_lb(b"203.0.113.50").unwrap());
        assert!(c.w.lb.is_empty(), "both v4 service rows go");
        assert!(slots(&c, t4).is_empty(), "the v4 table goes");
        assert!(!slots(&c, t6).is_empty(), "the v6 LB is untouched");

        assert!(c.delete_lb(b"2001:DB8:0::50").unwrap());
        assert!(c.w.lb6.is_empty());
        assert!(c.w.maglev.is_empty());
        assert!(!c.delete_lb(b"2001:db8::50").unwrap(), "deleted once");
    }

    // detach_interface keeps a VNI an LB still lives on (vni_has_lb) out of purge_vni; an adopted
    // LB must count, or the detach of the VNI's last interface purges its routes and NATs from
    // under a live LB.
    #[test]
    fn adopted_lb_keeps_its_vni_in_use() {
        let a6 = [0xfd, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut c = ControlCore::new(MemMapWriter::default());
        c.create_lb(
            b"10.0.100.1",
            100,
            LbIpBytes::Ipv4([10, 0, 100, 1]),
            UL,
            vec![(443, 6)],
        )
        .unwrap();
        c.create_lb(b"fd10::1", 110, LbIpBytes::Ipv6(a6), UL, vec![(443, 6)])
            .unwrap();
        let mut c = restart(c);
        assert!(c.vni_has_lb(100) && c.vni_has_lb(110));
        assert!(!c.vni_has_lb(101));
        assert!(c.delete_lb(b"10.0.100.1").unwrap());
        assert!(c.delete_lb(b"fd10::1").unwrap());
        assert!(!c.vni_has_lb(100) && !c.vni_has_lb(110));
    }

    // flowplane restarts under a running agent (an upgrade restarts flowplane alone). The agent
    // keeps its view of each LB and sends only changes: a new backend, a withdrawn one. Both have
    // to land on the adopted LB, whose backends came back from its table.
    #[test]
    fn a_running_agent_keeps_managing_an_adopted_lb() {
        let mut c = restart(two_lbs());
        let t4 = c.w.lb[&key4(A4, 443)].table_id;
        c.add_lb_target(b"203.0.113.50", backend(9, 9)).unwrap();
        assert!(
            c.add_lb_target(b"203.0.113.50", backend(1, 5)).is_err(),
            "an adopted backend is attached already"
        );
        let gone = backend(1, 5);
        assert!(c
            .del_lb_target(b"203.0.113.50", gone.node_vtep, gone.overlay_ip)
            .unwrap());
        assert_eq!(backends_in(&c, t4), BTreeSet::from([6, 9]));
        assert_eq!(slots(&c, t4).len(), crate::maglev::TABLE_SIZE as usize);

        let t6 = c.w.lb6[&key6(A6, 443)].table_id;
        c.add_lb_target(b"2001:db8::50", backend(8, 8)).unwrap();
        assert_eq!(backends_in(&c, t6), BTreeSet::from([7, 8]));
        let gone = backend(3, 7);
        assert!(c
            .del_lb_target(b"2001:db8::50", gone.node_vtep, gone.overlay_ip)
            .unwrap());
        assert_eq!(backends_in(&c, t6), BTreeSet::from([8]));
    }

    // Both restarted: the fresh agent registers each LB as new and, refused because it exists,
    // deletes and re-creates it, then re-adds every backend. That has to converge on one table per
    // LB, none left behind.
    #[test]
    fn a_restarted_agent_recreates_an_adopted_lb_without_leaking() {
        let mut c = restart(two_lbs());
        let old = tables(&c);
        for (id, v6) in [(&b"203.0.113.50"[..], false), (b"2001:db8::50", true)] {
            let ip = || {
                if v6 {
                    LbIpBytes::Ipv6(A6)
                } else {
                    LbIpBytes::Ipv4(A4)
                }
            };
            assert!(c.create_lb(id, 0, ip(), UL, vec![(443, 6)]).is_err());
            assert!(c.delete_lb(id).unwrap());
            c.create_lb(id, 0, ip(), UL, vec![(443, 6)]).unwrap();
        }
        c.add_lb_target(b"203.0.113.50", backend(1, 5)).unwrap();
        c.add_lb_target(b"203.0.113.50", backend(2, 6)).unwrap();
        c.add_lb_target(b"2001:db8::50", backend(3, 7)).unwrap();

        let (t4, t6) = (
            c.w.lb[&key4(A4, 443)].table_id,
            c.w.lb6[&key6(A6, 443)].table_id,
        );
        assert_eq!(tables(&c), BTreeSet::from([t4, t6]), "no table left behind");
        assert!(old.is_disjoint(&BTreeSet::from([t4, t6])));
        assert_eq!(c.w.lb.len(), 1, "the dropped port's row goes too");
        assert_eq!(backends_in(&c, t4), BTreeSet::from([5, 6]));
        assert_eq!(backends_in(&c, t6), BTreeSet::from([7]));
    }

    // A create under an id that is not the address cannot claim the adopted LB on that address,
    // but its rows land on the same keys: it replaces the adopted LB, rather than leaving it listed
    // against rows it no longer owns and its table behind.
    #[test]
    fn a_create_on_an_adopted_address_replaces_it() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.create_lb(b"lb-a", 0, LbIpBytes::Ipv4(A4), UL, vec![(80, 6), (443, 6)])
            .unwrap();
        c.add_lb_target(b"lb-a", backend(1, 5)).unwrap();
        let mut c = restart(c);
        c.create_lb(b"lb-b", 0, LbIpBytes::Ipv4(A4), UL, vec![(443, 6)])
            .unwrap();
        assert_eq!(c.w.lb.len(), 1, "the replaced LB's other row goes");
        assert!(c.w.maglev.is_empty(), "the replaced LB's table goes");
        assert!(c.delete_lb(b"lb-b").unwrap());
        assert!(c.w.lb.is_empty());
        assert!(!c.vni_has_lb(0));
    }

    // What a crash or an older build can leave in the maps, and adopt cleans up: a table no row
    // points at (a delete cut between its rows and its slots), a table missing slots (a rebuild
    // cut short) and two addresses sharing one table (the counter reset this fixes).
    #[test]
    fn adopt_repairs_what_a_crash_left() {
        let shared = [198, 51, 100, 9];
        let full = crate::maglev::TABLE_SIZE as usize;
        let mut c = restart(damaged());
        assert!(slots(&c, 77).is_empty(), "the orphan table goes");
        let (a, b) = (
            c.w.lb[&key4(A4, 443)].table_id,
            c.w.lb[&key4(shared, 443)].table_id,
        );
        assert_eq!(c.w.lb[&key4(A4, 80)].table_id, a, "one LB, one table");
        assert_ne!(a, b, "each address gets a table of its own");
        assert_eq!(slots(&c, a).len(), full, "the partial table is refilled");
        assert_eq!(backends_in(&c, a), BTreeSet::from([5, 6]));
        assert_eq!(slots(&c, b), slots(&c, a), "forwarding as it was");
        assert!(c.delete_lb(b"203.0.113.50").unwrap());
        assert_eq!(slots(&c, b).len(), full, "deleting one leaves the other");
        assert!(c.delete_lb(b"198.51.100.9").unwrap());
        assert!(c.w.lb.is_empty());
        let t6 = c.w.lb6[&key6(A6, 443)].table_id;
        assert_eq!(
            tables(&c),
            BTreeSet::from([t6]),
            "only the v6 LB's table is left"
        );
    }

    /// The damage `adopt_repairs_what_a_crash_left` repairs: an orphan table (77), a table missing
    /// slots (the v4 LB's) and a second address on that same table.
    fn damaged() -> ControlCore<MemMapWriter> {
        let mut c = two_lbs();
        let t4 = c.w.lb[&key4(A4, 443)].table_id;
        c.w.maglev_upsert(
            MaglevKey {
                table_id: 77,
                slot: 3,
            },
            backend(1, 5),
        )
        .unwrap();
        for slot in 0..100 {
            c.w.maglev.remove(&MaglevKey { table_id: t4, slot });
        }
        c.w.lb_upsert(
            key4([198, 51, 100, 9], 443),
            LbValue {
                table_id: t4,
                size: crate::maglev::TABLE_SIZE,
            },
        )
        .unwrap();
        c
    }

    // A walk a read error cut short reads live rows and slots as missing: a live table would look
    // orphaned and be deleted, a whole one partial and be rewritten. Adopt takes what it read and
    // repairs nothing, and says so.
    #[test]
    fn a_cut_walk_adopts_what_it_read_and_repairs_nothing() {
        let mut w = damaged().w;
        w.lb_walk_cut = Some(1);
        let (lb, lb6, maglev) = (w.lb.clone(), w.lb6.clone(), w.maglev.clone());
        let mut c = ControlCore::new(w);
        assert!(c.adopt_lbs().is_err(), "a cut walk is reported");
        assert_eq!(c.w.lb, lb);
        assert_eq!(c.w.lb6, lb6);
        assert!(c.w.maglev == maglev, "no table removed or rewritten");

        // The one v6 row was read, so that LB is adopted and its delete is whole.
        let t6 = c.w.lb6[&key6(A6, 443)].table_id;
        assert!(c.delete_lb(b"2001:db8::50").unwrap());
        assert!(c.w.lb6.is_empty());
        assert!(slots(&c, t6).is_empty());
    }

    // The counter reset could also re-create an address under a new table while some of its
    // ports kept the old one. It is still one LB: the delete by its address takes every row and
    // both tables.
    #[test]
    fn an_address_on_two_tables_is_one_lb() {
        let mut c = two_lbs();
        for slot in 0..crate::maglev::TABLE_SIZE {
            c.w.maglev_upsert(MaglevKey { table_id: 9, slot }, backend(4, 8))
                .unwrap();
        }
        c.w.lb_upsert(
            key4(A4, 80),
            LbValue {
                table_id: 9,
                size: crate::maglev::TABLE_SIZE,
            },
        )
        .unwrap();
        let mut c = ControlCore::new(c.w);
        assert_eq!(c.adopt_lbs().unwrap(), 2, "one LB per address");
        assert!(c.w.maglev.keys().any(|k| k.table_id == 9), "kept as it was");
        assert!(c.delete_lb(b"203.0.113.50").unwrap());
        assert!(c.w.lb.is_empty());
        let t6 = c.w.lb6[&key6(A6, 443)].table_id;
        assert_eq!(tables(&c), BTreeSet::from([t6]), "both its tables go");
    }
}
