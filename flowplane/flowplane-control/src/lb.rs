//! Load-balancer (`LB`/`MAGLEV`) programming (backend-agnostic core).
//!
//! Moved verbatim out of the eBPF `Control` (control/lb.rs), applying the MapWriter transform:
//! `g.lbs` -> `self.lbs`, `g.next_table_id` -> `self.next_table_id`, `g.lb`/`g.maglev`/`g.underlay`
//! map ops -> `self.w.<map>_<op>`, and `crate::maglev::build` -> `crate::maglev::build`.

use crate::shadow::{LbEntry, LbIp, LbIpBytes};
use crate::{ControlCore, MapWriter};
use flowplane_common::{LbKey, LbValue, MaglevKey};

impl<W: MapWriter> ControlCore<W> {
    /// Whether any registered load balancer still lives on `vni` (the eBPF `detach_interface`
    /// VNI-reset half of the "is this VNI still in use?" decision).
    pub fn vni_has_lb(&self, vni: u32) -> bool {
        self.lbs.values().any(|lb| lb.vni == vni)
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
        if self.lbs.contains_key(id) {
            anyhow::bail!("load balancer already exists");
        }
        let table_id = self.next_table_id;

        let lb_ip = match &ip {
            LbIpBytes::Ipv4(a) => LbIp::Ipv4(*a),
            LbIpBytes::Ipv6(a) => LbIp::Ipv6(*a),
        };
        let lb_ip_bytes4 = lb_ip.last4();

        // Write the per-port LB rows, tracking each so a partial failure can be unwound. Otherwise an
        // upsert error part-way left orphaned LB map rows (and a burned table_id) with NO `lbs`
        // bookkeeping — DelLbVip iterates entry.ports, so it could never reach or remove them.
        let mut written: Vec<LbKey> = Vec::with_capacity(ports.len());
        let mut result: anyhow::Result<()> = Ok(());
        for &(port, proto) in &ports {
            let key = LbKey {
                vni,
                ipv4: lb_ip_bytes4,
                port,
                proto,
                _pad: 0,
            };
            if let Err(e) = self.w.lb_upsert(
                key,
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
        // tap_ifindex=0 and guest_mac=[0;6] because the LB VIP is anycast (no local tap).
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
                let _ = self.w.lb_remove(key); // unwind the partial LB rows
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

    /// Remove a backend from an LB, identified by its owner node's underlay `node_vtep` (the
    /// withdraw path `applyPublic` -> `DelLbBackend` is keyed on the backend node's owner underlay,
    /// not the per-backend overlay IP). Returns true if found, false if not.
    pub fn del_lb_target(
        &mut self,
        id: &[u8],
        backend_node_vtep: [u8; 16],
    ) -> anyhow::Result<bool> {
        let entry = self
            .lbs
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("unknown load balancer"))?;
        let before = entry.backends.len();
        entry.backends.retain(|b| b.node_vtep != backend_node_vtep);
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
        let entry = match self.lbs.remove(id) {
            Some(e) => e,
            None => return Ok(false),
        };
        let ip4 = entry.ip.last4();
        for &(port, proto) in &entry.ports {
            let _ = self.w.lb_remove(&LbKey {
                vni: entry.vni,
                ipv4: ip4,
                port,
                proto,
                _pad: 0,
            });
        }
        for slot in 0..crate::maglev::TABLE_SIZE {
            let _ = self.w.maglev_remove(&MaglevKey {
                table_id: entry.table_id,
                slot,
            });
        }
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
            b"vip-a",
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
            b"vip-b",
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
            b"vip",
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
        c.add_lb_target(b"vip", b0).expect("add b0");
        c.add_lb_target(b"vip", b1).expect("add b1");
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
        assert!(c.add_lb_target(b"vip", b0).is_err());

        // Remove one (by node_vtep): still filled (one backend remains).
        assert!(c.del_lb_target(b"vip", node0).expect("del b0"));
        let filled = (0..crate::maglev::TABLE_SIZE)
            .filter(|&slot| {
                c.writer()
                    .maglev
                    .contains_key(&MaglevKey { table_id, slot })
            })
            .count();
        assert_eq!(filled, crate::maglev::TABLE_SIZE as usize);

        // Remove the last backend: all slots cleared.
        assert!(c.del_lb_target(b"vip", node1).expect("del b1"));
        let filled = (0..crate::maglev::TABLE_SIZE)
            .filter(|&slot| {
                c.writer()
                    .maglev
                    .contains_key(&MaglevKey { table_id, slot })
            })
            .count();
        assert_eq!(filled, 0);

        // delete_lb removes the LB rows.
        assert!(c.delete_lb(b"vip").expect("delete_lb"));
        assert!(!c.delete_lb(b"vip").expect("delete_lb again"));
    }
}
