//! NAT: guest source-NAT + distributed neighbor-NAT return (backend-agnostic core).
//!
//! Moved verbatim out of the eBPF `Control` (control/nat.rs), applying the MapWriter transform:
//! `g.by_id` -> `self.ifaces_meta`, `g.lbs` -> `self.lbs`, `g.nat`/`g.nat_ips`/`g.neigh_nat*`
//! map ops -> `self.w.<map>_<op>`, and the CT flush -> `self.w.conntrack_flush(scope)`.

use crate::{ControlCore, CtFlushScope, MapWriter};
use flowplane_common::{NatKey, NatValue, NeighborNatEntry, NB_MAX_ENTRIES};

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
        // Mark this nat_ip in NAT_IPS so the ingress can generate ICMP echo replies for it.
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

    /// Reprogram NEIGHBOR_NAT and NEIGHBOR_NAT_COUNT from the in-memory vec.
    fn neigh_nat_reprogram(&mut self) -> anyhow::Result<()> {
        let n = self.neigh_nats.len() as u32;
        for (i, e) in self.neigh_nats.iter().enumerate() {
            self.w.neigh_nat_upsert(i as u32, *e)?;
        }
        self.w.neigh_nat_count_set(n)?;
        Ok(())
    }

    /// Add a neighbor-NAT entry (capped at NB_MAX_ENTRIES).
    pub fn add_neighbor_nat(
        &mut self,
        vni: u32,
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
        underlay: [u8; 16],
    ) -> anyhow::Result<()> {
        if self.neigh_nats.len() >= NB_MAX_ENTRIES as usize {
            anyhow::bail!("neighbor NAT table full (max {})", NB_MAX_ENTRIES);
        }
        // Check for duplicate or overlapping port range.
        if self.neigh_nats.iter().any(|e| {
            e.nat_ip == nat_ip
                && (
                    // Exact match (same vni and ports) → always duplicate.
                    (e.vni == vni && e.port_min == port_min && e.port_max == port_max)
                // Overlapping port range for the same nat_ip (any vni) → also duplicate.
                || (e.port_min < port_max && e.port_max > port_min)
                )
        }) {
            anyhow::bail!(
                "ALREADY_EXISTS: neighbor NAT entry already exists or port range overlaps"
            );
        }
        self.neigh_nats.push(NeighborNatEntry {
            underlay,
            nat_ip,
            vni,
            port_min,
            port_max,
            enabled: 1,
            _pad: [0; 3],
        });
        self.neigh_nat_reprogram()
    }

    /// Remove a neighbor-NAT entry matching (vni, nat_ip, port_min, port_max).
    /// Returns true if removed, false if not found.
    pub fn del_neighbor_nat(
        &mut self,
        vni: u32,
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
    ) -> anyhow::Result<bool> {
        let before = self.neigh_nats.len();
        self.neigh_nats.retain(|e| {
            !(e.vni == vni
                && e.nat_ip == nat_ip
                && e.port_min == port_min
                && e.port_max == port_max)
        });
        if self.neigh_nats.len() == before {
            return Ok(false);
        }
        self.neigh_nat_reprogram()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::{mem::MemMapWriter, shadow::IfaceMeta, ControlCore};
    use flowplane_common::NeighborNatEntry;

    #[test]
    fn add_and_del_neighbor_nat_programs_maps_and_rejects_overlap() {
        let mut c = ControlCore::new(MemMapWriter::default());

        let vni: u32 = 10;
        let nat_ip: [u8; 4] = [203, 0, 113, 1];
        let underlay: [u8; 16] = [2u8; 16];

        // Add first entry: should write slot 0 and set count to 1.
        c.add_neighbor_nat(vni, nat_ip, 1024, 2048, underlay)
            .unwrap();
        assert_eq!(c.w.neigh_nat_count, 1);
        assert_eq!(
            c.w.neigh_nat.get(&0),
            Some(&NeighborNatEntry {
                underlay,
                nat_ip,
                vni,
                port_min: 1024,
                port_max: 2048,
                enabled: 1,
                _pad: [0; 3],
            })
        );

        // Exact duplicate (same vni + nat_ip + ports) must be rejected.
        assert!(c
            .add_neighbor_nat(vni, nat_ip, 1024, 2048, underlay)
            .is_err());

        // Overlapping port range on the same nat_ip (different vni) must also be rejected.
        // [1500, 3000) overlaps [1024, 2048).
        assert!(c
            .add_neighbor_nat(vni + 1, nat_ip, 1500, 3000, underlay)
            .is_err());

        // Non-overlapping range on a different nat_ip is fine (different nat_ip → no conflict).
        let nat_ip2: [u8; 4] = [203, 0, 113, 2];
        c.add_neighbor_nat(vni, nat_ip2, 1024, 2048, [3u8; 16])
            .unwrap();
        assert_eq!(c.w.neigh_nat_count, 2);

        // Delete the first entry: count drops back to 1 and returns true.
        assert!(c.del_neighbor_nat(vni, nat_ip, 1024, 2048).unwrap());
        assert_eq!(c.w.neigh_nat_count, 1);

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
}
