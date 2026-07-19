//! NAT: guest source-NAT + distributed neighbor-NAT return.
//!
//! Split out of `control.rs`; a child module of `control`, so it reaches
//! `Inner`'s private fields via `super`. Pure code movement — no logic changes.

use flowplane_common::{CtKey, NatKey, NatValue, NeighborNatEntry, NB_MAX_ENTRIES};

use super::{Control, Inner};
use crate::maps::Conntrack;

impl Control {
    /// Program a guest's NAT config: (vni, guest_ip) -> (nat_ip, port_min, port_max).
    /// Returns the underlay route on success.
    pub fn create_nat(
        &self,
        interface_id: &[u8],
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
        preferred_ul: Option<[u8; 16]>,
    ) -> anyhow::Result<[u8; 16]> {
        let mut g = self.inner.lock();
        let rec = g
            .by_id
            .get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
        let underlay = rec.underlay;

        // Check for existing NAT on this interface (any NAT IP).
        if g.nat.get(&NatKey { vni, ipv4: gip }).is_some() {
            anyhow::bail!("SNAT_EXISTS: NAT already configured for this interface");
        }

        // Check for overlapping port range across all interfaces in this VNI with the same nat_ip.
        for r in g.by_id.values() {
            if r.vni == vni {
                if let Some(v) = g.nat.get(&NatKey { vni, ipv4: r.ipv4 }) {
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
            if g.by_id.values().any(|r| r.underlay == pul)
                || g.lbs.values().any(|lb| lb.lb_underlay == pul)
            {
                anyhow::bail!("VNF_INSERT: preferred underlay collision");
            }
        }

        g.nat.upsert(
            NatKey { vni, ipv4: gip },
            NatValue {
                nat_ipv4: nat_ip,
                port_min,
                port_max,
            },
        )?;
        // Mark this nat_ip in NAT_IPS so the ingress can generate ICMP echo replies for it.
        let _ = g.nat_ips.set(vni, nat_ip);
        Ok(preferred_ul.unwrap_or(underlay))
    }

    /// Flush CONNTRACK entries whose egress 5-tuple originated from `(vni, src_ip)`.
    /// For NAT flows this removes both the forward entry (CT_REWRITE_SRC, key.src_ip == gip)
    /// and the reverse entry (CT_REWRITE_DST, key.dst_ip == nat_ip with xlate_port in range).
    fn ct_flush_for_guest(
        ct: &mut Conntrack,
        vni: u32,
        gip: [u8; 4],
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
    ) {
        // Collect all keys to remove first to avoid borrow issues during iteration.
        let to_remove: Vec<CtKey> = ct
            .entries()
            .into_iter()
            .filter_map(|(k, e)| {
                if k.vni != vni {
                    return None;
                }
                // Forward NAT entry: src_ip == guest IP, CT_REWRITE_SRC set.
                let is_fwd = k.src_ip == gip
                    && (e.flags & flowplane_common::CT_REWRITE_SRC != 0
                        || e.flags & flowplane_common::CT_F_SRC_NAT != 0);
                // Reverse NAT entry: dst_ip == nat_ip, dst_port in the NAT port range.
                let is_rev = k.dst_ip == nat_ip
                    && k.dst_port >= port_min
                    && k.dst_port < port_max
                    && e.flags & flowplane_common::CT_REWRITE_DST != 0;
                if is_fwd || is_rev {
                    Some(k)
                } else {
                    None
                }
            })
            .collect();
        for k in to_remove {
            let _ = ct.remove(&k);
        }
    }

    /// Remove a guest's NAT config. Returns true if found and deleted, false if no NAT was set.
    pub fn delete_nat(&self, interface_id: &[u8]) -> anyhow::Result<bool> {
        let (vni, gip, nat_ip, port_min, port_max) = {
            let mut g = self.inner.lock();
            let rec = g
                .by_id
                .get(interface_id)
                .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
            let (vni, gip) = (rec.vni, rec.ipv4);
            let nat_val = match g.nat.get(&NatKey { vni, ipv4: gip }) {
                Some(v) => v,
                None => return Ok(false),
            };
            let nat_ip = nat_val.nat_ipv4;
            let port_min = nat_val.port_min;
            let port_max = nat_val.port_max;
            let _ = g.nat.remove(&NatKey { vni, ipv4: gip });
            // Remove the NAT_IPS marker if no other interface in this VNI uses the same nat_ip.
            let still_used = g.by_id.iter().any(|(other_id, r)| {
                other_id.as_slice() != interface_id
                    && r.vni == vni
                    && g.nat
                        .get(&NatKey {
                            vni: r.vni,
                            ipv4: r.ipv4,
                        })
                        .map(|v| v.nat_ipv4 == nat_ip)
                        .unwrap_or(false)
            });
            if !still_used {
                let _ = g.nat_ips.remove(vni, nat_ip);
            }
            (vni, gip, nat_ip, port_min, port_max)
        };
        // Flush CT entries for this guest outside the inner lock (conntrack lock is separate).
        let mut ct = self.conntrack.lock();
        Self::ct_flush_for_guest(&mut ct, vni, gip, nat_ip, port_min, port_max);
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Neighbor NAT management (distributed NAT return)
    // -----------------------------------------------------------------------

    /// Reprogram NEIGHBOR_NAT and NEIGHBOR_NAT_COUNT from the in-memory vec.
    fn neigh_nat_reprogram(g: &mut Inner) -> anyhow::Result<()> {
        let n = g.neigh_nats.len() as u32;
        for (i, e) in g.neigh_nats.iter().enumerate() {
            g.neigh_nat.upsert(i as u32, *e)?;
        }
        g.neigh_nat_count.set(n)?;
        Ok(())
    }

    /// Add a neighbor-NAT entry (capped at NB_MAX_ENTRIES).
    pub fn add_neighbor_nat(
        &self,
        vni: u32,
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
        underlay: [u8; 16],
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        if g.neigh_nats.len() >= NB_MAX_ENTRIES as usize {
            anyhow::bail!("neighbor NAT table full (max {})", NB_MAX_ENTRIES);
        }
        // Check for duplicate or overlapping port range.
        if g.neigh_nats.iter().any(|e| {
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
        g.neigh_nats.push(NeighborNatEntry {
            underlay,
            nat_ip,
            vni,
            port_min,
            port_max,
            enabled: 1,
            _pad: [0; 3],
        });
        Self::neigh_nat_reprogram(&mut g)
    }

    /// Remove a neighbor-NAT entry matching (vni, nat_ip, port_min, port_max).
    /// Returns true if removed, false if not found.
    pub fn del_neighbor_nat(
        &self,
        vni: u32,
        nat_ip: [u8; 4],
        port_min: u16,
        port_max: u16,
    ) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let before = g.neigh_nats.len();
        g.neigh_nats.retain(|e| {
            !(e.vni == vni
                && e.nat_ip == nat_ip
                && e.port_min == port_min
                && e.port_max == port_max)
        });
        if g.neigh_nats.len() == before {
            return Ok(false);
        }
        Self::neigh_nat_reprogram(&mut g)?;
        Ok(true)
    }
}
