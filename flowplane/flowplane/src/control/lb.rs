//! Load-balancer (`LB`/`MAGLEV`) programming.
//!
//! Split out of `control.rs`; a child module of `control`, so it reaches
//! `Inner`'s private fields via `super`. Pure code movement — no logic changes.

use flowplane_common::{LbKey, LbValue, MaglevKey};

use super::{Control, LbEntry, LbIp, LbIpBytes};

impl Control {
    /// Register a load balancer: allocate a Maglev table id and program the `LB` map for each
    /// (port, proto) service. Backends are added later via `add_lb_target`.
    pub fn create_lb(
        &self,
        id: &[u8],
        vni: u32,
        ip: LbIpBytes,
        lb_underlay: [u8; 16],
        ports: Vec<(u16, u8)>,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        if g.lbs.contains_key(id) {
            anyhow::bail!("load balancer already exists");
        }
        let table_id = g.next_table_id;

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
            if let Err(e) = g.lb.upsert(
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
            result = g.underlay.upsert(
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
                let _ = g.lb.remove(key); // unwind the partial LB rows
            }
            return Err(e);
        }
        // All datapath writes succeeded — commit table_id + bookkeeping.
        g.next_table_id += 1;
        g.lbs.insert(
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
        // Mirror the agnostic subset into the core so the NAT preferred-underlay collision check
        // (moved into ControlCore in Task 4) sees this LB's underlay. `Inner.lbs` stays
        // authoritative on `Control` until Task 5.
        g.core.register_lb(
            id.to_vec(),
            flowplane_control::shadow::LbEntry { lb_underlay },
        );
        Ok(())
    }

    /// Append a backend underlay /128 to a registered LB and rebuild + write its Maglev table.
    pub fn add_lb_target(&self, id: &[u8], backend: [u8; 16]) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        let entry = g
            .lbs
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("unknown load balancer"))?;
        // Reject duplicates.
        if entry.backends.contains(&backend) {
            anyhow::bail!("load balancer target already exists");
        }
        entry.backends.push(backend);
        let table_id = entry.table_id;
        let backends = entry.backends.clone();
        let table = crate::maglev::build(&backends);
        for (slot, &bi) in table.iter().enumerate() {
            g.maglev.upsert(
                MaglevKey {
                    table_id,
                    slot: slot as u32,
                },
                backends[bi as usize],
            )?;
        }
        Ok(())
    }

    /// Remove a backend from an LB. Returns true if found, false if not.
    pub fn del_lb_target(&self, id: &[u8], backend: [u8; 16]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let entry = g
            .lbs
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("unknown load balancer"))?;
        let before = entry.backends.len();
        entry.backends.retain(|b| b != &backend);
        if entry.backends.len() == before {
            return Ok(false);
        }
        // Rebuild Maglev table.
        let table_id = entry.table_id;
        let backends = entry.backends.clone();
        if backends.is_empty() {
            // Clear all Maglev slots.
            for slot in 0..crate::maglev::TABLE_SIZE {
                let _ = g.maglev.remove(&MaglevKey { table_id, slot });
            }
        } else {
            let table = crate::maglev::build(&backends);
            for (slot, &bi) in table.iter().enumerate() {
                g.maglev.upsert(
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
    pub fn delete_lb(&self, id: &[u8]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let entry = match g.lbs.remove(id) {
            Some(e) => e,
            None => return Ok(false),
        };
        // Drop the core's agnostic mirror (registered in create_lb).
        g.core.forget_lb(id);
        let ip4 = entry.ip.last4();
        for &(port, proto) in &entry.ports {
            let _ = g.lb.remove(&LbKey {
                vni: entry.vni,
                ipv4: ip4,
                port,
                proto,
                _pad: 0,
            });
        }
        for slot in 0..crate::maglev::TABLE_SIZE {
            let _ = g.maglev.remove(&MaglevKey {
                table_id: entry.table_id,
                slot,
            });
        }
        Ok(true)
    }
}
