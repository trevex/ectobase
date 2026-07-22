//! NAT: guest source-NAT + distributed neighbor-NAT return — thin delegations to `ControlCore`.
//!
//! Split out of `control.rs`; a child module of `control`, so it reaches
//! `Inner`'s private fields via `super`. Pure code movement — no logic changes.

use super::Control;

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
        g.core
            .create_nat(interface_id, nat_ip, port_min, port_max, preferred_ul)
    }

    /// Remove a guest's NAT config. Returns true if found and deleted, false if no NAT was set.
    pub fn delete_nat(&self, interface_id: &[u8]) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        g.core.delete_nat(interface_id)
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
        g.core
            .add_neighbor_nat(vni, nat_ip, port_min, port_max, underlay)
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
        g.core.del_neighbor_nat(vni, nat_ip, port_min, port_max)
    }
}
