//! Route table (`ROUTES`/`ROUTES6`) programming — thin delegations to `ControlCore`.
//!
//! Split out of `control.rs`; a child module of `control`, so it reaches
//! `Inner`'s private fields via `super`. Pure code movement — no logic changes.

use super::Control;

impl Control {
    pub fn create_route(
        &self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
        nexthop_ipv6: [u8; 16],
        nexthop_vni: u32,
        is_external: bool,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        g.core.create_route(
            vni,
            ipv4,
            prefix_len,
            nexthop_ipv6,
            nexthop_vni,
            is_external,
        )
    }

    /// Delete a route. Returns true if found and deleted, false if not found.
    pub fn delete_route(&self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        g.core.delete_route(vni, ipv4, prefix_len)
    }

    pub fn create_route6(
        &self,
        vni: u32,
        ipv6: [u8; 16],
        prefix_len: u32,
        nexthop_ipv6: [u8; 16],
        nexthop_vni: u32,
        is_external: bool,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        g.core.create_route6(
            vni,
            ipv6,
            prefix_len,
            nexthop_ipv6,
            nexthop_vni,
            is_external,
        )
    }

    /// Delete an IPv6 route. Returns true if found, false if not found.
    pub fn delete_route6(&self, vni: u32, ipv6: [u8; 16], prefix_len: u32) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        g.core.delete_route6(vni, ipv6, prefix_len)
    }
}
