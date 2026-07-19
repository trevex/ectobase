//! Route table (`ROUTES`/`ROUTES6`) programming.
//!
//! Split out of `control.rs`; a child module of `control`, so it reaches
//! `Inner`'s private fields via `super`. Pure code movement — no logic changes.

use flowplane_common::RouteValue;

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
        // Check for duplicate — routes_shadow is the source of truth.
        if g.routes_shadow
            .iter()
            .any(|&(v, p, l, _, _)| v == vni && p == ipv4 && l == prefix_len)
        {
            anyhow::bail!("ROUTE_EXISTS: route already exists");
        }
        g.routes.upsert(
            vni,
            ipv4,
            prefix_len,
            RouteValue {
                nexthop_vni,
                nexthop_ipv6,
                is_external: is_external as u8,
                _pad: [0; 3],
            },
        )?;
        g.routes_shadow
            .push((vni, ipv4, prefix_len, nexthop_vni, nexthop_ipv6));
        Ok(())
    }

    /// Delete a route. Returns true if found and deleted, false if not found.
    pub fn delete_route(&self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let before = g.routes_shadow.len();
        g.routes_shadow
            .retain(|&(v, p, l, _, _)| !(v == vni && p == ipv4 && l == prefix_len));
        if g.routes_shadow.len() == before {
            return Ok(false);
        }
        let _ = g.routes.remove(vni, ipv4, prefix_len);
        Ok(true)
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
        // Check for duplicate.
        if g.routes6_shadow
            .iter()
            .any(|&(v, p, l, _, _)| v == vni && p == ipv6 && l == prefix_len)
        {
            anyhow::bail!("ROUTE_EXISTS: route already exists");
        }
        g.routes6.upsert(
            vni,
            ipv6,
            prefix_len,
            RouteValue {
                nexthop_vni,
                nexthop_ipv6,
                is_external: is_external as u8,
                _pad: [0; 3],
            },
        )?;
        g.routes6_shadow
            .push((vni, ipv6, prefix_len, nexthop_vni, nexthop_ipv6));
        Ok(())
    }

    /// Delete an IPv6 route. Returns true if found, false if not found.
    pub fn delete_route6(&self, vni: u32, ipv6: [u8; 16], prefix_len: u32) -> anyhow::Result<bool> {
        let mut g = self.inner.lock();
        let before = g.routes6_shadow.len();
        g.routes6_shadow
            .retain(|&(v, p, l, _, _)| !(v == vni && p == ipv6 && l == prefix_len));
        if g.routes6_shadow.len() == before {
            return Ok(false);
        }
        let _ = g.routes6.remove(vni, ipv6, prefix_len);
        Ok(true)
    }
}
