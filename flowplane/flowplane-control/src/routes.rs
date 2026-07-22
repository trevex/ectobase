use crate::{ControlCore, MapWriter};
use flowplane_common::RouteValue;

impl<W: MapWriter> ControlCore<W> {
    pub fn create_route(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
        nexthop_ipv6: [u8; 16],
        nexthop_vni: u32,
        is_external: bool,
    ) -> anyhow::Result<()> {
        // Check for duplicate — routes_shadow is the source of truth.
        if self
            .routes_shadow
            .iter()
            .any(|&(v, p, l, _, _)| v == vni && p == ipv4 && l == prefix_len)
        {
            anyhow::bail!("ROUTE_EXISTS: route already exists");
        }
        self.w.route_upsert(
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
        self.routes_shadow
            .push((vni, ipv4, prefix_len, nexthop_vni, nexthop_ipv6));
        Ok(())
    }

    /// Delete a route. Returns true if found and deleted, false if not found.
    pub fn delete_route(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
    ) -> anyhow::Result<bool> {
        let before = self.routes_shadow.len();
        self.routes_shadow
            .retain(|&(v, p, l, _, _)| !(v == vni && p == ipv4 && l == prefix_len));
        if self.routes_shadow.len() == before {
            return Ok(false);
        }
        let _ = self.w.route_remove(vni, ipv4, prefix_len);
        Ok(true)
    }

    pub fn create_route6(
        &mut self,
        vni: u32,
        ipv6: [u8; 16],
        prefix_len: u32,
        nexthop_ipv6: [u8; 16],
        nexthop_vni: u32,
        is_external: bool,
    ) -> anyhow::Result<()> {
        // Check for duplicate.
        if self
            .routes6_shadow
            .iter()
            .any(|&(v, p, l, _, _)| v == vni && p == ipv6 && l == prefix_len)
        {
            anyhow::bail!("ROUTE_EXISTS: route already exists");
        }
        self.w.route6_upsert(
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
        self.routes6_shadow
            .push((vni, ipv6, prefix_len, nexthop_vni, nexthop_ipv6));
        Ok(())
    }

    /// Delete an IPv6 route. Returns true if found, false if not found.
    pub fn delete_route6(
        &mut self,
        vni: u32,
        ipv6: [u8; 16],
        prefix_len: u32,
    ) -> anyhow::Result<bool> {
        let before = self.routes6_shadow.len();
        self.routes6_shadow
            .retain(|&(v, p, l, _, _)| !(v == vni && p == ipv6 && l == prefix_len));
        if self.routes6_shadow.len() == before {
            return Ok(false);
        }
        let _ = self.w.route6_remove(vni, ipv6, prefix_len);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::MemMapWriter;

    #[test]
    fn create_route_writes_map_and_shadow_and_rejects_dup() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.create_route(7, [10, 0, 0, 0], 24, [0u8; 16], 7, false)
            .unwrap();
        assert!(c.w.routes.contains_key(&(7, [10, 0, 0, 0], 24)));
        assert_eq!(c.routes_shadow.len(), 1);
        assert!(c
            .create_route(7, [10, 0, 0, 0], 24, [0u8; 16], 7, false)
            .is_err());
        assert!(c.delete_route(7, [10, 0, 0, 0], 24).unwrap());
        assert!(!c.w.routes.contains_key(&(7, [10, 0, 0, 0], 24)));
        assert_eq!(c.routes_shadow.len(), 0);
        assert!(!c.delete_route(7, [10, 0, 0, 0], 24).unwrap());
    }
}
