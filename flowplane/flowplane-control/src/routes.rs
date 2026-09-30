use crate::{ControlCore, MapWriter};
use flowplane_common::{IfaceKey, IfaceKey6, IfaceValue, RouteValue};

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

    /// Adopt after a restart: the pinned `ROUTES{,6}` tries survived, the shadows did not. Rebuild
    /// them from the tries, or every withdraw finds nothing and leaves its route forwarding.
    ///
    /// The tries also hold each local interface's self-route (`program_interface`), which the
    /// shadows never list, so no withdraw can remove it. Those stay out here too: a host route whose
    /// `INTERFACES{,6}` entry is local and whose nexthop is that interface's own underlay in its own
    /// VNI. A route that overwrote a self-route's key names another nexthop, so it is adopted.
    pub fn adopt_routes(&mut self) {
        let is_self = |iv: Option<IfaceValue>, r: &RouteValue, vni: u32| {
            iv.is_some_and(|iv| {
                iv.is_local == 1
                    && iv.underlay_ipv6 == r.nexthop_ipv6
                    && r.nexthop_vni == vni
                    && r.is_external == 0
            })
        };
        self.routes_shadow = self
            .w
            .route_entries()
            .into_iter()
            .filter(|&(v, p, l, r)| {
                !(l == 32 && is_self(self.w.ifaces_get(&IfaceKey::new(v, p)), &r, v))
            })
            .map(|(v, p, l, r)| (v, p, l, r.nexthop_vni, r.nexthop_ipv6))
            .collect();
        self.routes6_shadow = self
            .w
            .route6_entries()
            .into_iter()
            .filter(|&(v, p, l, r)| {
                !(l == 128 && is_self(self.w.ifaces6_get(&IfaceKey6::new(v, p)), &r, v))
            })
            .map(|(v, p, l, r)| (v, p, l, r.nexthop_vni, r.nexthop_ipv6))
            .collect();
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

    const NH: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
    const P6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    fn sorted<T: Ord>(mut v: Vec<T>) -> Vec<T> {
        v.sort();
        v
    }

    // After a restart the pinned ROUTES{,6} tries survive and the shadows do not. Without adopt a
    // withdraw finds nothing in the empty shadow and leaves the kernel entry in place, so a route
    // the mesh withdraws keeps forwarding.
    #[test]
    fn adopt_rebuilds_the_shadows_so_a_withdraw_removes() {
        let mut before = ControlCore::new(MemMapWriter::default());
        before
            .create_route(100, [10, 0, 0, 61], 32, NH, 100, false)
            .unwrap();
        before
            .create_route(110, [10, 1, 0, 0], 16, NH, 120, true)
            .unwrap();
        before.create_route6(100, P6, 64, NH, 100, false).unwrap();
        before.create_route6(110, P6, 128, NH, 110, true).unwrap();
        let (want4, want6) = (
            sorted(before.routes_shadow.clone()),
            sorted(before.routes6_shadow.clone()),
        );

        let mut c = ControlCore::new(before.w);
        c.adopt_routes();
        assert_eq!(sorted(c.routes_shadow.clone()), want4);
        assert_eq!(sorted(c.routes6_shadow.clone()), want6);

        assert!(c.delete_route(100, [10, 0, 0, 61], 32).unwrap());
        assert!(!c.w.routes.contains_key(&(100, [10, 0, 0, 61], 32)));
        assert!(c.delete_route6(100, P6, 64).unwrap());
        assert!(!c.w.routes6.contains_key(&(100, P6, 64)));
        // The rest is untouched, and a re-announce of an adopted route replaces it.
        assert!(c.w.routes.contains_key(&(110, [10, 1, 0, 0], 16)));
        assert!(c.w.routes6.contains_key(&(110, P6, 128)));
        assert_eq!(c.routes_shadow.len(), 1);
        assert_eq!(c.routes6_shadow.len(), 1);
    }

    // A local interface's self-route lives in ROUTES{,6} but never in a shadow, so no withdraw can
    // take it: adopt must leave it out too. A user route on the same key (a different nexthop) is
    // still a user route.
    #[test]
    fn adopt_leaves_self_routes_out_of_the_shadows() {
        use flowplane_common::{IfaceKey, IfaceKey6, IfaceValue};
        let local = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let iface = IfaceValue {
            tap_ifindex: 42,
            is_local: 1,
            underlay_ipv6: local,
            guest_mac: [2, 0, 0, 0, 0, 1],
            peer_capable: 1,
            _pad: [0; 1],
        };
        let self_route = RouteValue {
            nexthop_vni: 100,
            nexthop_ipv6: local,
            is_external: 0,
            _pad: [0; 3],
        };
        let mut w = MemMapWriter::default();
        w.ifaces_upsert(IfaceKey::new(100, [10, 0, 0, 5]), iface)
            .unwrap();
        w.ifaces6_upsert(IfaceKey6::new(100, P6), iface).unwrap();
        w.route_upsert(100, [10, 0, 0, 5], 32, self_route).unwrap();
        w.route6_upsert(100, P6, 128, self_route).unwrap();
        // A local interface whose key a remote route overwrote before the restart.
        w.ifaces_upsert(IfaceKey::new(100, [10, 0, 0, 6]), iface)
            .unwrap();
        w.route_upsert(
            100,
            [10, 0, 0, 6],
            32,
            RouteValue {
                nexthop_ipv6: NH,
                ..self_route
            },
        )
        .unwrap();

        let mut c = ControlCore::new(w);
        c.adopt_routes();
        assert_eq!(c.routes_shadow, vec![(100, [10, 0, 0, 6], 32, 100, NH)]);
        assert!(c.routes6_shadow.is_empty());
        assert!(!c.delete_route(100, [10, 0, 0, 5], 32).unwrap());
        assert!(!c.delete_route6(100, P6, 128).unwrap());
        assert!(c.w.routes.contains_key(&(100, [10, 0, 0, 5], 32)));
        assert!(c.w.routes6.contains_key(&(100, P6, 128)));
    }
}
