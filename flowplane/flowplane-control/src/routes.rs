use crate::{ControlCore, MapWriter};
use flowplane_common::{IfaceKey, IfaceKey6, IfaceValue, RouteValue};

// A mesh route and a local interface's self-route can share a key: a VM that moves onto this node
// is attached while the fabric still carries its old owner's /32 or /128. The self-route wins the
// kernel entry for as long as the interface lives, and the mesh route waits in the shadow (the
// fabric's view) — added there without a kernel write, withdrawn from there alone — until
// `remove_self_routes` puts it back.

impl<W: MapWriter> ControlCore<W> {
    /// Whether a local interface's self-route holds the kernel entry for this key.
    fn self_route_holds(&self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> bool {
        prefix_len == 32 && self.self_routes.contains(&(vni, ipv4))
    }

    fn self_route6_holds(&self, vni: u32, ipv6: [u8; 16], prefix_len: u32) -> bool {
        prefix_len == 128 && self.self_routes6.contains(&(vni, ipv6))
    }

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
            .any(|&(v, p, l, _)| v == vni && p == ipv4 && l == prefix_len)
        {
            anyhow::bail!("ROUTE_EXISTS: route already exists");
        }
        let val = RouteValue {
            nexthop_vni,
            nexthop_ipv6,
            is_external: is_external as u8,
            _pad: [0; 3],
        };
        if !self.self_route_holds(vni, ipv4, prefix_len) {
            self.w.route_upsert(vni, ipv4, prefix_len, val)?;
        }
        self.routes_shadow.push((vni, ipv4, prefix_len, val));
        Ok(())
    }

    /// Adopt after a restart: the pinned `ROUTES{,6}` tries survived, the shadows did not. Rebuild
    /// them from the tries, or every withdraw finds nothing and leaves its route forwarding. Runs
    /// after the interfaces are recovered (`register_iface_meta`), since it reads them.
    ///
    /// The tries also hold each local interface's self-route (`program_interface`), which the
    /// shadows never list: a host route whose `INTERFACES{,6}` entry is local and whose nexthop is
    /// that interface's own underlay in its own VNI. A recovered interface's self-route holds its
    /// key again. One whose interface did not come back (its device went away while the process was
    /// down) is left out of both, so a mesh route for its key overwrites it. A route that overwrote
    /// a self-route's key names another nexthop, so it is adopted.
    ///
    /// A mesh route a self-route was holding back is lost here: the kernel never had it. The mesh
    /// agent re-sends a route only when its route-bus session restarts (the subscribe replay) or
    /// the prefix changes, so until then detaching that interface removes the key instead of
    /// restoring the route.
    pub fn adopt_routes(&mut self) {
        let is_self = |iv: Option<IfaceValue>, r: &RouteValue, vni: u32| {
            iv.is_some_and(|iv| {
                iv.is_local == 1
                    && iv.underlay_ipv6 == r.nexthop_ipv6
                    && r.nexthop_vni == vni
                    && r.is_external == 0
            })
        };
        self.self_routes.clear();
        self.self_routes6.clear();
        let mut shadow = Vec::new();
        for (v, p, l, r) in self.w.route_entries() {
            if l == 32 && is_self(self.w.ifaces_get(&IfaceKey::new(v, p)), &r, v) {
                if self.ifaces_meta.values().any(|m| m.vni == v && m.ipv4 == p) {
                    self.self_routes.insert((v, p));
                }
            } else {
                shadow.push((v, p, l, r));
            }
        }
        self.routes_shadow = shadow;
        let mut shadow6 = Vec::new();
        for (v, p, l, r) in self.w.route6_entries() {
            if l == 128 && is_self(self.w.ifaces6_get(&IfaceKey6::new(v, p)), &r, v) {
                if self.ifaces_meta.values().any(|m| m.vni == v && m.ipv6 == p) {
                    self.self_routes6.insert((v, p));
                }
            } else {
                shadow6.push((v, p, l, r));
            }
        }
        self.routes6_shadow = shadow6;
    }

    /// Delete a route. Returns true if found and deleted, false if not found. A failed kernel
    /// delete is an error and keeps the route listed, so a retried withdraw can finish it.
    pub fn delete_route(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
    ) -> anyhow::Result<bool> {
        let Some(i) = self
            .routes_shadow
            .iter()
            .position(|&(v, p, l, _)| v == vni && p == ipv4 && l == prefix_len)
        else {
            return Ok(false);
        };
        if !self.self_route_holds(vni, ipv4, prefix_len) {
            self.w.route_remove(vni, ipv4, prefix_len)?;
        }
        self.routes_shadow.remove(i);
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
            .any(|&(v, p, l, _)| v == vni && p == ipv6 && l == prefix_len)
        {
            anyhow::bail!("ROUTE_EXISTS: route already exists");
        }
        let val = RouteValue {
            nexthop_vni,
            nexthop_ipv6,
            is_external: is_external as u8,
            _pad: [0; 3],
        };
        if !self.self_route6_holds(vni, ipv6, prefix_len) {
            self.w.route6_upsert(vni, ipv6, prefix_len, val)?;
        }
        self.routes6_shadow.push((vni, ipv6, prefix_len, val));
        Ok(())
    }

    /// Delete an IPv6 route. Returns true if found, false if not found. Same failure contract as
    /// [`Self::delete_route`].
    pub fn delete_route6(
        &mut self,
        vni: u32,
        ipv6: [u8; 16],
        prefix_len: u32,
    ) -> anyhow::Result<bool> {
        let Some(i) = self
            .routes6_shadow
            .iter()
            .position(|&(v, p, l, _)| v == vni && p == ipv6 && l == prefix_len)
        else {
            return Ok(false);
        };
        if !self.self_route6_holds(vni, ipv6, prefix_len) {
            self.w.route6_remove(vni, ipv6, prefix_len)?;
        }
        self.routes6_shadow.remove(i);
        Ok(true)
    }

    /// Give up an interface's self-route keys (detach, or an attach rolled back): put back the mesh
    /// route each was holding, else remove the key. The keys stop counting as held even if a write
    /// fails, since the interface is gone either way: a later mesh add then overwrites what is
    /// left, and a withdraw removes it. Both families are attempted; the first error is returned.
    pub fn remove_self_routes(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        ipv6: [u8; 16],
    ) -> anyhow::Result<()> {
        let mut res = Ok(());
        if ipv4 != [0u8; 4] {
            self.self_routes.remove(&(vni, ipv4));
            let mesh = self
                .routes_shadow
                .iter()
                .find(|&&(v, p, l, _)| v == vni && p == ipv4 && l == 32)
                .map(|&(_, _, _, r)| r);
            res = res.and(match mesh {
                Some(r) => self.w.route_upsert(vni, ipv4, 32, r),
                None => self.w.route_remove(vni, ipv4, 32),
            });
        }
        if ipv6 != [0u8; 16] {
            self.self_routes6.remove(&(vni, ipv6));
            let mesh = self
                .routes6_shadow
                .iter()
                .find(|&&(v, p, l, _)| v == vni && p == ipv6 && l == 128)
                .map(|&(_, _, _, r)| r);
            res = res.and(match mesh {
                Some(r) => self.w.route6_upsert(vni, ipv6, 128, r),
                None => self.w.route6_remove(vni, ipv6, 128),
            });
        }
        res
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

    // A kernel delete that fails leaves the route forwarding; the shadow must keep listing it, or
    // no later withdraw can retry.
    #[test]
    fn a_failed_kernel_remove_keeps_the_shadow_entry() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.create_route(7, [10, 0, 0, 0], 24, NH, 7, false).unwrap();
        c.create_route6(7, P6, 64, NH, 7, false).unwrap();
        c.w.route_remove_fault = Some((7, [10, 0, 0, 0], 24));
        c.w.route6_remove_fault = Some((7, P6, 64));
        assert!(c.delete_route(7, [10, 0, 0, 0], 24).is_err());
        assert!(c.delete_route6(7, P6, 64).is_err());
        assert_eq!(c.routes_shadow.len(), 1);
        assert_eq!(c.routes6_shadow.len(), 1);

        c.w.route_remove_fault = None;
        c.w.route6_remove_fault = None;
        assert!(c.delete_route(7, [10, 0, 0, 0], 24).unwrap());
        assert!(c.delete_route6(7, P6, 64).unwrap());
        assert!(c.w.routes.is_empty() && c.w.routes6.is_empty());
    }

    const NH: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
    const P6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    fn sorted<P: Ord + Copy>(
        mut v: Vec<(u32, P, u32, RouteValue)>,
    ) -> Vec<(u32, P, u32, RouteValue)> {
        v.sort_by_key(|r| (r.0, r.1, r.2));
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
    // take it: adopt must leave it out too, and a recovered interface's self-route holds its key
    // against a mesh add again. A user route on the same key (a different nexthop) is still a user
    // route, and a self-route whose interface did not come back holds nothing.
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

        // An interface whose device went away while the process was down: not recovered.
        w.ifaces_upsert(IfaceKey::new(100, [10, 0, 0, 7]), iface)
            .unwrap();
        w.route_upsert(100, [10, 0, 0, 7], 32, self_route).unwrap();

        let mut c = ControlCore::new(w);
        for (id, ipv4, ipv6) in [
            (&b"a"[..], [10, 0, 0, 5], P6),
            (b"b", [10, 0, 0, 6], [0; 16]),
        ] {
            c.register_iface_meta(
                id.to_vec(),
                crate::shadow::IfaceMeta {
                    vni: 100,
                    ipv4,
                    ipv6,
                    underlay: local,
                    ifindex: 42,
                },
            );
        }
        c.adopt_routes();
        let overwrote = RouteValue {
            nexthop_ipv6: NH,
            ..self_route
        };
        assert_eq!(c.routes_shadow, vec![(100, [10, 0, 0, 6], 32, overwrote)]);
        assert!(c.routes6_shadow.is_empty());
        assert!(!c.delete_route(100, [10, 0, 0, 5], 32).unwrap());
        assert!(!c.delete_route6(100, P6, 128).unwrap());
        assert!(c.w.routes.contains_key(&(100, [10, 0, 0, 5], 32)));
        assert!(c.w.routes6.contains_key(&(100, P6, 128)));

        // The recovered interface's keys are held: a mesh add waits in the shadow.
        c.create_route(100, [10, 0, 0, 5], 32, NH, 100, false)
            .unwrap();
        c.create_route6(100, P6, 128, NH, 100, false).unwrap();
        assert_eq!(c.w.routes[&(100, [10, 0, 0, 5], 32)], self_route);
        assert_eq!(c.w.routes6[&(100, P6, 128)], self_route);
        // The orphan's key is not: a mesh add takes it.
        c.create_route(100, [10, 0, 0, 7], 32, NH, 100, false)
            .unwrap();
        assert_eq!(c.w.routes[&(100, [10, 0, 0, 7], 32)], overwrote);
    }
}
