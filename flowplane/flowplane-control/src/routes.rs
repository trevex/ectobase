use crate::{ControlCore, MapWriter};
use flowplane_common::{IfaceKey, IfaceKey6, IfaceValue, RouteValue};
use std::collections::HashMap;

fn route_value(nexthop_ipv6: [u8; 16], nexthop_vni: u32, is_external: bool) -> RouteValue {
    RouteValue {
        nexthop_vni,
        nexthop_ipv6,
        is_external: is_external as u8,
        _pad: [0; 3],
    }
}

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

    /// Add a route that must not exist yet (`ROUTE_EXISTS` otherwise).
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
        self.replace_route(
            vni,
            ipv4,
            prefix_len,
            nexthop_ipv6,
            nexthop_vni,
            is_external,
        )
    }

    /// Add a route, or replace the one listed on its key in place (the re-announce path): one
    /// kernel upsert — none while a self-route holds the key — and the listed entry overwritten. A
    /// moved prefix is never unrouted in between, and never waits on a kernel delete.
    pub fn replace_route(
        &mut self,
        vni: u32,
        ipv4: [u8; 4],
        prefix_len: u32,
        nexthop_ipv6: [u8; 16],
        nexthop_vni: u32,
        is_external: bool,
    ) -> anyhow::Result<()> {
        let val = route_value(nexthop_ipv6, nexthop_vni, is_external);
        if !self.self_route_holds(vni, ipv4, prefix_len) {
            self.w.route_upsert(vni, ipv4, prefix_len, val)?;
        }
        match self
            .routes_shadow
            .iter_mut()
            .find(|r| r.0 == vni && r.1 == ipv4 && r.2 == prefix_len)
        {
            Some(r) => r.3 = val,
            None => self.routes_shadow.push((vni, ipv4, prefix_len, val)),
        }
        Ok(())
    }

    /// IPv6 sibling of [`Self::replace_route`].
    pub fn replace_route6(
        &mut self,
        vni: u32,
        ipv6: [u8; 16],
        prefix_len: u32,
        nexthop_ipv6: [u8; 16],
        nexthop_vni: u32,
        is_external: bool,
    ) -> anyhow::Result<()> {
        let val = route_value(nexthop_ipv6, nexthop_vni, is_external);
        if !self.self_route6_holds(vni, ipv6, prefix_len) {
            self.w.route6_upsert(vni, ipv6, prefix_len, val)?;
        }
        match self
            .routes6_shadow
            .iter_mut()
            .find(|r| r.0 == vni && r.1 == ipv6 && r.2 == prefix_len)
        {
            Some(r) => r.3 = val,
            None => self.routes6_shadow.push((vni, ipv6, prefix_len, val)),
        }
        Ok(())
    }

    /// Adopt after a restart: the pinned `ROUTES{,6}` tries survived, the shadows did not. Rebuild
    /// them from the tries, or every withdraw finds nothing and leaves its route forwarding. Runs
    /// after the interfaces are recovered (`register_iface_meta`), since it reads them.
    ///
    /// Every recovered interface's self-routes are (re)written and hold their keys. Whatever else
    /// sat on such a key is a mesh route and is listed, the fabric's view: code from before the
    /// keys were held let a mesh add overwrite a live self-route and a mesh withdraw delete one,
    /// and adopt is where a node damaged that way gets local delivery back.
    ///
    /// A self-route whose interface did not come back (its device went away while the process was
    /// down) is recognised by its `INTERFACES{,6}` entry — local, with the route's nexthop as its
    /// underlay, in its own VNI — and is neither listed nor held, so a mesh route for its key
    /// overwrites it.
    ///
    /// A mesh route a self-route was holding back is lost here: the kernel never had it. The mesh
    /// agent re-sends every route it holds when the instance id ListInterfaces reports changes, so
    /// it is back within one agent reconcile tick; until then detaching that interface removes the
    /// key instead of restoring the route.
    pub fn adopt_routes(&mut self) {
        let orphan = |iv: Option<IfaceValue>, r: &RouteValue, vni: u32| {
            iv.is_some_and(|iv| {
                iv.is_local == 1
                    && iv.underlay_ipv6 == r.nexthop_ipv6
                    && r.nexthop_vni == vni
                    && r.is_external == 0
            })
        };
        let own4: HashMap<(u32, [u8; 4]), RouteValue> = self
            .ifaces_meta
            .values()
            .filter(|m| m.ipv4 != [0u8; 4])
            .map(|m| ((m.vni, m.ipv4), route_value(m.underlay, m.vni, false)))
            .collect();
        let own6: HashMap<(u32, [u8; 16]), RouteValue> = self
            .ifaces_meta
            .values()
            .filter(|m| m.ipv6 != [0u8; 16])
            .map(|m| ((m.vni, m.ipv6), route_value(m.underlay, m.vni, false)))
            .collect();

        self.routes_shadow.clear();
        for (v, p, l, r) in self.w.route_entries() {
            let listed = match own4.get(&(v, p)) {
                Some(own) if l == 32 => r != *own,
                _ => !(l == 32 && orphan(self.w.ifaces_get(&IfaceKey::new(v, p)), &r, v)),
            };
            if listed {
                self.routes_shadow.push((v, p, l, r));
            }
        }
        self.self_routes.clear();
        for (&(v, p), &own) in &own4 {
            // A key whose write fails stays unheld, so the kernel and the shadow still agree on
            // it; the next adopt retries.
            if self.w.route_upsert(v, p, 32, own).is_ok() {
                self.self_routes.insert((v, p));
            }
        }

        self.routes6_shadow.clear();
        for (v, p, l, r) in self.w.route6_entries() {
            let listed = match own6.get(&(v, p)) {
                Some(own) if l == 128 => r != *own,
                _ => !(l == 128 && orphan(self.w.ifaces6_get(&IfaceKey6::new(v, p)), &r, v)),
            };
            if listed {
                self.routes6_shadow.push((v, p, l, r));
            }
        }
        self.self_routes6.clear();
        for (&(v, p), &own) in &own6 {
            if self.w.route6_upsert(v, p, 128, own).is_ok() {
                self.self_routes6.insert((v, p));
            }
        }
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
        self.replace_route6(
            vni,
            ipv6,
            prefix_len,
            nexthop_ipv6,
            nexthop_vni,
            is_external,
        )
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
    // against a mesh add again. A self-route whose interface did not come back holds nothing.
    //
    // Adopt also repairs what the pre-arbitration code could leave behind on a live interface's
    // key: a mesh route that overwrote the self-route (kept in the shadow, as the fabric's view),
    // or a self-route a mesh withdraw deleted. Both get the self-route back, held, or local
    // delivery to that guest stays broken for as long as it lives.
    #[test]
    fn adopt_restores_and_holds_every_recovered_self_route() {
        use flowplane_common::{IfaceKey, IfaceKey6, IfaceValue};
        let local = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let v6 = |last: u8| {
            let mut a = P6;
            a[15] = last;
            a
        };
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
        let foreign = RouteValue {
            nexthop_ipv6: NH,
            is_external: 1,
            ..self_route
        };
        let mut w = MemMapWriter::default();
        // a: intact.
        w.ifaces_upsert(IfaceKey::new(100, [10, 0, 0, 5]), iface)
            .unwrap();
        w.ifaces6_upsert(IfaceKey6::new(100, v6(5)), iface).unwrap();
        w.route_upsert(100, [10, 0, 0, 5], 32, self_route).unwrap();
        w.route6_upsert(100, v6(5), 128, self_route).unwrap();
        // b: a mesh route overwrote its self-routes.
        w.ifaces_upsert(IfaceKey::new(100, [10, 0, 0, 6]), iface)
            .unwrap();
        w.ifaces6_upsert(IfaceKey6::new(100, v6(6)), iface).unwrap();
        w.route_upsert(100, [10, 0, 0, 6], 32, foreign).unwrap();
        w.route6_upsert(100, v6(6), 128, foreign).unwrap();
        // d: a mesh withdraw deleted its self-routes.
        w.ifaces_upsert(IfaceKey::new(100, [10, 0, 0, 8]), iface)
            .unwrap();
        w.ifaces6_upsert(IfaceKey6::new(100, v6(8)), iface).unwrap();
        // An interface whose device went away while the process was down: not recovered.
        w.ifaces_upsert(IfaceKey::new(100, [10, 0, 0, 7]), iface)
            .unwrap();
        w.route_upsert(100, [10, 0, 0, 7], 32, self_route).unwrap();

        let mut c = ControlCore::new(w);
        for (id, last) in [(&b"a"[..], 5), (b"b", 6), (b"d", 8)] {
            c.register_iface_meta(
                id.to_vec(),
                crate::shadow::IfaceMeta {
                    vni: 100,
                    ipv4: [10, 0, 0, last],
                    ipv6: v6(last),
                    underlay: local,
                    ifindex: 42,
                },
            );
        }
        c.adopt_routes();
        assert_eq!(c.routes_shadow, vec![(100, [10, 0, 0, 6], 32, foreign)]);
        assert_eq!(c.routes6_shadow, vec![(100, v6(6), 128, foreign)]);
        for last in [5, 6, 8] {
            assert_eq!(c.w.routes[&(100, [10, 0, 0, last], 32)], self_route);
            assert_eq!(c.w.routes6[&(100, v6(last), 128)], self_route);
        }

        // Every recovered key is held: a withdraw of b's mesh route and a mesh add over a or d
        // touch the shadow only.
        assert!(c.delete_route(100, [10, 0, 0, 6], 32).unwrap());
        assert!(c.delete_route6(100, v6(6), 128).unwrap());
        assert!(!c.delete_route(100, [10, 0, 0, 5], 32).unwrap());
        for last in [5, 8] {
            c.create_route(100, [10, 0, 0, last], 32, NH, 100, false)
                .unwrap();
            c.create_route6(100, v6(last), 128, NH, 100, false).unwrap();
        }
        for last in [5, 6, 8] {
            assert_eq!(c.w.routes[&(100, [10, 0, 0, last], 32)], self_route);
            assert_eq!(c.w.routes6[&(100, v6(last), 128)], self_route);
        }
        // The orphan's key is not held: a mesh add takes it.
        c.create_route(100, [10, 0, 0, 7], 32, NH, 100, true)
            .unwrap();
        assert_eq!(c.w.routes[&(100, [10, 0, 0, 7], 32)], foreign);
    }

    // A re-announce replaces a route in place: one kernel write, no gap, and no dependence on a
    // kernel delete that could fail. On a held key it changes only the shadow.
    #[test]
    fn replace_route_overwrites_in_place() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.replace_route(7, [10, 0, 0, 0], 24, NH, 7, false).unwrap();
        c.replace_route6(7, P6, 64, NH, 7, false).unwrap();
        // A remove would fail now; a replace never needs one.
        c.w.route_remove_fault = Some((7, [10, 0, 0, 0], 24));
        c.w.route6_remove_fault = Some((7, P6, 64));
        let moved = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
        c.replace_route(7, [10, 0, 0, 0], 24, moved, 8, true)
            .unwrap();
        c.replace_route6(7, P6, 64, moved, 8, true).unwrap();
        let want = RouteValue {
            nexthop_vni: 8,
            nexthop_ipv6: moved,
            is_external: 1,
            _pad: [0; 3],
        };
        assert_eq!(c.w.routes[&(7, [10, 0, 0, 0], 24)], want);
        assert_eq!(c.w.routes6[&(7, P6, 64)], want);
        assert_eq!(c.routes_shadow, vec![(7, [10, 0, 0, 0], 24, want)]);
        assert_eq!(c.routes6_shadow, vec![(7, P6, 64, want)]);

        c.self_routes.insert((7, [10, 0, 0, 5]));
        c.replace_route(7, [10, 0, 0, 5], 32, NH, 7, false).unwrap();
        c.replace_route(7, [10, 0, 0, 5], 32, moved, 7, false)
            .unwrap();
        assert!(!c.w.routes.contains_key(&(7, [10, 0, 0, 5], 32)));
        assert_eq!(c.routes_shadow.len(), 2);
        assert_eq!(c.routes_shadow[1].3.nexthop_ipv6, moved);
    }
}
