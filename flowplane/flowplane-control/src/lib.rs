//! Backend-agnostic control-plane programming for the eBPF dataplane's control core.
mod firewall;
pub mod fwclass;
mod interface;
mod lb;
pub mod maglev;
#[cfg(feature = "mem-writer")]
pub mod mem;
mod nat;
pub mod natowner;
mod ports;
mod routes;
pub mod shadow;
pub mod writer;

pub use firewall::FwError;
use flowplane_common::{IfaceMetaKey, IfaceMetaVal};
pub use interface::{meter_state, IfaceParams};
pub use nat::ReplaceCounts;
pub use natowner::NeighborNatError;
pub use writer::{CtFlushScope, CtFlushScope6, MapWriter, Walk};

/// A neighbor-NAT block's place in the index: its nat_ip and the port its range starts at.
pub(crate) type BlockKey4 = ([u8; 4], u16);
/// v6 sibling of [`BlockKey4`], over a nat_ip6.
pub(crate) type BlockKey6 = ([u8; 16], u16);

/// Backend-agnostic control-plane state + programming, generic over the map write surface.
/// Holds the config shadow + interface metadata the agnostic ops need; programs maps via `W`.
pub struct ControlCore<W: MapWriter> {
    pub(crate) w: W,
    // ROUTES domain
    pub(crate) routes_shadow: Vec<shadow::RouteShadowV4>,
    pub(crate) routes6_shadow: Vec<shadow::RouteShadowV6>,
    // The (vni, host ip) keys whose kernel entry is a local interface's self-route (routes.rs).
    pub(crate) self_routes: std::collections::HashSet<(u32, [u8; 4])>,
    pub(crate) self_routes6: std::collections::HashSet<(u32, [u8; 16])>,
    // NAT domain: interface meta + lb shadow the nat conflict checks read.
    pub(crate) ifaces_meta: std::collections::HashMap<Vec<u8>, shadow::IfaceMeta>,
    // Set when adopt's `IFACE_META` walk was cut short: a live interface may be missing from the
    // recovered set, so its absence proves nothing until the next whole adopt.
    pub(crate) ifaces_partial: bool,
    // The (vni, address) keys that cut walk did read: those interfaces' absence is real.
    pub(crate) journal_read4: std::collections::HashSet<(u32, [u8; 4])>,
    pub(crate) journal_read6: std::collections::HashSet<(u32, [u8; 16])>,
    // LB domain: the load balancers (keyed by id) + the Maglev table-id allocator.
    // The eBPF `detach_interface` VNI-reset reads lb-vni membership via `keeps_vni`.
    pub(crate) lbs: std::collections::HashMap<Vec<u8>, shadow::LbEntry>,
    // Load balancers adopt found in the pinned maps, which keep everything but the id: each waits
    // here until a call names its address (lb.rs `claim_lb`).
    pub(crate) adopted_lbs: Vec<shadow::LbEntry>,
    pub(crate) next_table_id: u32,
    // After a cut LB adopt, the counter's value after its jump: no table below it is deleted, as
    // a row the walk never read may point at it. 0 after a whole adopt.
    pub(crate) unread_tables_below: u32,
    // Neighbor-NAT blocks, keyed by (nat_ip, port_min): blocks never overlap on one nat_ip, so
    // this order makes an overlap check two neighbour lookups and a delete one removal. The
    // NAT_OWNERS tries store each block as its port prefixes.
    pub(crate) neigh_nats:
        std::collections::BTreeMap<BlockKey4, flowplane_common::NeighborNatEntry>,
    // NAT66 sibling of `neigh_nats`, stored in NAT_OWNERS6.
    pub(crate) neigh_nats6:
        std::collections::BTreeMap<BlockKey6, flowplane_common::NeighborNat6Entry>,
    // Sum of the listed blocks' prefix counts, per family (the capacity check reads these). Equal
    // to the trie's size while list and trie agree; after a failed write it reads high, never low.
    pub(crate) nat_owner_count4: usize,
    pub(crate) nat_owner_count6: usize,
    // FIREWALL classifier: each interface's current binding (mirrors `FW_BIND`) and how many
    // (interface, direction) pairs reference each scope — a scope is deleted at zero.
    pub(crate) fw_binds: std::collections::HashMap<u32, flowplane_common::FwBind>,
    pub(crate) fw_scope_refs: std::collections::HashMap<u64, u32>,
    // Set when adopt's `FW_BIND` walk was cut short: no scope is deleted (firewall.rs).
    pub(crate) fw_partial: bool,
}

impl<W: MapWriter> ControlCore<W> {
    pub fn new(w: W) -> Self {
        Self {
            w,
            routes_shadow: Vec::new(),
            routes6_shadow: Vec::new(),
            self_routes: std::collections::HashSet::new(),
            self_routes6: std::collections::HashSet::new(),
            ifaces_meta: std::collections::HashMap::new(),
            ifaces_partial: false,
            journal_read4: std::collections::HashSet::new(),
            journal_read6: std::collections::HashSet::new(),
            lbs: std::collections::HashMap::new(),
            adopted_lbs: Vec::new(),
            next_table_id: 1,
            unread_tables_below: 0,
            neigh_nats: std::collections::BTreeMap::new(),
            neigh_nats6: std::collections::BTreeMap::new(),
            nat_owner_count4: 0,
            nat_owner_count6: 0,
            fw_binds: std::collections::HashMap::new(),
            fw_scope_refs: std::collections::HashMap::new(),
            fw_partial: false,
        }
    }
    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.w
    }
    /// Shared access to the underlying writer (used by the MAC-snapshot / underlay-read paths and
    /// the LB control-core tests).
    pub fn writer(&self) -> &W {
        &self.w
    }
    /// Mirror an interface's agnostic metadata (the eBPF `create_interface` keeps its own record
    /// but also registers the subset the nat/lb/fw logic reads here).
    pub fn register_iface_meta(&mut self, id: Vec<u8>, m: shadow::IfaceMeta) {
        self.ifaces_meta.insert(id, m);
    }
    pub fn forget_iface_meta(&mut self, id: &[u8]) {
        self.ifaces_meta.remove(id);
    }
    /// Adopt: the `IFACE_META` restart journal the caller rebuilds its interfaces from. A walk a
    /// read error cut short (its `error` set) may miss live interfaces, so the core stops taking an
    /// interface's absence for its removal: [`Self::keeps_vni`] keeps every VNI and
    /// `adopt_routes` holds the orphan-looking self-routes the walk did not list, until the next
    /// whole adopt.
    pub fn read_iface_journal(&mut self) -> Walk<(IfaceMetaKey, IfaceMetaVal)> {
        let walk = self.w.iface_meta_entries();
        self.ifaces_partial = walk.error.is_some();
        self.journal_read4 = walk.entries.iter().map(|(_, v)| (v.vni, v.ipv4)).collect();
        self.journal_read6 = walk.entries.iter().map(|(_, v)| (v.vni, v.ipv6)).collect();
        walk
    }
    /// Whether something besides the caller's own interfaces keeps `vni` in use, so the detach
    /// of its last known interface must not purge it: a load balancer on it, or interfaces a cut
    /// `IFACE_META` walk may have left unrecovered.
    pub fn keeps_vni(&self, vni: u32) -> bool {
        self.ifaces_partial || self.vni_has_lb(vni)
    }
    /// The tap ifindex registered for an interface (0 if unknown). Used by the eBPF
    /// `detach_interface` device path now `Inner.by_ifindex` is retired — `ifaces_meta` is the
    /// single source of truth for the interface_id -> ifindex mapping.
    pub fn iface_ifindex(&self, id: &[u8]) -> Option<u32> {
        self.ifaces_meta.get(id).map(|m| m.ifindex)
    }
    /// Resolve a locally-registered interface id from `(vni, ipv4)`. The agnostic NAT RPCs identify a
    /// source by its overlay (vni, ip), but `create_nat`/`delete_nat` are keyed by interface id;
    /// `ifaces_meta` is the bridge. Returns the FIRST matching id. Mirrors the eBPF node service's
    /// `find_interface_id` (which searches `Control::list_interfaces`) — the seam keeps that lookup
    /// out of the per-backend handlers. Returns `None` if no local interface matches.
    #[must_use]
    pub fn find_iface_by_vni_ipv4(&self, vni: u32, ipv4: [u8; 4]) -> Option<Vec<u8>> {
        self.ifaces_meta
            .iter()
            .find(|(_, m)| m.vni == vni && m.ipv4 == ipv4)
            .map(|(id, _)| id.clone())
    }
    /// v6 sibling of [`find_iface_by_vni_ipv4`] — resolve an interface id from `(vni, ipv6)`, for the
    /// NAT66 handler path. Returns the FIRST matching id, or `None`.
    #[must_use]
    pub fn find_iface_by_vni_ipv6(&self, vni: u32, ipv6: [u8; 16]) -> Option<Vec<u8>> {
        self.ifaces_meta
            .iter()
            .find(|(_, m)| m.vni == vni && m.ipv6 == ipv6)
            .map(|(id, _)| id.clone())
    }
}
