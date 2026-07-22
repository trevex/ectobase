//! Backend-agnostic control-plane programming shared by the eBPF and DPDK dataplanes.
mod firewall;
mod lb;
pub mod maglev;
#[cfg(feature = "mem-writer")]
pub mod mem;
mod nat;
mod routes;
pub mod shadow;
pub mod writer;

pub use writer::{CtFlushScope, MapWriter};

/// Backend-agnostic control-plane state + programming, generic over the map write surface.
/// Holds the config shadow + interface metadata the agnostic ops need; programs maps via `W`.
pub struct ControlCore<W: MapWriter> {
    pub(crate) w: W,
    // ROUTES domain (Task 2)
    pub routes_shadow: Vec<shadow::RouteShadowV4>,
    pub routes6_shadow: Vec<shadow::RouteShadowV6>,
    // NAT domain (Task 4): interface meta + lb shadow the nat conflict checks read, and the
    // in-memory neighbor-NAT vec that drives the NEIGHBOR_NAT map reprogram.
    pub(crate) ifaces_meta: std::collections::HashMap<Vec<u8>, shadow::IfaceMeta>,
    // LB domain (Task 5): the load balancers (keyed by id) + the Maglev table-id allocator.
    // `pub` so the eBPF `detach_interface` VNI-reset can still read `lbs` (vni membership) until
    // that reset logic moves into the core (Task 7).
    pub lbs: std::collections::HashMap<Vec<u8>, shadow::LbEntry>,
    pub(crate) next_table_id: u32,
    // `pub` (like `routes_shadow`) so the eBPF `detach_interface` VNI-reset can still purge
    // neighbor-NATs verbatim until that reset logic moves into the core (Task 7).
    pub neigh_nats: Vec<flowplane_common::NeighborNatEntry>,
    // FIREWALL domain (Task 6): ifindex -> ordered (rule_id, rule) pairs. Drives the FW_RULES /
    // FW_META reprogram. `pub` so the eBPF `detach_interface` can still drop an interface's shadow
    // entry (matching the former `Inner.fw.remove(&tap)`) until that teardown moves into the core.
    pub fw: std::collections::HashMap<u32, Vec<(Vec<u8>, flowplane_common::FwRule)>>,
}

impl<W: MapWriter> ControlCore<W> {
    pub fn new(w: W) -> Self {
        Self {
            w,
            routes_shadow: Vec::new(),
            routes6_shadow: Vec::new(),
            ifaces_meta: std::collections::HashMap::new(),
            lbs: std::collections::HashMap::new(),
            next_table_id: 1,
            neigh_nats: Vec::new(),
            fw: std::collections::HashMap::new(),
        }
    }
    /// Consume the core, returning the writer (used by the eBPF adapter on teardown).
    pub fn into_writer(self) -> W {
        self.w
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
}
