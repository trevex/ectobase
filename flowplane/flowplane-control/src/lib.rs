//! Backend-agnostic control-plane programming shared by the eBPF and DPDK dataplanes.
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
    pub(crate) lbs: std::collections::HashMap<Vec<u8>, shadow::LbEntry>,
    // `pub` (like `routes_shadow`) so the eBPF `detach_interface` VNI-reset can still purge
    // neighbor-NATs verbatim until that reset logic moves into the core (Task 7).
    pub neigh_nats: Vec<flowplane_common::NeighborNatEntry>,
}

impl<W: MapWriter> ControlCore<W> {
    pub fn new(w: W) -> Self {
        Self {
            w,
            routes_shadow: Vec::new(),
            routes6_shadow: Vec::new(),
            ifaces_meta: std::collections::HashMap::new(),
            lbs: std::collections::HashMap::new(),
            neigh_nats: Vec::new(),
        }
    }
    /// Consume the core, returning the writer (used by the eBPF adapter on teardown).
    pub fn into_writer(self) -> W {
        self.w
    }
    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.w
    }
    /// Mirror an interface's agnostic metadata (the eBPF `create_interface` keeps its own record
    /// but also registers the subset the nat/lb/fw logic reads here).
    pub fn register_iface_meta(&mut self, id: Vec<u8>, m: shadow::IfaceMeta) {
        self.ifaces_meta.insert(id, m);
    }
    pub fn forget_iface_meta(&mut self, id: &[u8]) {
        self.ifaces_meta.remove(id);
    }
    /// Mirror a load balancer's agnostic subset (used by the nat preferred-underlay collision check).
    pub fn register_lb(&mut self, id: Vec<u8>, e: shadow::LbEntry) {
        self.lbs.insert(id, e);
    }
    pub fn forget_lb(&mut self, id: &[u8]) {
        self.lbs.remove(id);
    }
}
