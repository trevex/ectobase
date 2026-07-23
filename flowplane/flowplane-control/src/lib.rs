//! Backend-agnostic control-plane programming shared by the eBPF and DPDK dataplanes.
mod firewall;
mod interface;
mod lb;
pub mod maglev;
#[cfg(feature = "mem-writer")]
pub mod mem;
mod nat;
mod routes;
pub mod shadow;
pub mod writer;

pub use interface::{meter_state, IfaceParams};
pub use writer::{CtFlushScope, MapWriter};

/// Backend-agnostic control-plane state + programming, generic over the map write surface.
/// Holds the config shadow + interface metadata the agnostic ops need; programs maps via `W`.
pub struct ControlCore<W: MapWriter> {
    pub(crate) w: W,
    // ROUTES domain (Task 2)
    pub(crate) routes_shadow: Vec<shadow::RouteShadowV4>,
    pub(crate) routes6_shadow: Vec<shadow::RouteShadowV6>,
    // NAT domain (Task 4): interface meta + lb shadow the nat conflict checks read, and the
    // in-memory neighbor-NAT vec that drives the NEIGHBOR_NAT map reprogram.
    pub(crate) ifaces_meta: std::collections::HashMap<Vec<u8>, shadow::IfaceMeta>,
    // LB domain (Task 5): the load balancers (keyed by id) + the Maglev table-id allocator.
    // The eBPF `detach_interface` VNI-reset reads lb-vni membership via `vni_has_lb`.
    pub(crate) lbs: std::collections::HashMap<Vec<u8>, shadow::LbEntry>,
    pub(crate) next_table_id: u32,
    pub(crate) neigh_nats: Vec<flowplane_common::NeighborNatEntry>,
    // FIREWALL domain (Task 6): ifindex -> ordered (rule_id, rule) pairs. Drives the FW_RULES /
    // FW_META reprogram. The eBPF `detach_interface` drops an interface's shadow entry via
    // `remove_fw_rules`.
    pub(crate) fw: std::collections::HashMap<u32, Vec<(Vec<u8>, flowplane_common::FwRule)>>,
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
    /// The tap ifindex registered for an interface (0 if unknown). Used by the eBPF
    /// `detach_interface` device path now `Inner.by_ifindex` is retired — `ifaces_meta` is the
    /// single source of truth for the interface_id -> ifindex mapping.
    pub fn iface_ifindex(&self, id: &[u8]) -> Option<u32> {
        self.ifaces_meta.get(id).map(|m| m.ifindex)
    }
}
