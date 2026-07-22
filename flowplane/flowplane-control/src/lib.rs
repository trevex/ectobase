//! Backend-agnostic control-plane programming shared by the eBPF and DPDK dataplanes.
#[cfg(feature = "mem-writer")]
pub mod mem;
mod routes;
pub mod shadow;
pub mod writer;

pub use writer::{CtFlushScope, MapWriter};

/// Backend-agnostic control-plane state + programming, generic over the map write surface.
/// Holds the config shadow + interface metadata the agnostic ops need; programs maps via `W`.
pub struct ControlCore<W: MapWriter> {
    pub(crate) w: W,
    // ROUTES domain (Task 2)
    pub(crate) routes_shadow: Vec<shadow::RouteShadowV4>,
    pub(crate) routes6_shadow: Vec<shadow::RouteShadowV6>,
}

impl<W: MapWriter> ControlCore<W> {
    pub fn new(w: W) -> Self {
        Self {
            w,
            routes_shadow: Vec::new(),
            routes6_shadow: Vec::new(),
        }
    }
    /// Consume the core, returning the writer (used by the eBPF adapter on teardown).
    pub fn into_writer(self) -> W {
        self.w
    }
    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.w
    }
}
