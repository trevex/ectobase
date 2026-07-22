//! Load-balancer (`LB`/`MAGLEV`) programming — thin delegations to `ControlCore`.
//!
//! The LB + Maglev domain moved into `flowplane-control` (Task 5); these `Control` methods just
//! take the inner lock and forward to `core`, preserving the exact signatures `node.rs` calls.

use flowplane_control::shadow::LbIpBytes;

use super::Control;

impl Control {
    /// Register a load balancer: allocate a Maglev table id and program the `LB` map for each
    /// (port, proto) service. Backends are added later via `add_lb_target`.
    pub fn create_lb(
        &self,
        id: &[u8],
        vni: u32,
        ip: LbIpBytes,
        lb_underlay: [u8; 16],
        ports: Vec<(u16, u8)>,
    ) -> anyhow::Result<()> {
        self.inner
            .lock()
            .core
            .create_lb(id, vni, ip, lb_underlay, ports)
    }

    /// Append a backend underlay /128 to a registered LB and rebuild + write its Maglev table.
    pub fn add_lb_target(&self, id: &[u8], backend: [u8; 16]) -> anyhow::Result<()> {
        self.inner.lock().core.add_lb_target(id, backend)
    }

    /// Remove a backend from an LB. Returns true if found, false if not.
    pub fn del_lb_target(&self, id: &[u8], backend: [u8; 16]) -> anyhow::Result<bool> {
        self.inner.lock().core.del_lb_target(id, backend)
    }

    /// Remove a load balancer: clear its `LB` service entries and `MAGLEV` slots.
    /// Returns true if found and deleted, false if not found.
    pub fn delete_lb(&self, id: &[u8]) -> anyhow::Result<bool> {
        self.inner.lock().core.delete_lb(id)
    }
}
