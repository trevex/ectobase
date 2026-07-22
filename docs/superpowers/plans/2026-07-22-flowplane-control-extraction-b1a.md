# flowplane-control Extraction (B1a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the eBPF `flowplane` crate's backend-agnostic control-plane programming into a new `flowplane-control` crate generic over a `MapWriter` trait, so the DPDK dataplane (B1b) can reuse the exact same orchestration — with the existing eBPF behavior byte-unchanged.

**Architecture:** New crate `flowplane-control` holds `ControlCore<W: MapWriter>` = the config shadow state + interface metadata + the agnostic programming methods (routes/nat/lb/fw/qos/dhcp/interface-map-programming). `W` abstracts the ~35 uniform map writes (currently aya `.upsert/.remove/.set` calls). The eBPF `flowplane` crate keeps its device/loader glue and provides an `AyaWriter: MapWriter` over its existing aya map wrappers; `Control::Inner` holds a `ControlCore<AyaWriter>` and delegates the agnostic methods to it. This is a **pure code-movement refactor** — no logic changes — guarded by the existing flowplane test suite.

**Tech Stack:** Rust workspace, `anyhow`, `parking_lot`, `flowplane-common` (POD types). Tests use an in-memory `MemMapWriter` fake so the agnostic logic is tested without CAP_BPF.

**Scope:** This is slice B1a of `docs/superpowers/specs/2026-07-22-flowplane-dpdk-b1-serve-control-seam-design.md`. It does NOT build the DPDK `MapWriter`, the map split, or the `flowplane-dpdk serve` binary (that is B1b). The only observable outcome is: `flowplane-control` exists, is unit-tested via `MemMapWriter`, and the eBPF `flowplane` calls it with no behavior change.

**Refactor safety rule for every task:** after wiring each domain, `cargo build -p flowplane` must succeed and `cargo test -p flowplane` must pass unchanged. The moves are verbatim — do not "improve" logic. If a move forces a logic change, STOP and report it.

---

## File Structure

New crate `flowplane/flowplane-control/`:
- `Cargo.toml` — deps: `flowplane-common`, `anyhow`. Optional `mem-writer` feature.
- `src/lib.rs` — `ControlCore<W>` struct + module wiring + re-exports.
- `src/writer.rs` — the `MapWriter` trait (the §C surface) + `CtFlushScope`.
- `src/mem.rs` — `MemMapWriter` in-memory fake (feature `mem-writer`), for tests in this crate and B1b.
- `src/routes.rs`, `src/nat.rs`, `src/lb.rs`, `src/firewall.rs`, `src/interface.rs` — the agnostic methods, mirroring the current `control/*.rs` split.
- `src/shadow.rs` — the moved shadow/meta types: `IfaceRecord` (agnostic subset), `LbEntry`, `LbIp`, `LbIpBytes`, `RouteShadowV4/V6`, `IfaceParams`.

Modified in `flowplane/flowplane/`:
- `Cargo.toml` — add `flowplane-control` dep.
- `src/control/aya_writer.rs` (new) — `AyaWriter` struct owning the config-map aya wrappers + `impl MapWriter for AyaWriter`.
- `src/control/mod.rs` — `Inner` loses the config maps + shadow + agnostic-meta fields (they move into `ControlCore<AyaWriter>`); gains `core: ControlCore<AyaWriter>`; keeps device/loader fields. Agnostic methods become thin delegations.
- `src/control/{routes,nat,lb,firewall}.rs` — emptied (their impls move to `flowplane-control`); deleted once callers are rewired.
- `src/node.rs` — handlers call `ctrl.core...` where they called agnostic `Control` methods (signatures preserved, so mostly unchanged).

Workspace `Cargo.toml` — add `flowplane/flowplane-control` to `members` (and `default-members`).

---

## Task 1: Scaffold `flowplane-control` + `MapWriter` trait + `MemMapWriter`

**Files:**
- Create: `flowplane/flowplane-control/Cargo.toml`
- Create: `flowplane/flowplane-control/src/lib.rs`
- Create: `flowplane/flowplane-control/src/writer.rs`
- Create: `flowplane/flowplane-control/src/mem.rs`
- Modify: root `Cargo.toml` (workspace members)

- [ ] **Step 1: Create the crate + register in the workspace.**

Create `flowplane/flowplane-control/Cargo.toml`:

```toml
[package]
name = "flowplane-control"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
flowplane-common = { path = "../flowplane-common" }
anyhow = { workspace = true }

[features]
# In-memory MapWriter for tests (this crate) and B1b bring-up. Off by default.
mem-writer = []

[dev-dependencies]
flowplane-control = { path = ".", features = ["mem-writer"] }
```

In the root `Cargo.toml`, add `"flowplane/flowplane-control"` to BOTH `members` and `default-members` (the latter so `cargo test` picks it up by default).

- [ ] **Step 2: Write the failing test.**

Create `flowplane/flowplane-control/src/writer.rs` with the trait (the §C surface). Every method mirrors an existing aya wrapper call one-to-one:

```rust
//! The control-plane map write surface. eBPF (`AyaWriter`) and DPDK (`SharedConfigMaps`, B1b)
//! each implement this; `ControlCore` programs maps only through it.
use flowplane_common::{
    DhcpConfig, FwMeta, FwRule, FwRuleKey, LbKey, LbValue, MaglevKey, NatKey, NatValue,
    NeighborNatEntry, RouteValue, UnderlayValue,
};

/// The set of conntrack entries a NAT teardown must invalidate. eBPF flushes matching CT map
/// entries; DPDK bumps the config-generation (see spec §5a). Fields mirror `ct_flush_for_guest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtFlushScope {
    pub vni: u32,
    pub guest_ip: [u8; 4],
    pub nat_ip: [u8; 4],
    pub port_min: u16,
    pub port_max: u16,
}

/// Uniform config-map write surface. All methods return `anyhow::Result<()>` except the reads
/// used by conflict checks. Method names are `<map>_<op>`.
pub trait MapWriter {
    // routes / routes6
    fn route_upsert(&mut self, vni: u32, ipv4: [u8; 4], prefix_len: u32, val: RouteValue) -> anyhow::Result<()>;
    fn route_remove(&mut self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<()>;
    fn route6_upsert(&mut self, vni: u32, ipv6: [u8; 16], prefix_len: u32, val: RouteValue) -> anyhow::Result<()>;
    fn route6_remove(&mut self, vni: u32, ipv6: [u8; 16], prefix_len: u32) -> anyhow::Result<()>;
    // nat / nat_ips
    fn nat_upsert(&mut self, key: NatKey, val: NatValue) -> anyhow::Result<()>;
    fn nat_remove(&mut self, key: &NatKey) -> anyhow::Result<()>;
    fn nat_get(&self, key: &NatKey) -> Option<NatValue>;
    fn nat_ips_set(&mut self, vni: u32, nat_ip: [u8; 4]) -> anyhow::Result<()>;
    fn nat_ips_remove(&mut self, vni: u32, nat_ip: [u8; 4]) -> anyhow::Result<()>;
    // neighbor nat
    fn neigh_nat_upsert(&mut self, idx: u32, val: NeighborNatEntry) -> anyhow::Result<()>;
    fn neigh_nat_count_set(&mut self, count: u32) -> anyhow::Result<()>;
    // lb / maglev
    fn lb_upsert(&mut self, key: LbKey, val: LbValue) -> anyhow::Result<()>;
    fn lb_remove(&mut self, key: &LbKey) -> anyhow::Result<()>;
    fn maglev_upsert(&mut self, key: MaglevKey, val: [u8; 16]) -> anyhow::Result<()>;
    fn maglev_remove(&mut self, key: &MaglevKey) -> anyhow::Result<()>;
    // underlay
    fn underlay_upsert(&mut self, key: [u8; 16], val: UnderlayValue) -> anyhow::Result<()>;
    fn underlay_remove(&mut self, key: &[u8; 16]) -> anyhow::Result<()>;
    fn underlay_get(&self, key: &[u8; 16]) -> Option<UnderlayValue>;
    // firewall
    fn fw_rules_upsert(&mut self, key: FwRuleKey, val: FwRule) -> anyhow::Result<()>;
    fn fw_rules_remove(&mut self, key: &FwRuleKey) -> anyhow::Result<()>;
    fn fw_meta_upsert(&mut self, ifindex: u32, val: FwMeta) -> anyhow::Result<()>;
    // meter (qos)
    fn meter_upsert(&mut self, ifindex: u32, val: flowplane_common::MeterState) -> anyhow::Result<()>;
    fn meter_remove(&mut self, ifindex: &u32) -> anyhow::Result<()>;
    // dhcp
    fn dhcp_config_set(&mut self, cfg: &DhcpConfig) -> anyhow::Result<()>;
    // conntrack invalidation on NAT teardown (backend-specific behavior; see spec §5a)
    fn conntrack_flush(&mut self, scope: CtFlushScope) -> anyhow::Result<()>;
}
```

> NOTE: the interface-programming maps (`ports`, `ifaces`, `iface_meta`, `dhcp_meta`, `vips`) are added to this trait in Task 7 when `program_interface` moves. Keep the trait growing per task rather than all at once.

Create `flowplane/flowplane-control/src/lib.rs`:

```rust
//! Backend-agnostic control-plane programming shared by the eBPF and DPDK dataplanes.
pub mod writer;
#[cfg(feature = "mem-writer")]
pub mod mem;

pub use writer::{CtFlushScope, MapWriter};
```

Create `flowplane/flowplane-control/src/mem.rs` — an in-memory `MapWriter` used by tests. It stores each table in a `HashMap`/`Vec` so assertions can inspect them:

```rust
//! In-memory `MapWriter` for testing `ControlCore` without CAP_BPF or a live map.
use std::collections::HashMap;
use flowplane_common::{
    DhcpConfig, FwMeta, FwRule, FwRuleKey, LbKey, LbValue, MaglevKey, MeterState, NatKey, NatValue,
    NeighborNatEntry, RouteValue, UnderlayValue,
};
use crate::writer::{CtFlushScope, MapWriter};

#[derive(Default)]
pub struct MemMapWriter {
    pub routes: HashMap<(u32, [u8; 4], u32), RouteValue>,
    pub routes6: HashMap<(u32, [u8; 16], u32), RouteValue>,
    pub nat: HashMap<NatKey, NatValue>,
    pub nat_ips: std::collections::HashSet<(u32, [u8; 4])>,
    pub neigh_nat: HashMap<u32, NeighborNatEntry>,
    pub neigh_nat_count: u32,
    pub lb: HashMap<LbKey, LbValue>,
    pub maglev: HashMap<MaglevKey, [u8; 16]>,
    pub underlay: HashMap<[u8; 16], UnderlayValue>,
    pub fw_rules: HashMap<FwRuleKey, FwRule>,
    pub fw_meta: HashMap<u32, FwMeta>,
    pub meter: HashMap<u32, MeterState>,
    pub dhcp_config: Option<DhcpConfig>,
    pub ct_flushes: Vec<CtFlushScope>,
}

impl MapWriter for MemMapWriter {
    fn route_upsert(&mut self, vni: u32, ipv4: [u8; 4], p: u32, val: RouteValue) -> anyhow::Result<()> { self.routes.insert((vni, ipv4, p), val); Ok(()) }
    fn route_remove(&mut self, vni: u32, ipv4: [u8; 4], p: u32) -> anyhow::Result<()> { self.routes.remove(&(vni, ipv4, p)); Ok(()) }
    fn route6_upsert(&mut self, vni: u32, ipv6: [u8; 16], p: u32, val: RouteValue) -> anyhow::Result<()> { self.routes6.insert((vni, ipv6, p), val); Ok(()) }
    fn route6_remove(&mut self, vni: u32, ipv6: [u8; 16], p: u32) -> anyhow::Result<()> { self.routes6.remove(&(vni, ipv6, p)); Ok(()) }
    fn nat_upsert(&mut self, k: NatKey, v: NatValue) -> anyhow::Result<()> { self.nat.insert(k, v); Ok(()) }
    fn nat_remove(&mut self, k: &NatKey) -> anyhow::Result<()> { self.nat.remove(k); Ok(()) }
    fn nat_get(&self, k: &NatKey) -> Option<NatValue> { self.nat.get(k).copied() }
    fn nat_ips_set(&mut self, vni: u32, ip: [u8; 4]) -> anyhow::Result<()> { self.nat_ips.insert((vni, ip)); Ok(()) }
    fn nat_ips_remove(&mut self, vni: u32, ip: [u8; 4]) -> anyhow::Result<()> { self.nat_ips.remove(&(vni, ip)); Ok(()) }
    fn neigh_nat_upsert(&mut self, i: u32, v: NeighborNatEntry) -> anyhow::Result<()> { self.neigh_nat.insert(i, v); Ok(()) }
    fn neigh_nat_count_set(&mut self, c: u32) -> anyhow::Result<()> { self.neigh_nat_count = c; Ok(()) }
    fn lb_upsert(&mut self, k: LbKey, v: LbValue) -> anyhow::Result<()> { self.lb.insert(k, v); Ok(()) }
    fn lb_remove(&mut self, k: &LbKey) -> anyhow::Result<()> { self.lb.remove(k); Ok(()) }
    fn maglev_upsert(&mut self, k: MaglevKey, v: [u8; 16]) -> anyhow::Result<()> { self.maglev.insert(k, v); Ok(()) }
    fn maglev_remove(&mut self, k: &MaglevKey) -> anyhow::Result<()> { self.maglev.remove(k); Ok(()) }
    fn underlay_upsert(&mut self, k: [u8; 16], v: UnderlayValue) -> anyhow::Result<()> { self.underlay.insert(k, v); Ok(()) }
    fn underlay_remove(&mut self, k: &[u8; 16]) -> anyhow::Result<()> { self.underlay.remove(k); Ok(()) }
    fn underlay_get(&self, k: &[u8; 16]) -> Option<UnderlayValue> { self.underlay.get(k).copied() }
    fn fw_rules_upsert(&mut self, k: FwRuleKey, v: FwRule) -> anyhow::Result<()> { self.fw_rules.insert(k, v); Ok(()) }
    fn fw_rules_remove(&mut self, k: &FwRuleKey) -> anyhow::Result<()> { self.fw_rules.remove(k); Ok(()) }
    fn fw_meta_upsert(&mut self, i: u32, v: FwMeta) -> anyhow::Result<()> { self.fw_meta.insert(i, v); Ok(()) }
    fn meter_upsert(&mut self, i: u32, v: MeterState) -> anyhow::Result<()> { self.meter.insert(i, v); Ok(()) }
    fn meter_remove(&mut self, i: &u32) -> anyhow::Result<()> { self.meter.remove(i); Ok(()) }
    fn dhcp_config_set(&mut self, c: &DhcpConfig) -> anyhow::Result<()> { self.dhcp_config = Some(*c); Ok(()) }
    fn conntrack_flush(&mut self, s: CtFlushScope) -> anyhow::Result<()> { self.ct_flushes.push(s); Ok(()) }
}
```

Run: `cargo build -p flowplane-control --features mem-writer`
Expected: FAIL if any `flowplane_common` type name is wrong (e.g. `RouteValue`, `NatKey`, `MeterState`, `DhcpConfig`). Fix any import to match the actual `flowplane-common` exports (grep `flowplane/flowplane-common/src/lib.rs` for the exact type names).

- [ ] **Step 3: Make it compile.**

Adjust imports in `writer.rs`/`mem.rs` until `cargo build -p flowplane-control --features mem-writer` succeeds. Confirm each `flowplane_common` type used exists: `grep -n 'pub struct RouteValue\|pub struct NatKey\|pub struct NatValue\|pub struct LbKey\|pub struct LbValue\|pub struct MaglevKey\|pub struct FwRule\|pub struct FwRuleKey\|pub struct FwMeta\|pub struct MeterState\|pub struct UnderlayValue\|pub struct NeighborNatEntry\|pub struct DhcpConfig' flowplane/flowplane-common/src/*.rs`.

- [ ] **Step 4: Verify it builds and the workspace still builds.**

Run: `cargo build -p flowplane-control --features mem-writer && cargo build -p flowplane`
Expected: PASS — both build; `flowplane` is unaffected (new crate is not yet a dependency).

- [ ] **Step 5: Commit.**

```bash
git add flowplane/flowplane-control Cargo.toml
git commit -m "feat(control): scaffold flowplane-control crate + MapWriter trait + MemMapWriter"
```

---

## Task 2: Move the ROUTES domain into `ControlCore`

**Files:**
- Create: `flowplane/flowplane-control/src/shadow.rs`
- Create: `flowplane/flowplane-control/src/routes.rs`
- Modify: `flowplane/flowplane-control/src/lib.rs`

This task establishes `ControlCore<W>` and the **transform pattern** every later domain follows:
- `g.<map>.upsert(...)` → `self.w.<map>_upsert(...)` (the `MapWriter` method).
- `g.<shadow>` → `self.<shadow>` (a field on `ControlCore`).
- The method body is otherwise moved verbatim (routes.rs headers already say "Pure code movement — no logic changes").

- [ ] **Step 1: Define `ControlCore` + move the route shadow types.**

Create `flowplane/flowplane-control/src/shadow.rs`:

```rust
//! Agnostic shadow/meta types moved out of the eBPF `Control::Inner`.
/// (vni, prefix, prefix_len, nexthop_vni, nexthop_ipv6) — mirrors control/mod.rs RouteShadowV4.
pub type RouteShadowV4 = (u32, [u8; 4], u32, u32, [u8; 16]);
/// (vni, prefix, prefix_len, nexthop_vni, nexthop_ipv6) — mirrors control/mod.rs RouteShadowV6.
pub type RouteShadowV6 = (u32, [u8; 16], u32, u32, [u8; 16]);
```

In `flowplane/flowplane-control/src/lib.rs`, add the core struct (fields grow per task):

```rust
pub mod writer;
pub mod shadow;
#[cfg(feature = "mem-writer")]
pub mod mem;
mod routes;

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
        Self { w, routes_shadow: Vec::new(), routes6_shadow: Vec::new() }
    }
    /// Consume the core, returning the writer (used by the eBPF adapter on teardown).
    pub fn into_writer(self) -> W { self.w }
    pub fn writer_mut(&mut self) -> &mut W { &mut self.w }
}
```

- [ ] **Step 2: Write the failing test.**

Create `flowplane/flowplane-control/src/routes.rs` and put a unit test at the bottom that uses `MemMapWriter`:

```rust
use crate::{shadow::{RouteShadowV4, RouteShadowV6}, ControlCore, MapWriter};
use flowplane_common::RouteValue;

impl<W: MapWriter> ControlCore<W> {
    // (methods added in Step 3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::MemMapWriter;

    #[test]
    fn create_route_writes_map_and_shadow_and_rejects_dup() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.create_route(7, [10, 0, 0, 0], 24, [0u8; 16], 7, false).unwrap();
        assert!(c.w.routes.contains_key(&(7, [10, 0, 0, 0], 24)));
        assert_eq!(c.routes_shadow.len(), 1);
        // duplicate rejected
        assert!(c.create_route(7, [10, 0, 0, 0], 24, [0u8; 16], 7, false).is_err());
        // delete removes both
        assert!(c.delete_route(7, [10, 0, 0, 0], 24).unwrap());
        assert!(!c.w.routes.contains_key(&(7, [10, 0, 0, 0], 24)));
        assert_eq!(c.routes_shadow.len(), 0);
        assert!(!c.delete_route(7, [10, 0, 0, 0], 24).unwrap());
    }
}
```

Run: `cargo test -p flowplane-control --features mem-writer routes`
Expected: FAIL — `create_route` not defined on `ControlCore`.

- [ ] **Step 3: Move the four route methods verbatim, applying the transform.**

Into the `impl<W: MapWriter> ControlCore<W>` block in `routes.rs`, move `create_route`, `delete_route`, `create_route6`, `delete_route6` from `flowplane/flowplane/src/control/routes.rs` (lines 11-101), applying exactly:
- delete `let mut g = self.inner.lock();` (ControlCore has no inner lock — its methods take `&mut self`); change each method to `&mut self`.
- `g.routes_shadow` → `self.routes_shadow`; `g.routes6_shadow` → `self.routes6_shadow`.
- `g.routes.upsert(vni, ipv4, prefix_len, val)` → `self.w.route_upsert(vni, ipv4, prefix_len, val)`.
- `g.routes.remove(vni, ipv4, prefix_len)` → `self.w.route_remove(vni, ipv4, prefix_len)`.
- `g.routes6.upsert(...)` → `self.w.route6_upsert(...)`; `g.routes6.remove(...)` → `self.w.route6_remove(...)`.
- Keep the duplicate-check and retain logic byte-for-byte.

The signatures become (note `&mut self`):
```rust
pub fn create_route(&mut self, vni: u32, ipv4: [u8; 4], prefix_len: u32, nexthop_ipv6: [u8; 16], nexthop_vni: u32, is_external: bool) -> anyhow::Result<()>
pub fn delete_route(&mut self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<bool>
pub fn create_route6(&mut self, vni: u32, ipv6: [u8; 16], prefix_len: u32, nexthop_ipv6: [u8; 16], nexthop_vni: u32, is_external: bool) -> anyhow::Result<()>
pub fn delete_route6(&mut self, vni: u32, ipv6: [u8; 16], prefix_len: u32) -> anyhow::Result<bool>
```

- [ ] **Step 4: Run the test.**

Run: `cargo test -p flowplane-control --features mem-writer routes`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add flowplane/flowplane-control/src
git commit -m "feat(control): ControlCore route programming (generic over MapWriter)"
```

---

## Task 3: Wire the eBPF `flowplane` to use `ControlCore` for routes (`AyaWriter`)

This is where the eBPF crate starts calling `flowplane-control`. It introduces `AyaWriter` and proves the existing tests still pass. NOTE: this is the delicate structural task — moving the config-map fields out of `Inner` into `AyaWriter` held by `ControlCore`.

**Files:**
- Modify: `flowplane/flowplane/Cargo.toml`
- Create: `flowplane/flowplane/src/control/aya_writer.rs`
- Modify: `flowplane/flowplane/src/control/mod.rs`
- Modify: `flowplane/flowplane/src/control/routes.rs` (delete moved methods)
- Modify: `flowplane/flowplane/src/node.rs` (route handlers)

- [ ] **Step 1: Add the dependency.**

In `flowplane/flowplane/Cargo.toml` add under `[dependencies]`: `flowplane-control = { path = "../flowplane-control" }`.

- [ ] **Step 2: Create `AyaWriter` implementing `MapWriter` (routes methods real, rest `todo!()` for now).**

Create `flowplane/flowplane/src/control/aya_writer.rs`. It owns the config-map aya wrappers moved out of `Inner`, and implements `MapWriter`. For THIS task only the route methods are real; the other trait methods are `unimplemented!("moved in a later task")` so the crate compiles — they are never called yet because `Inner` still holds the other maps and the other agnostic methods still live on `Control`.

```rust
//! `MapWriter` over the eBPF aya map wrappers. Owns the config maps moved out of `Control::Inner`.
use flowplane_control::{CtFlushScope, MapWriter};
use flowplane_common::RouteValue;
use crate::maps::{Routes, Routes6};

pub struct AyaWriter {
    pub routes: Routes,
    pub routes6: Routes6,
    // Remaining config maps are migrated here in Tasks 4-7.
}

impl MapWriter for AyaWriter {
    fn route_upsert(&mut self, vni: u32, ipv4: [u8; 4], p: u32, val: RouteValue) -> anyhow::Result<()> { self.routes.upsert(vni, ipv4, p, val) }
    fn route_remove(&mut self, vni: u32, ipv4: [u8; 4], p: u32) -> anyhow::Result<()> { self.routes.remove(vni, ipv4, p) }
    fn route6_upsert(&mut self, vni: u32, ipv6: [u8; 16], p: u32, val: RouteValue) -> anyhow::Result<()> { self.routes6.upsert(vni, ipv6, p, val) }
    fn route6_remove(&mut self, vni: u32, ipv6: [u8; 16], p: u32) -> anyhow::Result<()> { self.routes6.remove(vni, ipv6, p) }
    // The following are wired in later tasks; not reachable until then.
    fn nat_upsert(&mut self, _k: flowplane_common::NatKey, _v: flowplane_common::NatValue) -> anyhow::Result<()> { unimplemented!("Task 4") }
    fn nat_remove(&mut self, _k: &flowplane_common::NatKey) -> anyhow::Result<()> { unimplemented!("Task 4") }
    fn nat_get(&self, _k: &flowplane_common::NatKey) -> Option<flowplane_common::NatValue> { unimplemented!("Task 4") }
    fn nat_ips_set(&mut self, _vni: u32, _ip: [u8; 4]) -> anyhow::Result<()> { unimplemented!("Task 4") }
    fn nat_ips_remove(&mut self, _vni: u32, _ip: [u8; 4]) -> anyhow::Result<()> { unimplemented!("Task 4") }
    fn neigh_nat_upsert(&mut self, _i: u32, _v: flowplane_common::NeighborNatEntry) -> anyhow::Result<()> { unimplemented!("Task 4") }
    fn neigh_nat_count_set(&mut self, _c: u32) -> anyhow::Result<()> { unimplemented!("Task 4") }
    fn lb_upsert(&mut self, _k: flowplane_common::LbKey, _v: flowplane_common::LbValue) -> anyhow::Result<()> { unimplemented!("Task 5") }
    fn lb_remove(&mut self, _k: &flowplane_common::LbKey) -> anyhow::Result<()> { unimplemented!("Task 5") }
    fn maglev_upsert(&mut self, _k: flowplane_common::MaglevKey, _v: [u8; 16]) -> anyhow::Result<()> { unimplemented!("Task 5") }
    fn maglev_remove(&mut self, _k: &flowplane_common::MaglevKey) -> anyhow::Result<()> { unimplemented!("Task 5") }
    fn underlay_upsert(&mut self, _k: [u8; 16], _v: flowplane_common::UnderlayValue) -> anyhow::Result<()> { unimplemented!("Task 5") }
    fn underlay_remove(&mut self, _k: &[u8; 16]) -> anyhow::Result<()> { unimplemented!("Task 5") }
    fn underlay_get(&self, _k: &[u8; 16]) -> Option<flowplane_common::UnderlayValue> { unimplemented!("Task 5") }
    fn fw_rules_upsert(&mut self, _k: flowplane_common::FwRuleKey, _v: flowplane_common::FwRule) -> anyhow::Result<()> { unimplemented!("Task 6") }
    fn fw_rules_remove(&mut self, _k: &flowplane_common::FwRuleKey) -> anyhow::Result<()> { unimplemented!("Task 6") }
    fn fw_meta_upsert(&mut self, _i: u32, _v: flowplane_common::FwMeta) -> anyhow::Result<()> { unimplemented!("Task 6") }
    fn meter_upsert(&mut self, _i: u32, _v: flowplane_common::MeterState) -> anyhow::Result<()> { unimplemented!("Task 7") }
    fn meter_remove(&mut self, _i: &u32) -> anyhow::Result<()> { unimplemented!("Task 7") }
    fn dhcp_config_set(&mut self, _c: &flowplane_common::DhcpConfig) -> anyhow::Result<()> { unimplemented!("Task 7") }
    fn conntrack_flush(&mut self, _s: CtFlushScope) -> anyhow::Result<()> { unimplemented!("Task 4") }
}
```

- [ ] **Step 3: Move `routes`/`routes6` from `Inner` into `AyaWriter`, held via `ControlCore`.**

In `flowplane/flowplane/src/control/mod.rs`:
- Add `mod aya_writer; use aya_writer::AyaWriter;` and `use flowplane_control::ControlCore;`.
- Remove the `routes` and `routes6` fields from `Inner`.
- Add a field `core: ControlCore<AyaWriter>` to `Inner`.
- In `bring_up()` where `routes`/`routes6` are currently taken from the eBPF object, construct them into an `AyaWriter { routes, routes6 }` and then `core: ControlCore::new(aya_writer)`. (The other `AyaWriter` fields do not exist yet — they are added in later tasks; for now `AyaWriter` has only routes/routes6.)
- Delete the four route methods from `flowplane/flowplane/src/control/routes.rs` (they now live in `flowplane-control`). Replace that file's `impl Control` route methods with thin delegations on `Control`:

```rust
impl Control {
    pub fn create_route(&self, vni: u32, ipv4: [u8; 4], prefix_len: u32, nexthop_ipv6: [u8; 16], nexthop_vni: u32, is_external: bool) -> anyhow::Result<()> {
        self.inner.lock().core.create_route(vni, ipv4, prefix_len, nexthop_ipv6, nexthop_vni, is_external)
    }
    pub fn delete_route(&self, vni: u32, ipv4: [u8; 4], prefix_len: u32) -> anyhow::Result<bool> {
        self.inner.lock().core.delete_route(vni, ipv4, prefix_len)
    }
    pub fn create_route6(&self, vni: u32, ipv6: [u8; 16], prefix_len: u32, nexthop_ipv6: [u8; 16], nexthop_vni: u32, is_external: bool) -> anyhow::Result<()> {
        self.inner.lock().core.create_route6(vni, ipv6, prefix_len, nexthop_ipv6, nexthop_vni, is_external)
    }
    pub fn delete_route6(&self, vni: u32, ipv6: [u8; 16], prefix_len: u32) -> anyhow::Result<bool> {
        self.inner.lock().core.delete_route6(vni, ipv6, prefix_len)
    }
}
```
`node.rs` route handlers call `Control::create_route` etc. — their signatures are unchanged, so `node.rs` needs no edits (verify).

- [ ] **Step 4: Build + run the full flowplane test suite (the safety net).**

Run: `cargo build -p flowplane && cargo test -p flowplane`
Expected: PASS — same tests, same results as before this task. The route path now flows through `ControlCore`, behavior identical.

- [ ] **Step 5: Commit.**

```bash
git add flowplane/flowplane/Cargo.toml flowplane/flowplane/src/control
git commit -m "refactor(flowplane): route programming via flowplane-control ControlCore + AyaWriter"
```

---

## Task 4: Move the NAT + neighbor-NAT domain (with the conntrack-flush hook)

**Files:** `flowplane/flowplane-control/src/{lib.rs,nat.rs}`, `flowplane/flowplane/src/control/{mod.rs,nat.rs,aya_writer.rs}`.

The NAT methods read INTERFACE-META (`by_id` for vni/ipv4/underlay, and iterate all interfaces for conflict checks) and `lbs` (collision check), and `delete_nat` flushes conntrack. So `ControlCore` must, by this task, own the interface-meta map and the `lbs` shadow. To keep this task bounded: add an `ifaces_meta: HashMap<Vec<u8>, IfaceMeta>` (agnostic subset `{vni, ipv4, ipv6, underlay}`) and `lbs: HashMap<Vec<u8>, LbEntry>` to `ControlCore`, populated by the eBPF `create_interface`/`create_lb` (which stay on `Control` until Tasks 7/5 but ALSO mirror into `core`). The conntrack flush becomes `self.w.conntrack_flush(scope)`.

> TRANSITIONAL NOTE (not a bug): `create_nat` is the ONLY reader of `lbs` (the preferred-underlay collision check) and of interface metadata, and both move into `core` in THIS task. So from here on `Inner.lbs` is write-only/dead (kept in sync by the mirror only so Task 5's still-on-`Control` `create_lb` bookkeeping stays consistent) until Task 5 deletes `Inner.lbs` entirely. No `Control` method reads `Inner.lbs` after this task — verify with `grep -n 'g\.lbs\|\.lbs\b' flowplane/flowplane/src/control/` (only `create_lb`'s own writes should remain). If you prefer zero transitional mirroring, you MAY execute Task 5 (LB) before Task 4 (NAT) — LB has no interface-meta dependency, so `core.lbs` would already exist; adjust the `unimplemented!("Task N")` labels accordingly.

- [ ] **Step 1: Extend `ControlCore` state + `MapWriter` usage; move `IfaceMeta`/`LbEntry` agnostic types to `shadow.rs`.**

In `shadow.rs` add:
```rust
/// Agnostic per-interface metadata the nat/lb/fw/qos logic reads (subset of the eBPF IfaceRecord).
#[derive(Clone, Copy, Debug)]
pub struct IfaceMeta { pub vni: u32, pub ipv4: [u8; 4], pub ipv6: [u8; 16], pub underlay: [u8; 16] }
```
(The `LbEntry`/`LbIp`/`LbIpBytes` types move here in Task 5; for Task 4 the collision check only needs `lbs.values().any(|lb| lb.lb_underlay == pul)`, so define a minimal `LbEntry { pub lb_underlay: [u8; 16], /* backends etc. added in Task 5 */ }` now and extend it in Task 5.)

Add to `ControlCore` fields: `pub(crate) ifaces_meta: std::collections::HashMap<Vec<u8>, shadow::IfaceMeta>`, `pub(crate) lbs: std::collections::HashMap<Vec<u8>, shadow::LbEntry>`, `pub(crate) neigh_nats: Vec<flowplane_common::NeighborNatEntry>`. Initialize empty in `new()`. Add helper methods the eBPF side uses to mirror meta:
```rust
pub fn register_iface_meta(&mut self, id: Vec<u8>, m: shadow::IfaceMeta) { self.ifaces_meta.insert(id, m); }
pub fn forget_iface_meta(&mut self, id: &[u8]) { self.ifaces_meta.remove(id); }
```

- [ ] **Step 2: Write the failing test** in `flowplane-control/src/nat.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mem::MemMapWriter, shadow::IfaceMeta, ControlCore};

    #[test]
    fn create_and_delete_nat_programs_maps_and_flushes_ct() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.register_iface_meta(b"if1".to_vec(), IfaceMeta { vni: 5, ipv4: [10, 0, 0, 2], ipv6: [0u8; 16], underlay: [1u8; 16] });
        let ul = c.create_nat(b"if1", [1, 2, 3, 4], 1024, 2048, None).unwrap();
        assert_eq!(ul, [1u8; 16]);
        assert!(c.w.nat.contains_key(&flowplane_common::NatKey { vni: 5, ipv4: [10, 0, 0, 2] }));
        assert!(c.w.nat_ips.contains(&(5, [1, 2, 3, 4])));
        // duplicate NAT on same iface rejected
        assert!(c.create_nat(b"if1", [1, 2, 3, 4], 1024, 2048, None).is_err());
        assert!(c.delete_nat(b"if1").unwrap());
        assert_eq!(c.w.ct_flushes.len(), 1);
        assert!(!c.w.nat.contains_key(&flowplane_common::NatKey { vni: 5, ipv4: [10, 0, 0, 2] }));
    }
}
```
Run: `cargo test -p flowplane-control --features mem-writer nat` → FAIL (methods absent).

- [ ] **Step 3: Move `create_nat`, `delete_nat`, `add_neighbor_nat`, `del_neighbor_nat`, `neigh_nat_reprogram` verbatim, applying the transform.**

From `flowplane/flowplane/src/control/nat.rs`:
- `g.by_id.get(interface_id)` → look up `self.ifaces_meta.get(interface_id)` (fields `vni/ipv4/underlay`); the `by_id.values()`/`by_id.iter()` conflict iterations → iterate `self.ifaces_meta`.
- `g.lbs.values()` → `self.lbs.values()`.
- `g.nat.get(...)` → `self.w.nat_get(...)`; `g.nat.upsert(...)` → `self.w.nat_upsert(...)`; `g.nat.remove(...)` → `self.w.nat_remove(...)`.
- `g.nat_ips.set(...)` → `self.w.nat_ips_set(...)`; `g.nat_ips.remove(...)` → `self.w.nat_ips_remove(...)`.
- `g.neigh_nats` → `self.neigh_nats`; `neigh_nat_reprogram(&mut g)` becomes a `&mut self` method using `self.w.neigh_nat_upsert(...)` + `self.w.neigh_nat_count_set(...)`.
- The `delete_nat` conntrack flush: replace the `self.conntrack.lock()` + `Self::ct_flush_for_guest(...)` block with `self.w.conntrack_flush(CtFlushScope { vni, guest_ip: gip, nat_ip, port_min, port_max })?;`. **The actual CT scan/remove logic (`ct_flush_for_guest`) moves to the eBPF `AyaWriter::conntrack_flush` impl (Step 4)** — that is where the eBPF conntrack map lives.

- [ ] **Step 4: Implement `AyaWriter`'s nat/neigh methods + `conntrack_flush` for real.**

In `flowplane/flowplane/src/control/aya_writer.rs`, replace the `unimplemented!("Task 4")` bodies with the real aya calls (`self.nat.upsert(...)`, `self.nat.get(...)`, `self.nat_ips.set(...)`, `self.neigh_nat.upsert(...)`, `self.neigh_nat_count.set(...)`). Add the `nat`, `nat_ips`, `neigh_nat`, `neigh_nat_count` fields to `AyaWriter` (moved out of `Inner`). For `conntrack_flush`, `AyaWriter` must hold `conntrack: Arc<Mutex<Conntrack>>` (the same handle `Control` holds); the impl runs the former `ct_flush_for_guest` scan+remove using `scope`. Move `ct_flush_for_guest` (nat.rs:74-109) into `aya_writer.rs` as a private fn.

- [ ] **Step 5: Rewire `Control` + `Inner`.**

In `control/mod.rs`: remove `nat`, `nat_ips`, `neigh_nat`, `neigh_nat_count`, `neigh_nats` fields from `Inner` (moved to `AyaWriter`/`ControlCore`); construct them into `AyaWriter` in `bring_up`; make `AyaWriter` own the `conntrack` Arc clone. Replace `control/nat.rs`'s methods with thin delegations to `self.inner.lock().core.<method>(...)` (same signatures — `node.rs` unchanged). Ensure `create_interface` (still on `Control`) mirrors interface meta into `core.register_iface_meta(id, IfaceMeta{..})` at its commit point (mod.rs:672), and `detach_interface` calls `core.forget_iface_meta(id)`.

- [ ] **Step 6: Test both crates.**

Run: `cargo test -p flowplane-control --features mem-writer nat && cargo build -p flowplane && cargo test -p flowplane`
Expected: PASS — control-core nat test green; full flowplane suite unchanged.

- [ ] **Step 7: Commit.**

```bash
git add flowplane/flowplane-control/src flowplane/flowplane/src/control
git commit -m "refactor(flowplane): NAT + neighbor-NAT via ControlCore; CT flush behind MapWriter"
```

---

## Task 5: Move the LB + Maglev domain

**Files:** `flowplane/flowplane-control/src/{lib.rs,shadow.rs,lb.rs}`, `flowplane/flowplane/src/control/{mod.rs,lb.rs,aya_writer.rs}`.

- [ ] **Step 1: Move the LB shadow types** (`LbEntry` full definition, `LbIp`, `LbIpBytes` from control/mod.rs:112-140) into `shadow.rs` (extend the minimal `LbEntry` from Task 4 to its full fields: backends, ports, vni, lb_underlay, table_id). Add `next_table_id: u32` to `ControlCore`.

- [ ] **Step 2: Write the failing test** in `flowplane-control/src/lb.rs` — port the existing `create_lb_skips_underlay_write_for_wan_edge` assertion (control/mod.rs:1151) to use `MemMapWriter` (NO CAP_BPF): create_lb with vni==0 must NOT populate `w.underlay`; with vni!=0 it MUST. Plus an add/del backend round-trip asserting `w.maglev` slot counts. Run → FAIL.

- [ ] **Step 3: Move `create_lb`, `add_lb_target`, `del_lb_target`, `delete_lb` verbatim** from `control/lb.rs` (13-184), transform: `g.lbs` → `self.lbs`, `g.next_table_id` → `self.next_table_id`, `g.lb.upsert/remove` → `self.w.lb_upsert/lb_remove`, `g.maglev.upsert/remove` → `self.w.maglev_upsert/maglev_remove`, `g.underlay.upsert` → `self.w.underlay_upsert`. `crate::maglev::build(...)` → depend on the maglev builder: move `flowplane/flowplane/src/maglev.rs`'s pure `build` fn into `flowplane-control` (or `flowplane-core` if shared) and call it. (Check whether `maglev.rs` is already backend-agnostic and has no aya deps — the inventory says it is pure; move it to `flowplane-control::maglev`.)

- [ ] **Step 4: Implement `AyaWriter` lb/maglev/underlay methods for real** (add `lb`, `maglev`, `underlay` fields to `AyaWriter`, moved out of `Inner`); replace the `unimplemented!("Task 5")` bodies.

- [ ] **Step 5: Rewire** `Control`/`Inner` (remove `lb`, `maglev`, `underlay`, `lbs`, `next_table_id` from `Inner`; construct into `AyaWriter`/`ControlCore`; `control/lb.rs` methods become delegations). `create_lb` on `Control` must mirror the lb into `core.lbs` (it now lives there — so `Control::create_lb` becomes a delegation too). Verify `underlay_get` used by the test and the MAC-snapshot path is available via `core.writer().underlay_get` or a `Control` accessor.

- [ ] **Step 6: Test.** `cargo test -p flowplane-control --features mem-writer lb && cargo build -p flowplane && cargo test -p flowplane` → PASS. Note: the ported `create_lb_skips_underlay_write_for_wan_edge` now runs WITHOUT `#[ignore]`/CAP_BPF (it uses `MemMapWriter`) — a strict improvement; keep the eBPF integration test too if it still compiles.

- [ ] **Step 7: Commit.**
```bash
git add flowplane/flowplane-control/src flowplane/flowplane/src/control flowplane/flowplane/src/maglev.rs
git commit -m "refactor(flowplane): LB + Maglev via ControlCore; underlay writes behind MapWriter"
```

---

## Task 6: Move the firewall domain

**Files:** `flowplane/flowplane-control/src/{lib.rs,firewall.rs}`, `flowplane/flowplane/src/control/{mod.rs,firewall.rs,aya_writer.rs}`.

- [ ] **Step 1: Add fw state to `ControlCore`:** `fw: std::collections::HashMap<u32, Vec<(Vec<u8>, flowplane_common::FwRule)>>` (keyed by ifindex). Firewall reads `by_ifindex` to resolve interface_id→ifindex — extend `IfaceMeta` with `ifindex: u32` (populated by the eBPF create_interface at commit time) so `ControlCore` can resolve it from `ifaces_meta`.

- [ ] **Step 2: Write the failing test** in `flowplane-control/src/firewall.rs`: register an iface meta with an ifindex, `add_fw_rule` twice, assert `w.fw_rules`/`w.fw_meta` populated with the right slot count; `del_fw_rule` removes; duplicate rule-id rejected; cap at `FW_MAX_RULES`. Run → FAIL.

- [ ] **Step 3: Move `add_fw_rule`, `del_fw_rule`, `fw_reprogram` verbatim** from `control/firewall.rs` (16-93), transform: `g.by_ifindex[id]` → `self.ifaces_meta.get(id).ifindex`, `g.fw` → `self.fw`, `g.fw_rules.remove/upsert` → `self.w.fw_rules_remove/fw_rules_upsert`, `g.fw_meta.upsert` → `self.w.fw_meta_upsert`.

- [ ] **Step 4: Implement `AyaWriter` fw methods for real** (add `fw_rules`, `fw_meta` fields; replace `unimplemented!("Task 6")`).

- [ ] **Step 5: Rewire** (remove `fw_rules`, `fw_meta`, `fw` from `Inner`; `control/firewall.rs` → delegations).

- [ ] **Step 6: Test.** `cargo test -p flowplane-control --features mem-writer firewall && cargo build -p flowplane && cargo test -p flowplane` → PASS.

- [ ] **Step 7: Commit.**
```bash
git add flowplane/flowplane-control/src flowplane/flowplane/src/control
git commit -m "refactor(flowplane): firewall programming via ControlCore"
```

---

## Task 7: Move QoS + DHCP-config + the interface map-programming half

**Files:** `flowplane/flowplane-control/src/{lib.rs,interface.rs}`, `flowplane/flowplane/src/control/{mod.rs,aya_writer.rs}`.

This is the last and largest move: `set_qos` (mod.rs:946), `set_dhcp_config` (mod.rs:535), the `meter_state` pure helper (mod.rs:561), the map-programming body `program_iface_maps` (mod.rs:689-799 → ports/ifaces/underlay/routes/routes6/meter/iface_meta upserts), and the detach agnostic VNI-reset purge (mod.rs:843-906). `create_interface`/`detach_interface` on `Control` keep the DEVICE work (§D) and call into `ControlCore` for the map programming + meta registration.

- [ ] **Step 1: Extend `MapWriter`** with the interface-programming maps used by `program_iface_maps`: `ports_upsert/ports_remove`, `ifaces_upsert/ifaces_remove/ifaces_get`, `iface_meta_upsert/iface_meta_remove`, `dhcp_meta_remove`, `vips_upsert/vips_remove/vips_get`. Add matching `MemMapWriter` + `AyaWriter` impls. (Signatures: copy from `maps.rs` per §C.)

- [ ] **Step 2: Write failing tests** in `flowplane-control/src/interface.rs`: (a) `set_qos` three-lane mbps → `w.meter` state matches the ported `meter_state` (assert the exact `MeterState` the existing `meter_state_conversion` test at mod.rs:1077 asserts — port that test verbatim onto `MemMapWriter`); (b) `set_dhcp_config` sets `w.dhcp_config`; (c) `program_interface` writes ports/ifaces/underlay/self-routes/meter; (d) `purge_vni` on last-interface-in-VNI clears neigh/vips/nat/routes. Run → FAIL.

- [ ] **Step 3: Move the methods verbatim** applying the transform (`g.<map>.<op>` → `self.w.<map>_<op>`, `g.<shadow/meta>` → `self.<...>`, `g.by_ifindex[id]` → `self.ifaces_meta[id].ifindex`). `meter_state` and `LbIp::last4` are pure — move as free fns/methods on `ControlCore`. `program_interface(&mut self, params: IfaceParams) -> Result<()>` emits ports/ifaces/underlay/routes/routes6/meter/iface_meta (mod.rs:713-784). `purge_vni(&mut self, vni: u32)` holds the detach reconciliation (mod.rs:843-906).

- [ ] **Step 4: Implement the remaining `AyaWriter` methods for real** (`ports`, `ifaces`, `iface_meta`, `dhcp_meta`, `vips`, `meter`, `dhcp_config` fields moved out of `Inner`; replace all remaining `unimplemented!`). After this, `AyaWriter` owns ALL config maps and `Inner` holds only DEVICE/LOADER fields + `core`.

- [ ] **Step 5: Rewire `create_interface`/`detach_interface`.** They keep §D device lines (name/ifindex/mac resolve, tc/XDP attach, GuestLink, guest_dev devmap, unwind, links/by_ifindex device bookkeeping) and call `self.inner.lock().core.program_interface(params)` for the map half + `core.register_iface_meta(id, IfaceMeta{vni,ipv4,ipv6,underlay,ifindex})` at commit, and `core.purge_vni(...)`/`core.forget_iface_meta(id)` on detach. `set_qos`/`set_dhcp_config` become delegations. `node.rs` signatures unchanged.

- [ ] **Step 6: Test.** `cargo test -p flowplane-control --features mem-writer && cargo build -p flowplane && cargo test -p flowplane` → PASS. The `meter_state_conversion` assertion now runs in `flowplane-control` (no CAP_BPF).

- [ ] **Step 7: Commit.**
```bash
git add flowplane/flowplane-control/src flowplane/flowplane/src/control
git commit -m "refactor(flowplane): QoS + DHCP + interface map-programming via ControlCore"
```

---

## Task 8: Cleanup + final verification

**Files:** `flowplane/flowplane/src/control/{routes,nat,lb,firewall}.rs` (delete if now only delegations — or keep as thin delegation modules), `flowplane/flowplane/src/control/mod.rs`.

- [ ] **Step 1: Remove dead code.** Delete the now-empty child modules if their only content is delegations that can live inline in `mod.rs`, OR keep them as thin `impl Control { .. delegations .. }` files (follow whichever keeps `mod.rs` smaller). Confirm `Inner` no longer holds any CONFIG-MAP or CONFIG-SHADOW field — only DEVICE/LOADER + `core`. Confirm no `unimplemented!` remains in `aya_writer.rs`.

Run: `grep -rn 'unimplemented!\|todo!' flowplane/flowplane/src/control/` → Expected: no matches.

- [ ] **Step 2: Full workspace build + test + clippy.**

Run: `cargo build --workspace && cargo test -p flowplane-control --features mem-writer && cargo test -p flowplane && cargo clippy -p flowplane-control -p flowplane -- -D warnings`
Expected: all PASS, no clippy warnings.

- [ ] **Step 3: Confirm the seam is real (no duplicated orchestration).**

Run: `grep -rn 'fn create_route\|fn create_nat\|fn create_lb\|fn add_fw_rule\|fn set_qos' flowplane/flowplane/src/ flowplane/flowplane-control/src/`
Expected: each orchestration body appears ONCE (in `flowplane-control`); `flowplane` has only delegations. This is the [[seam-not-duplicate-for-tests]] check.

- [ ] **Step 4: Commit.**
```bash
git add flowplane/flowplane/src/control
git commit -m "refactor(flowplane): drop empty control shadow fields; verify single-source orchestration"
```

---

## Manual checkpoint (before B1b)

Run the clab regression sweep (cross-cluster ping + QoS + LB + NAT egress) on the eBPF dataplane built from this branch to confirm the extraction is behavior-preserving on a live fabric — the unit suite covers logic, but only the fabric exercises the full attach→program→forward path. Only after it passes should B1b (the DPDK `MapWriter` + `flowplane-dpdk serve`) build on `flowplane-control`.
