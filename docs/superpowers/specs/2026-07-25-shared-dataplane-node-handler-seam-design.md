# Shared DataplaneNode handler seam — design

Date: 2026-07-25
Status: designed, approved

## Problem

The eBPF (`flowplane/src/node.rs`, `NodeService`) and DPDK
(`flowplane-dpdk/src/node.rs`, `DpdkNodeService`) gRPC `DataplaneNode` services
each re-implement the ~13 backend-agnostic RPC handlers (routes / NAT /
neighbor-NAT / LB / firewall / QoS). Each handler is thin proto→args marshalling
that drives the SAME `flowplane_control::ControlCore` orchestration — the
orchestration is already single-source (ControlCore is generic over
`MapWriter`), but the marshalling around it is duplicated. So are the pure parse
helpers (`parse_prefix`, `parse_fw_cidr`, `parse_nexthop6`, `parse_ipv4`, plus
DPDK's `parse_mac`/`first_ipv4`/`first_ipv6`).

This duplication already drifts: the eBPF handlers log (`println!`) and gate on a
readiness guard (`self.attach` → `failed_precondition`); the DPDK handlers do
neither. The [[seam-not-duplicate-for-tests]] invariant wants ONE source for the
handler logic so the two backends cannot diverge.

Each crate also compiles `api/proto/dataplane/v1/dataplane.proto` independently
(its own `build.rs` + `tonic::include_proto!`), so the two `pb` modules are
DISTINCT types — the root obstacle to sharing a handler that takes a proto type.

## Decision

Extract the marshalling into a **new `flowplane-node` crate** that (a) compiles
the proto ONCE and (b) hosts per-RPC generic marshalling fns + the parse
helpers. Each backend keeps its own concurrency wrapper, readiness guard, and
logging, but the parse + `ControlCore`-call + response logic is single-source.

Rejected: putting the shared code in `flowplane-control` (it is deliberately
tonic-free — used by CAP_BPF-free `MemMapWriter` tests; adding tonic/proto would
pollute the pure-orchestration crate). Rejected: a fully-unified tonic service
(blanket impl over the writer) — it would require unifying the two backends'
concurrency models (eBPF `spawn_blocking` over a `Control` wrapper vs DPDK
`parking_lot::Mutex<ControlCore>`), changing the working eBPF control plane.

## Architecture

```
flowplane-common (types) → flowplane-control (orchestration, tonic-free)
                                     ↓
                         flowplane-node  (NEW: proto + shared handlers + parse helpers)
                            ↓                         ↓
                   flowplane (eBPF NodeService)   flowplane-dpdk (DpdkNodeService)
```

### `flowplane-node` crate

- **Compiles the proto once.** `build.rs` runs `tonic_build` on
  `api/proto/dataplane/v1/dataplane.proto`; the crate exposes `pub mod pb { tonic::include_proto!("dataplane.v1"); }`
  — the proto message types AND the generated `dataplane_node_server::DataplaneNode`
  service trait + `DataplaneNodeServer`. Both binaries drop their own proto
  `build.rs` step + `include_proto!` and use `flowplane_node::pb`.
- **Parse helpers** (moved verbatim from the two node.rs files, with their existing
  unit tests): `parse_prefix`, `parse_fw_cidr`, `parse_nexthop6`, `parse_ipv4`,
  `parse_mac`, `first_ipv4`, `first_ipv6`.
- **Per-RPC marshalling fns** for the agnostic set (below).
- Depends on: `flowplane-control` (`ControlCore`, `MapWriter`, and the shared arg
  types it already exposes — e.g. `flowplane_control::shadow::LbIpBytes`),
  `tonic` (for `Status` + the generated service), `prost`, `flowplane-common`.

### The shared marshalling fn boundary

One generic fn per agnostic RPC, taking `&mut ControlCore<W>` (ControlCore
methods are `&mut self`) + the shared proto request, returning the proto response
or a `tonic::Status`:

```rust
pub fn add_route<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddRouteRequest,
) -> Result<pb::AddRouteResponse, Status> {
    let (is_v6, bytes, len) =
        parse_prefix(&req.prefix).map_err(|e| Status::invalid_argument(e.to_string()))?;
    let nexthop =
        parse_nexthop6(&req.nexthop_underlay).map_err(|e| Status::invalid_argument(e.to_string()))?;
    // Idempotent: drop any existing (vni, prefix) so a re-announce replaces the nexthop.
    if is_v6 {
        let _ = core.delete_route6(req.vni, bytes, len).map_err(internal)?;
        core.create_route6(req.vni, bytes, len, nexthop, req.vni, req.external).map_err(internal)?;
    } else {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&bytes[..4]);
        let _ = core.delete_route(req.vni, v4, len).map_err(internal)?;
        core.create_route(req.vni, v4, len, nexthop, req.vni, req.external).map_err(internal)?;
    }
    Ok(pb::AddRouteResponse {})
}
```

Each fn is **side-effect-free** apart from the `ControlCore` writes: no logging,
no I/O, no tonic transport. `internal` is a shared `|e| Status::internal(e.to_string())`
helper. This makes every fn unit-testable by calling it directly against a
`ControlCore<MemMapWriter>` (no root, no tonic).

**Agnostic set (shared, 13):** `add_route`, `withdraw_route`, `add_nat_source`,
`withdraw_nat_source`, `add_neighbor_nat`, `withdraw_neighbor_nat`, `add_lb_vip`,
`add_lb_backend`, `del_lb_vip`, `del_lb_backend`, `add_fw_rule`, `del_fw_rule`,
`configure_qos`. (`configure_network` is included only if the plan confirms it is
pure-`ControlCore` on both backends; otherwise it stays per-backend.)

### What stays per-backend

- **Device RPCs:** `attach_interface`, `detach_interface`, `list_interfaces` —
  they touch device/attach state (eBPF stands up the real device; DPDK stubs +
  returns `Unimplemented`, B2). Not shared.
- **Each `#[tonic::async_trait]` impl** stays in its binary and, for each agnostic
  RPC, keeps: its readiness guard, its concurrency wrapper, and its logging —
  delegating the parse+ControlCore+response to the `flowplane-node` fn.

  eBPF's `Control` (in `flowplane/src/control/mod.rs`) wraps
  `Mutex<Inner>` where `Inner.core: ControlCore<AyaWriter>`. Its agnostic methods
  are pure delegates (`self.inner.lock().core.<op>()`). Add ONE accessor:
  ```rust
  // flowplane/src/control/mod.rs
  pub fn with_core<R>(&self, f: impl FnOnce(&mut ControlCore<AyaWriter>) -> R) -> R {
      let mut g = self.inner.lock();
      f(&mut g.core)
  }
  ```
  Then an eBPF handler becomes (readiness guard + logging preserved):
  ```rust
  let attach = self.attach.as_ref().ok_or_else(|| Status::failed_precondition("datapath not initialized"))?.clone();
  let r = req.into_inner();
  let resp = tokio::task::spawn_blocking(move || attach.control.with_core(|c| flowplane_node::add_route(c, &r)))
      .await.map_err(|e| Status::internal(format!("add_route task panicked: {e}")))??;
  // (existing println! logging stays here if desired)
  Ok(Response::new(resp))
  ```
  DPDK stays inline under its lock:
  ```rust
  let r = req.into_inner();
  let resp = { let mut core = self.ctrl.lock(); flowplane_node::add_route(&mut core, &r)? };
  Ok(Response::new(resp))
  ```

  The redundant per-crate `Control` agnostic delegate methods (e.g.
  `Control::create_route`) that only existed to serve the node handler MAY be
  removed if the handler is their sole caller (the plan checks callers); otherwise
  they stay and simply are no longer used by the node path.

## Data flow

```
gRPC add_route ─▶ [per-backend wrapper: readiness + concurrency + logging]
                        │  &mut ControlCore<W>
                        ▼
              flowplane_node::add_route(core, req)   ← SINGLE SOURCE
                  parse → ControlCore ops → pb::Response | Status
```

## Testing

1. **`flowplane-node` unit tests** (no root, no tonic): moved parse-helper tests +
   for each marshalling fn, build a `ControlCore<flowplane_control::mem::MemMapWriter>`,
   call the fn with a crafted `pb` request, and assert (a) success returns the empty
   response AND the expected ControlCore/shadow state, and (b) a malformed field
   returns the right `Status` code (`invalid_argument`). At least the representative
   RPCs across each family (route, nat, neighbor-nat, lb, fw, qos) get a happy-path +
   a bad-input test.
2. **Both binaries' existing node tests stay green:** `flowplane` suite (44/3
   baseline, incl. `configure_network_returns_ok`, `attach_without_datapath_is_failed_precondition`);
   the `flowplane-dpdk` node unit tests. No behavior change to the RPC surface.
3. **Datapath / byte-parity untouched:** this is control-plane marshalling only —
   `make sim` (70) and `make sim-anchor` unchanged; not re-run as part of this work
   beyond a final sanity pass.
4. **Divergence guarantee (the goal):** after extraction both backends call the
   same `flowplane_node` fn per agnostic RPC, so the handler logic cannot drift.

## Scope boundaries (YAGNI)

- No unified tonic service / no change to either backend's concurrency model.
- No change to `ControlCore` / `MapWriter` / the datapath / eBPF programs / sim.
- Device RPCs (`attach`/`detach`/`list`) and B2 are out of scope.
- Logging stays per-backend (eBPF keeps its `println!`s; DPDK unchanged) — the
  shared fns add none.
- `flowplane-control` stays tonic-free (the new tonic layer is `flowplane-node`).
