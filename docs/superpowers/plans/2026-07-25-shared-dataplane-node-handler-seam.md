# Shared DataplaneNode Handler Seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the duplicated (and drifting) agnostic gRPC handler marshalling between the eBPF `NodeService` and DPDK `DpdkNodeService` by extracting a new `flowplane-node` crate that compiles the proto once and hosts per-RPC generic marshalling fns both binaries call.

**Architecture:** New `flowplane-node` crate = shared proto (`pb`) + parse helpers + `handle_x<W: MapWriter>(&mut ControlCore<W>, &pb::Req) -> Result<pb::Resp, Status>` fns for the 13 backend-agnostic RPCs. Each binary keeps its own tonic service impl (concurrency wrapper + readiness guard + logging) but delegates the parse+ControlCore+response logic to the shared fns. `flowplane-control` stays tonic-free. Control-plane only; datapath/byte-parity untouched.

**Tech Stack:** Rust, tonic/prost (gRPC), `flowplane-control` (`ControlCore`/`MapWriter`), `flowplane-control::mem::MemMapWriter` (CAP_BPF-free test writer).

**Reference spec:** `docs/superpowers/specs/2026-07-25-shared-dataplane-node-handler-seam-design.md`

---

## File Structure

- `flowplane/flowplane-node/` — NEW crate:
  - `Cargo.toml`, `build.rs` (tonic_build on the shared .proto), `src/lib.rs` (pb module + re-exports)
  - `src/parse.rs` — the shared parse helpers + their tests
  - `src/handlers.rs` — the 13 marshalling fns + unit tests over `ControlCore<MemMapWriter>`
- `Cargo.toml` (workspace root) — add `flowplane/flowplane-node` to `members`
- `flowplane/flowplane-dpdk/` — `Cargo.toml` (dep on flowplane-node; drop the proto build dep), `build.rs` (drop the proto compile), `src/node.rs` (use `flowplane_node::pb`, delegate agnostic handlers, drop local parse helpers)
- `flowplane/flowplane/` — `Cargo.toml` (dep on flowplane-node; drop the proto build dep), `build.rs` (drop the proto compile), `src/control/mod.rs` (add `with_core`), `src/node.rs` (use `flowplane_node::pb`, delegate agnostic handlers, drop local parse helpers)

**Note on the 13 agnostic RPCs:** `add_route`, `withdraw_route`, `add_nat_source`, `withdraw_nat_source`, `add_neighbor_nat`, `withdraw_neighbor_nat`, `add_lb_vip`, `add_lb_backend`, `del_lb_vip`, `del_lb_backend`, `add_fw_rule`, `del_fw_rule`, `configure_qos`. `configure_network`, `attach`, `detach`, `list_interfaces` stay per-backend (device/agnostic-but-composite — out of scope).

---

## Task 1: Create the `flowplane-node` crate (proto compiled once)

**Files:**
- Create: `flowplane/flowplane-node/Cargo.toml`, `flowplane/flowplane-node/build.rs`, `flowplane/flowplane-node/src/lib.rs`
- Modify: `Cargo.toml` (workspace root, `members` list)

- [ ] **Step 1: Add the crate to the workspace members**

In the root `Cargo.toml`, add `"flowplane/flowplane-node"` to the `members` array (leave `default-members` as-is — flowplane-node is not a default member, matching flowplane-dpdk/nfkit).

- [ ] **Step 2: Write `flowplane/flowplane-node/Cargo.toml`**

Read `flowplane/flowplane-dpdk/Cargo.toml` first to copy the exact tonic/prost/tonic-build versions and the `flowplane-control` path-dep style. Then:

```toml
[package]
name = "flowplane-node"
version = "0.1.0"
edition = "2021"

[dependencies]
flowplane-common = { path = "../flowplane-common" }
flowplane-control = { path = "../flowplane-control" }
# Match the versions used by flowplane-dpdk/Cargo.toml:
tonic = "<same as flowplane-dpdk>"
prost = "<same as flowplane-dpdk>"
anyhow = "<same as flowplane-dpdk>"

[build-dependencies]
tonic-build = "<same as flowplane-dpdk>"
```

- [ ] **Step 3: Write `flowplane/flowplane-node/build.rs`**

Copy the tonic_build invocation from `flowplane/flowplane-dpdk/build.rs` (which compiles `../../api/proto/dataplane/v1/dataplane.proto`). The .proto path is relative to the crate dir, so it is the SAME string `"../../api/proto/dataplane/v1/dataplane.proto"` (flowplane-node sits at the same depth as flowplane-dpdk). Example:

```rust
fn main() {
    tonic_build::configure()
        .build_client(false) // server-only, matches the binaries' usage; drop this line if flowplane-dpdk's build.rs builds the client
        .compile_protos(
            &["../../api/proto/dataplane/v1/dataplane.proto"],
            &["../../api/proto"],
        )
        .expect("tonic-build compile dataplane protos");
}
```
Match `flowplane-dpdk/build.rs`'s exact `.configure()` chain (client/server flags, include dir) so the generated code is identical.

- [ ] **Step 4: Write `flowplane/flowplane-node/src/lib.rs` with a proto smoke test**

```rust
//! Shared DataplaneNode gRPC layer: the proto types (compiled once here) + parse helpers + the
//! per-RPC marshalling fns both the eBPF `flowplane` and DPDK `flowplane-dpdk` node services call.
//! Keeps the handler logic single-source (the seam-not-duplicate invariant). `flowplane-control`
//! stays tonic-free; this crate is the tonic layer on top of it.

pub mod pb {
    tonic::include_proto!("dataplane.v1");
}

pub mod parse;
pub mod handlers;

pub use parse::*;
pub use handlers::*;

#[cfg(test)]
mod tests {
    #[test]
    fn proto_types_present() {
        // Smoke: the shared proto compiled and the agnostic request/response types exist.
        let _ = super::pb::AddRouteRequest::default();
        let _ = super::pb::AddRouteResponse::default();
        let _ = super::pb::ConfigureQoSRequest::default();
    }
}
```

Create empty `flowplane/flowplane-node/src/parse.rs` and `flowplane/flowplane-node/src/handlers.rs` (just `//! ...` doc lines) so lib.rs compiles this task; they are filled in Tasks 2–3.

- [ ] **Step 5: Verify it compiles + the smoke test passes**

Run: `cargo test -p flowplane-node`
Expected: builds, `proto_types_present ... ok`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml flowplane/flowplane-node/
git commit -m "feat(node): new flowplane-node crate compiling the dataplane proto once"
```

---

## Task 2: Shared parse helpers

**Files:**
- Modify: `flowplane/flowplane-node/src/parse.rs`

These move verbatim from `flowplane/flowplane/src/node.rs` (lines ~610–690) and `flowplane/flowplane-dpdk/src/node.rs` (lines ~509–620). The two copies are identical; read `flowplane/flowplane-dpdk/src/node.rs`'s versions and copy them exactly (they include `parse_mac`, `first_ipv4`, `first_ipv6` which the eBPF file lacks).

- [ ] **Step 1: Write the failing tests + helpers into `parse.rs`**

Copy the helper bodies EXACTLY from `flowplane/flowplane-dpdk/src/node.rs` (do not rewrite them): `parse_prefix`, `parse_fw_cidr`, `parse_nexthop6`, `parse_ipv4`, `port_u16`, `parse_mac`, `first_ipv4`, `first_ipv6`. Make each `pub`. Also copy the existing `#[cfg(test)]` tests for `parse_prefix` from `flowplane/flowplane/src/node.rs` (`parse_prefix_v4_and_v6`, `parse_prefix_rejects_bad`) into a `#[cfg(test)] mod tests` here, and add a couple more:

```rust
    #[test]
    fn port_u16_bounds() {
        assert_eq!(port_u16(0).unwrap(), 0);
        assert_eq!(port_u16(65535).unwrap(), 65535);
        assert!(port_u16(65536).is_err());
    }

    #[test]
    fn parse_mac_ok_and_bad() {
        assert_eq!(parse_mac("02:00:00:00:00:01").unwrap(), [2, 0, 0, 0, 0, 1]);
        assert!(parse_mac("not-a-mac").is_err());
    }
```

(The module needs `use anyhow` etc. — copy the imports the helpers reference from the source file.)

- [ ] **Step 2: Run to verify pass**

Run: `cargo test -p flowplane-node parse`
Expected: all parse tests pass.

- [ ] **Step 3: Commit**

```bash
git add flowplane/flowplane-node/src/parse.rs
git commit -m "feat(node): shared proto parse helpers (parse_prefix/fw_cidr/nexthop6/ipv4/mac/port_u16)"
```

---

## Task 3: The 13 marshalling fns + unit tests

**Files:**
- Modify: `flowplane/flowplane-node/src/handlers.rs`

Each fn translates the current DPDK inline handler body (`flowplane/flowplane-dpdk/src/node.rs`) by replacing `let mut core = self.ctrl.lock();` with the `core: &mut ControlCore<W>` parameter and returning the response value instead of `Response::new(...)`. The ControlCore call sequences and error mapping are copied exactly.

- [ ] **Step 1: Write the handler fns**

Top of `handlers.rs`:

```rust
//! Per-RPC marshalling fns shared by both DataplaneNode services. Each parses its `pb` request,
//! drives the SAME `ControlCore` calls the eBPF + DPDK handlers used, and builds the response —
//! side-effect-free apart from the ControlCore writes (no logging, no tonic transport), so each is
//! unit-testable directly against a `ControlCore<MemMapWriter>`.

use flowplane_control::{shadow::LbIpBytes, ControlCore, MapWriter};
use tonic::Status;

use crate::parse::{parse_fw_cidr, parse_ipv4, parse_nexthop6, parse_prefix, port_u16};
use crate::pb;

#[inline]
fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}
#[inline]
fn invalid(e: impl std::fmt::Display) -> Status {
    Status::invalid_argument(e.to_string())
}

pub fn add_route<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddRouteRequest,
) -> Result<pb::AddRouteResponse, Status> {
    let (is_v6, bytes, len) = parse_prefix(&req.prefix).map_err(invalid)?;
    let nexthop = parse_nexthop6(&req.nexthop_underlay).map_err(invalid)?;
    if is_v6 {
        let _ = core.delete_route6(req.vni, bytes, len).map_err(internal)?;
        core.create_route6(req.vni, bytes, len, nexthop, req.vni, req.external)
            .map_err(internal)?;
    } else {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&bytes[..4]);
        let _ = core.delete_route(req.vni, v4, len).map_err(internal)?;
        core.create_route(req.vni, v4, len, nexthop, req.vni, req.external)
            .map_err(internal)?;
    }
    Ok(pb::AddRouteResponse {})
}

pub fn withdraw_route<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::WithdrawRouteRequest,
) -> Result<pb::WithdrawRouteResponse, Status> {
    let (is_v6, bytes, len) = parse_prefix(&req.prefix).map_err(invalid)?;
    if is_v6 {
        core.delete_route6(req.vni, bytes, len).map_err(internal)?;
    } else {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&bytes[..4]);
        core.delete_route(req.vni, v4, len).map_err(internal)?;
    }
    Ok(pb::WithdrawRouteResponse {})
}

pub fn add_nat_source<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddNatSourceRequest,
) -> Result<pb::AddNatSourceResponse, Status> {
    let source = parse_ipv4(&req.source_ip).map_err(invalid)?;
    let nat_ip = parse_ipv4(&req.nat_ip).map_err(invalid)?;
    let port_min = port_u16(req.port_min).map_err(invalid)?;
    let port_max = port_u16(req.port_max).map_err(invalid)?;
    let id = core.find_iface_by_vni_ipv4(req.vni, source).ok_or_else(|| {
        Status::internal(format!(
            "NO_VM: no local interface for vni={} ip={}",
            req.vni,
            std::net::Ipv4Addr::from(source)
        ))
    })?;
    core.delete_nat(&id)
        .and_then(|_| core.create_nat(&id, nat_ip, port_min, port_max, None).map(|_| ()))
        .map_err(internal)?;
    Ok(pb::AddNatSourceResponse {})
}

pub fn withdraw_nat_source<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::WithdrawNatSourceRequest,
) -> Result<pb::WithdrawNatSourceResponse, Status> {
    let source = parse_ipv4(&req.source_ip).map_err(invalid)?;
    if let Some(id) = core.find_iface_by_vni_ipv4(req.vni, source) {
        core.delete_nat(&id).map_err(internal)?;
    }
    Ok(pb::WithdrawNatSourceResponse {})
}

pub fn add_neighbor_nat<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddNeighborNatRequest,
) -> Result<pb::AddNeighborNatResponse, Status> {
    let nat_ip = parse_ipv4(&req.nat_ip).map_err(invalid)?;
    let owner = parse_nexthop6(&req.owner_underlay).map_err(invalid)?;
    let port_min = port_u16(req.port_min).map_err(invalid)?;
    let port_max = port_u16(req.port_max).map_err(invalid)?;
    core.del_neighbor_nat(req.vni, nat_ip, port_min, port_max)
        .and_then(|_| core.add_neighbor_nat(req.vni, nat_ip, port_min, port_max, owner))
        .map_err(internal)?;
    Ok(pb::AddNeighborNatResponse {})
}

pub fn withdraw_neighbor_nat<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::WithdrawNeighborNatRequest,
) -> Result<pb::WithdrawNeighborNatResponse, Status> {
    let nat_ip = parse_ipv4(&req.nat_ip).map_err(invalid)?;
    let port_min = port_u16(req.port_min).map_err(invalid)?;
    let port_max = port_u16(req.port_max).map_err(invalid)?;
    core.del_neighbor_nat(req.vni, nat_ip, port_min, port_max)
        .map_err(internal)?;
    Ok(pb::WithdrawNeighborNatResponse {})
}

pub fn add_lb_vip<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddLbVipRequest,
) -> Result<pb::AddLbVipResponse, Status> {
    let lb_ip = match req.vip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => LbIpBytes::Ipv4(a.octets()),
        Ok(std::net::IpAddr::V6(a)) => LbIpBytes::Ipv6(a.octets()),
        Err(e) => return Err(Status::invalid_argument(format!("invalid vip {:?}: {e}", req.vip))),
    };
    let lb_underlay = parse_nexthop6(&req.lb_underlay).map_err(invalid)?;
    let ports: Vec<(u16, u8)> = req
        .ports
        .iter()
        .map(|pp| -> anyhow::Result<(u16, u8)> {
            let port = port_u16(pp.port)?;
            let proto = u8::try_from(pp.proto).map_err(|_| anyhow::anyhow!("proto {} > 255", pp.proto))?;
            Ok((port, proto))
        })
        .collect::<anyhow::Result<_>>()
        .map_err(invalid)?;
    let id = req.id.clone().into_bytes();
    core.create_lb(&id, req.vni, lb_ip, lb_underlay, ports)
        .map_err(internal)?;
    Ok(pb::AddLbVipResponse {})
}

pub fn add_lb_backend<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddLbBackendRequest,
) -> Result<pb::AddLbBackendResponse, Status> {
    let backend = parse_nexthop6(&req.backend_underlay).map_err(invalid)?;
    let id = req.id.clone().into_bytes();
    core.add_lb_target(&id, backend).map_err(internal)?;
    Ok(pb::AddLbBackendResponse {})
}

pub fn del_lb_vip<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::DelLbVipRequest,
) -> Result<pb::DelLbVipResponse, Status> {
    let id = req.id.clone().into_bytes();
    core.delete_lb(&id).map_err(internal)?;
    Ok(pb::DelLbVipResponse {})
}

pub fn del_lb_backend<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::DelLbBackendRequest,
) -> Result<pb::DelLbBackendResponse, Status> {
    let backend = parse_nexthop6(&req.backend_underlay).map_err(invalid)?;
    let id = req.id.clone().into_bytes();
    core.del_lb_target(&id, backend).map_err(internal)?;
    Ok(pb::DelLbBackendResponse {})
}

pub fn add_fw_rule<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::AddFwRuleRequest,
) -> Result<pb::AddFwRuleResponse, Status> {
    use flowplane_common::{FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS, FW_DIR_INGRESS};
    let (src_ip, src_mask) = parse_fw_cidr(&req.src_cidr).map_err(invalid)?;
    let (dst_ip, dst_mask) = parse_fw_cidr(&req.dst_cidr).map_err(invalid)?;
    let proto = u8::try_from(req.proto).map_err(|_| Status::invalid_argument("proto > 255"))?;
    let dst_port_min = port_u16(req.dst_port_min).map_err(invalid)?;
    let dst_port_max = if req.dst_port_max == 0 {
        65535u16
    } else {
        port_u16(req.dst_port_max).map_err(invalid)?
    };
    let rule = flowplane_common::FwRule {
        src_ip,
        src_mask,
        dst_ip,
        dst_mask,
        src_port_min: 0,
        src_port_max: 65535,
        dst_port_min,
        dst_port_max,
        icmp_type: 0xffff,
        icmp_code: 0xffff,
        proto,
        action: if req.allow { FW_ACTION_ACCEPT } else { FW_ACTION_DROP },
        direction: if req.egress { FW_DIR_EGRESS } else { FW_DIR_INGRESS },
        enabled: 1,
    };
    let iface = req.interface_id.clone().into_bytes();
    let rule_id = req.rule_id.clone().into_bytes();
    core.add_fw_rule(&iface, rule_id, rule).map_err(internal)?;
    Ok(pb::AddFwRuleResponse {})
}

pub fn del_fw_rule<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::DelFwRuleRequest,
) -> Result<pb::DelFwRuleResponse, Status> {
    let iface = req.interface_id.clone().into_bytes();
    let rule_id = req.rule_id.clone().into_bytes();
    core.del_fw_rule(&iface, &rule_id).map_err(internal)?;
    Ok(pb::DelFwRuleResponse {})
}

pub fn configure_qos<W: MapWriter>(
    core: &mut ControlCore<W>,
    req: &pb::ConfigureQoSRequest,
) -> Result<pb::ConfigureQoSResponse, Status> {
    let iface = req.interface_id.clone().into_bytes();
    core.set_qos(&iface, req.egress_mbps as u64, req.public_mbps as u64, req.ingress_mbps as u64)
        .map_err(internal)?;
    Ok(pb::ConfigureQoSResponse {})
}
```

IMPORTANT: these are transcribed from the current DPDK bodies. Before finishing, open `flowplane/flowplane-dpdk/src/node.rs` and diff each fn's parse+ControlCore-call sequence against the transcription — if any ControlCore method name/arg or proto field name differs (e.g. `req.owner_underlay`, `create_nat`'s trailing `None`), fix the transcription to match the real signatures. Do NOT invent methods; if a call doesn't compile, read the ControlCore signature in `flowplane-control/src/{routes,nat,lb,firewall,interface}.rs` and adjust.

- [ ] **Step 2: Write unit tests over `ControlCore<MemMapWriter>`**

Append to `handlers.rs`. These build a real `ControlCore<MemMapWriter>` (no privileges — pattern from `flowplane-control/src/lb.rs` tests) and drive the fns. Cover one happy-path per family + a bad-input case:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_control::mem::MemMapWriter;

    fn core() -> ControlCore<MemMapWriter> {
        ControlCore::new(MemMapWriter::default())
    }

    #[test]
    fn add_route_v4_programs_and_bad_prefix_rejected() {
        let mut c = core();
        // happy path: a valid external /24 route programs without error.
        let ok = add_route(
            &mut c,
            &pb::AddRouteRequest {
                vni: 100,
                prefix: "10.0.0.0/24".into(),
                nexthop_underlay: "2001:db8::1".into(),
                external: true,
            },
        );
        assert!(ok.is_ok(), "valid route: {ok:?}");
        // bad input: malformed prefix → invalid_argument.
        let bad = add_route(
            &mut c,
            &pb::AddRouteRequest {
                vni: 100,
                prefix: "not-a-cidr".into(),
                nexthop_underlay: "2001:db8::1".into(),
                external: true,
            },
        );
        assert_eq!(bad.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn add_fw_rule_programs() {
        let mut c = core();
        let r = add_fw_rule(
            &mut c,
            &pb::AddFwRuleRequest {
                interface_id: "if-1".into(),
                rule_id: "r-1".into(),
                src_cidr: "0.0.0.0/0".into(),
                dst_cidr: "10.0.0.5/32".into(),
                proto: 6,
                dst_port_min: 443,
                dst_port_max: 443,
                allow: true,
                egress: false,
            },
        );
        assert!(r.is_ok(), "fw rule: {r:?}");
    }

    #[test]
    fn configure_qos_programs() {
        let mut c = core();
        let r = configure_qos(
            &mut c,
            &pb::ConfigureQoSRequest {
                interface_id: "if-1".into(),
                egress_mbps: 100,
                public_mbps: 50,
                ingress_mbps: 100,
            },
        );
        assert!(r.is_ok(), "qos: {r:?}");
    }

    #[test]
    fn add_neighbor_nat_programs() {
        let mut c = core();
        let r = add_neighbor_nat(
            &mut c,
            &pb::AddNeighborNatRequest {
                vni: 100,
                nat_ip: "198.51.100.7".into(),
                owner_underlay: "2001:db8::bb".into(),
                port_min: 20000,
                port_max: 30000,
            },
        );
        assert!(r.is_ok(), "neighbor nat: {r:?}");
    }
}
```

Confirm each `pb::*Request` literal's fields match the real proto (field names/types from `api/proto/dataplane/v1/dataplane.proto`); adjust any field name/type that differs. If `MemMapWriter` has no `Default`, use its actual constructor (check `flowplane-control/src/mem.rs`; the lb.rs tests use `MemMapWriter::default()`).

- [ ] **Step 3: Run to verify pass**

Run: `cargo test -p flowplane-node`
Expected: all handler + parse + smoke tests pass.

- [ ] **Step 4: Commit**

```bash
git add flowplane/flowplane-node/src/handlers.rs
git commit -m "feat(node): shared marshalling fns for the 13 agnostic DataplaneNode RPCs"
```

---

## Task 4: Rewire the DPDK node service onto the shared fns

**Files:**
- Modify: `flowplane/flowplane-dpdk/Cargo.toml`, `flowplane/flowplane-dpdk/build.rs`, `flowplane/flowplane-dpdk/src/node.rs`

- [ ] **Step 1: Depend on flowplane-node; use its proto**

In `flowplane-dpdk/Cargo.toml` add `flowplane-node = { path = "../flowplane-node" }`. In `flowplane-dpdk/build.rs`, REMOVE the `tonic_build ... compile_protos(... dataplane.proto ...)` block (flowplane-node compiles it now). If the build.rs becomes empty, leave a `fn main() {}`. In `flowplane-dpdk/src/node.rs`, replace the local `mod pb { tonic::include_proto!("dataplane.v1"); }` with `use flowplane_node::pb;` (and keep `use pb::dataplane_node_server::DataplaneNode;`). Update any `pb::...` references to resolve through the re-exported module.

- [ ] **Step 2: Delegate each agnostic handler to the shared fn**

Replace the body of each of the 13 agnostic handlers in `flowplane-dpdk/src/node.rs` with the delegation form. Example for `add_route`:

```rust
    async fn add_route(
        &self,
        req: Request<AddRouteRequest>,
    ) -> Result<Response<AddRouteResponse>, Status> {
        let r = req.into_inner();
        let resp = {
            let mut core = self.ctrl.lock();
            flowplane_node::add_route(&mut core, &r)?
        };
        Ok(Response::new(resp))
    }
```

Do the same for the other 12 (`withdraw_route`, `add_nat_source`, `withdraw_nat_source`, `add_neighbor_nat`, `withdraw_neighbor_nat`, `add_lb_vip`, `add_lb_backend`, `del_lb_vip`, `del_lb_backend`, `add_fw_rule`, `del_fw_rule`, `configure_qo_s` → calls `flowplane_node::configure_qos`). Leave `attach_interface`, `detach_interface`, `list_interfaces`, `configure_network` UNCHANGED.

- [ ] **Step 3: Delete the now-unused local helpers**

Remove the local `parse_prefix`, `parse_fw_cidr`, `parse_nexthop6`, `parse_ipv4`, `port_u16`, `parse_mac`, `first_ipv4`, `first_ipv6` from `flowplane-dpdk/src/node.rs` IF they are no longer referenced (attach still uses `parse_mac`/`first_ipv4`/`first_ipv6` — keep those, or switch attach to `flowplane_node::{parse_mac, first_ipv4, first_ipv6}` and delete the locals). The compiler's dead-code / unused warnings will flag any leftover; resolve them so the build is warning-clean.

- [ ] **Step 4: Verify**

Run: `cargo build -p flowplane-dpdk && cargo test -p flowplane-dpdk`
Expected: builds warning-clean; existing node tests (`configure_network_returns_ok`, `attach_without_datapath_is_failed_precondition`, etc.) pass.

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane-dpdk/
git commit -m "refactor(dpdk): DpdkNodeService delegates agnostic RPCs to flowplane-node"
```

---

## Task 5: Rewire the eBPF node service onto the shared fns

**Files:**
- Modify: `flowplane/flowplane/Cargo.toml`, `flowplane/flowplane/build.rs`, `flowplane/flowplane/src/control/mod.rs`, `flowplane/flowplane/src/node.rs`

- [ ] **Step 1: Add the `with_core` accessor to `Control`**

In `flowplane/flowplane/src/control/mod.rs`, add to `impl Control` (near the other accessors like `take_conntrack`):

```rust
    /// Run `f` with an exclusive `&mut` borrow of the inner `ControlCore` under the `Inner` lock.
    /// Lets the shared `flowplane-node` handler fns drive the same ControlCore the per-domain
    /// `Control` methods use, without duplicating their parse/marshalling.
    pub fn with_core<R>(&self, f: impl FnOnce(&mut ControlCore<AyaWriter>) -> R) -> R {
        let mut g = self.inner.lock();
        f(&mut g.core)
    }
```
(Confirm the `ControlCore`/`AyaWriter` imports are in scope in `control/mod.rs`; they are — `Inner.core: ControlCore<AyaWriter>`.)

- [ ] **Step 2: Depend on flowplane-node; use its proto**

In `flowplane/Cargo.toml` add `flowplane-node = { path = "../flowplane-node" }`. In `flowplane/build.rs`, REMOVE the `tonic_build ... compile_protos(... dataplane.proto ...)` block (lines ~40–43; keep the rest of build.rs — the eBPF program build steps). In `flowplane/src/node.rs`, replace the local `mod pb { tonic::include_proto!("dataplane.v1"); }` with `use flowplane_node::pb;` (keep `use pb::dataplane_node_server::DataplaneNode;`).

- [ ] **Step 3: Delegate each agnostic handler to the shared fn (preserving the wrapper)**

Replace the body of each of the 13 agnostic handlers with the delegation form, KEEPING the readiness guard, `spawn_blocking`, and any existing `println!` logging. Example for `add_route`:

```rust
    async fn add_route(
        &self,
        req: Request<AddRouteRequest>,
    ) -> Result<Response<AddRouteResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let resp = tokio::task::spawn_blocking(move || attach.control.with_core(|c| flowplane_node::add_route(c, &r)))
            .await
            .map_err(|e| Status::internal(format!("add_route task panicked: {e}")))??;
        println!("ROUTE add vni={} prefix={}", r_vni_placeholder, r_prefix_placeholder); // see note
        Ok(Response::new(resp))
    }
```

NOTE on logging: the current eBPF `add_route` logs `r.vni`/`r.prefix` AFTER the call, but `r` is moved into `spawn_blocking`. Either (a) capture the log fields into locals BEFORE the move (`let (log_vni, log_prefix) = (r.vni, r.prefix.clone());`) and log those, or (b) drop the per-handler `println!` (logging is explicitly per-backend/optional in the spec — dropping it is acceptable and simpler). Pick ONE consistently across the handlers you touch; prefer (a) only where the handler currently logs, else (b). Do NOT change the readiness-guard or spawn_blocking behavior.

Apply the same delegation to the other 12 agnostic handlers, each preserving its own readiness guard + spawn_blocking wrapper (copy the wrapper shape from the current handler; only the inner work changes to `attach.control.with_core(|c| flowplane_node::X(c, &r))`). For handlers that currently build args before spawn_blocking and call multiple `attach.control` methods, the whole inner sequence collapses to the single shared fn. Leave `attach_interface`, `detach_interface`, `list_interfaces`, `configure_network` UNCHANGED.

- [ ] **Step 4: Delete the now-unused local helpers**

Remove `parse_prefix`, `parse_fw_cidr`, `parse_nexthop6`, `parse_ipv4`, `port_u16` from `flowplane/src/node.rs` if unreferenced after the rewire (resolve any dead-code warnings). If the per-domain `Control` agnostic methods (`Control::create_route`, `add_lb_target`, etc. in `flowplane/src/control/*.rs`) are now unused (the node handlers were their only callers), leave them for now UNLESS the compiler warns they're dead — if it does, remove the specifically-flagged ones. Do not remove `Control` methods still used elsewhere.

- [ ] **Step 5: Verify**

Run: `cargo build -p flowplane && cargo test -p flowplane`
Expected: builds warning-clean; the `flowplane` test suite passes (44/3 baseline — the node tests + all others).

- [ ] **Step 6: Commit**

```bash
git add flowplane/flowplane/
git commit -m "refactor(ebpf): NodeService delegates agnostic RPCs to flowplane-node via Control::with_core"
```

---

## Task 6: Final verification

**Files:** none (verification only)

- [ ] **Step 1: fmt + clippy on all touched crates**

Run: `cargo fmt --check -p flowplane-node -p flowplane-dpdk -p flowplane && cargo clippy -p flowplane-node -p flowplane-dpdk -p flowplane`
Expected: no fmt diff; no new warnings (pre-existing unrelated warnings like `too_many_arguments` on attach.rs may remain). If fmt diffs, `cargo fmt -p <crate>` and amend.

- [ ] **Step 2: Full non-root suites (datapath/byte-parity untouched)**

Run: `make test && make sim`
Expected: `flowplane-common`/host tests + `flowplane-sim` 70 green — unchanged (control-plane-only change).

- [ ] **Step 3: Privileged eBPF anchors unchanged**

Run: `make sim-anchor`
Expected: all anchors green (this change does not touch the datapath or eBPF programs).

- [ ] **Step 4: Confirm the proto is compiled exactly once**

Run: `grep -rn 'include_proto\|compile_protos' flowplane/flowplane/ flowplane/flowplane-dpdk/ flowplane/flowplane-node/`
Expected: only `flowplane-node` (`src/lib.rs` include_proto + `build.rs` compile_protos) — the two binaries no longer compile the proto themselves.

- [ ] **Step 5: Commit any fmt fixups (if Step 1 changed files)**

```bash
git add -A && git commit -m "chore(node): fmt after shared handler seam"
```

---

## Self-Review Notes (author)

- **Spec coverage:** new flowplane-node crate + proto-once (Task 1); shared parse helpers (Task 2); 13 marshalling fns + tests over MemMapWriter (Task 3); DPDK rewire + drop its proto build/helpers (Task 4); eBPF rewire via `Control::with_core` + readiness/spawn_blocking/logging preserved + drop its proto build/helpers (Task 5); verification incl. proto-compiled-once check (Task 6). All spec sections mapped.
- **Scope:** control-plane only; device RPCs (attach/detach/list) + configure_network left per-backend; ControlCore/MapWriter/datapath/eBPF/sim untouched; flowplane-control stays tonic-free.
- **Type consistency:** fn names `add_route`/…/`configure_qos` (note: proto rpc is `ConfigureQoS` → generated method `configure_qo_s`, but the shared fn is `configure_qos`); `Control::with_core`; `ControlCore<W: MapWriter>`; `MemMapWriter::default()`. The one transcription risk (exact ControlCore signatures/proto field names) is explicitly called out in Task 3 Step 1/2 with instructions to diff against the real source and fix.
