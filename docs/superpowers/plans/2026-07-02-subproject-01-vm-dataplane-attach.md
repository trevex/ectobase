# Sub-project ① (Phase A) — VM↔Dataplane Attach: Foundations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the monorepo foundations for running a KubeVirt VM exclusively on the eBPF dataplane — the primary-UDN research spike, the `api/` proto move, the Go workspace + kind e2e harness, the clean `dataplane.v1` gRPC, and a netns-proven `AttachInterface` on the extended `xdp-dp` daemon.

**Architecture:** Polyglot monorepo. The Rust `xdp-dp` daemon (existing aya datapath) gains a new clean `DataplaneNode` gRPC service under `api/proto/dataplane/v1`. A Go workspace holds the future CNI + the kind-based e2e harness. This Phase A stops before the primary-UDN CNI wiring, which gets its own plan once Task 1's spike fixes the mechanism.

**Tech Stack:** Rust (tonic, aya), Go (protoc-gen-go, controller-runtime/envtest, kind), KubeVirt + Multus + CDI, protobuf/gRPC, nix + Make.

**Parent spec:** `docs/superpowers/specs/2026-07-02-subproject-01-vm-dataplane-attach-design.md`

---

## File Structure (created/modified in this plan)

- `docs/superpowers/research/2026-07-02-primary-udn-mechanism.md` — **Create** (Task 1): the spike decision doc.
- `api/proto/dataplane/v1/dpdk.proto` — **Move** from `proto/dpdk.proto` (Task 2).
- `api/proto/dataplane/v1/dataplane.proto` — **Create** (Task 4): the clean `DataplaneNode` service.
- `xdp-dp/build.rs` — **Modify** (Tasks 2, 4): proto include paths.
- `xdp-dp/src/node.rs` — **Create** (Task 5): the `DataplaneNode` service impl.
- `xdp-dp/src/main.rs` — **Modify** (Task 5): register the new service (`~355-358`).
- `xdp-dp/src/ipam.rs` — **Create** (Task 6): minimal per-network IP allocator.
- `xdp-dp/src/attach.rs` — **Create** (Task 7): netns interface setup + eBPF endpoint programming.
- `go.work` — **Create** (Task 3).
- `cni/go.mod`, `cni/doc.go` — **Create** (Task 3): Go module placeholder for the CNI.
- `test/e2e/go.mod`, `test/e2e/kind_test.go` — **Create** (Task 3): kind harness + smoke test.
- `hack/kind-up.sh`, `hack/kind-down.sh`, `hack/install-stack.sh` — **Create** (Task 3).

---

### Task 1: Primary-UDN research spike (decision doc + manual proof)

This is a **research spike**, not TDD: its deliverable is a written decision + a manual proof, because the exact mechanism is unknown and downstream CNI code depends on the answer.

**Files:**
- Create: `docs/superpowers/research/2026-07-02-primary-udn-mechanism.md`

- [ ] **Step 1: Investigate the candidate mechanisms.** For each, record how it makes a *custom CNI* the virt-launcher pod's **primary** (only) network, with **no default pod network**, and the KubeVirt/Multus/k8s versions required:
  - Multus **default-network** delegation (`v1.multus-cni.io/default-network` annotation / Multus as cluster default CNI).
  - KubeVirt **network binding plugin** (`network-binding` + `NetworkBindingPlugins` feature gate) as the primary binding.
  - KubeVirt **primary user-defined network** API path (the ovn-kubernetes primary-UDN mechanism) and whether it is CNI-pluggable or ovn-specific.
  **Leading hypothesis (project steer):** a *custom KubeVirt network-binding plugin* is likely the required mechanism — evaluate it first (its sidecar/CNI contract, the `NetworkBindingPlugins` feature gate, and how it suppresses the default pod network), then compare against the alternatives. Use `WebSearch`/`WebFetch` on the KubeVirt user-guide, the network-binding-plugin docs, Multus docs, and the KubeVirt enhancements repo. Note version constraints and feature gates for each.

- [ ] **Step 2: Pick one mechanism and record the decision** in the doc: the chosen mechanism, why, exact feature gates/annotations, KubeVirt/Multus/CDI versions, and the concrete steps the CNI + node agent must perform.

- [ ] **Step 3: Manual proof (throwaway).** In a scratch kind cluster (use `hack/kind-up.sh` once Task 3 exists, or a manual `kind create cluster`), install KubeVirt + Multus + CDI, and bring up **one** VM whose primary interface is a trivial CNI (a stock bridge/macvlan CNI is fine as a stand-in for our dataplane) with **no default pod network**. Confirm via `kubectl exec`/`virtctl` into the virt-launcher pod that there is **no `eth0` pod-network interface**, only the delegated one. Capture the exact YAML + commands in the doc.

- [ ] **Step 4: Commit the decision doc.**
```bash
git add docs/superpowers/research/2026-07-02-primary-udn-mechanism.md
git commit -m "docs(research): primary-UDN mechanism decision for sub-project 1"
```

**Gate:** Tasks 2–7 do not depend on the spike outcome. The follow-up CNI+e2e plan does — write it only after this doc exists.

---

### Task 2: Move the proto into `api/proto/dataplane/v1`

**Files:**
- Move: `proto/dpdk.proto` → `api/proto/dataplane/v1/dpdk.proto`
- Modify: `xdp-dp/build.rs:40-44`

- [ ] **Step 1: Verify the current build is green (baseline).**

Run: `cargo build -p xdp-dp`
Expected: builds successfully (compiles `../proto/dpdk.proto`).

- [ ] **Step 2: Move the proto with git.**
```bash
mkdir -p api/proto/dataplane/v1
git mv proto/dpdk.proto api/proto/dataplane/v1/dpdk.proto
rmdir proto 2>/dev/null || true
```

- [ ] **Step 3: Update `xdp-dp/build.rs`** — replace the proto paths (lines ~40-44):
```rust
    // 2) Generate the dataplane gRPC services (server only).
    tonic_build::configure()
        .build_client(false)
        .compile_protos(
            &["../api/proto/dataplane/v1/dpdk.proto"],
            &["../api/proto/dataplane/v1"],
        )
        .context("tonic-build compile dataplane protos")?;
    println!("cargo:rerun-if-changed=../api/proto/dataplane/v1");
```

- [ ] **Step 4: Verify the build still passes** (the proto's `package dpdkironcore.v1;` is unchanged, so `main.rs:7 include_proto!("dpdkironcore.v1")` still resolves).

Run: `cargo build -p xdp-dp && cargo test -p xdp-dp`
Expected: PASS — no code change beyond the path.

- [ ] **Step 5: Commit.**
```bash
git add -A && git commit -m "refactor: move proto to api/proto/dataplane/v1 (Go-idiomatic api root)"
```

---

### Task 3: Go workspace + kind e2e harness skeleton

**Files:**
- Create: `go.work`, `cni/go.mod`, `cni/doc.go`, `test/e2e/go.mod`, `test/e2e/kind_test.go`
- Create: `hack/kind-up.sh`, `hack/kind-down.sh`, `hack/install-stack.sh`

- [ ] **Step 1: Create the Go workspace and module stubs.**
```bash
cat > go.work <<'EOF'
go 1.23

use (
	./cni
	./test/e2e
)
EOF
mkdir -p cni test/e2e
( cd cni && go mod init github.com/trevex/xdp-dp/cni )
printf 'package cni\n\n// Package cni holds the primary-UDN CNI plugin (implemented in a later plan).\n' > cni/doc.go
( cd test/e2e && go mod init github.com/trevex/xdp-dp/test/e2e )
```

- [ ] **Step 2: Write the failing kind smoke test.**

Create `test/e2e/kind_test.go`:
```go
package e2e

import (
	"os/exec"
	"testing"
)

// TestKindClusterLifecycle proves the harness can create and delete a kind
// cluster. It is the seed the two-VM e2e (later plan) grows from.
func TestKindClusterLifecycle(t *testing.T) {
	if _, err := exec.LookPath("kind"); err != nil {
		t.Skip("kind not installed")
	}
	up := exec.Command("../../hack/kind-up.sh", "xdp-e2e")
	if out, err := up.CombinedOutput(); err != nil {
		t.Fatalf("kind-up failed: %v\n%s", err, out)
	}
	down := exec.Command("../../hack/kind-down.sh", "xdp-e2e")
	if out, err := down.CombinedOutput(); err != nil {
		t.Fatalf("kind-down failed: %v\n%s", err, out)
	}
}
```

- [ ] **Step 3: Run it to verify it fails** (scripts don't exist yet).

Run: `cd test/e2e && go test -run TestKindClusterLifecycle -v`
Expected: FAIL — `kind-up.sh` not found (or skips if `kind` absent).

- [ ] **Step 4: Write the harness scripts.**

`hack/kind-up.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
NAME="${1:-xdp-e2e}"
kind get clusters | grep -qx "$NAME" || kind create cluster --name "$NAME"
```
`hack/kind-down.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
NAME="${1:-xdp-e2e}"
kind delete cluster --name "$NAME"
```
`hack/install-stack.sh` (used by the later e2e; stubbed now so the path exists):
```bash
#!/usr/bin/env bash
set -euo pipefail
# Installs KubeVirt + Multus + CDI into the current-context cluster.
# Versions are pinned per the Task 1 research doc; filled in by the CNI+e2e plan.
echo "install-stack: KubeVirt/Multus/CDI install is implemented in the CNI+e2e plan" >&2
exit 1
```
```bash
chmod +x hack/kind-up.sh hack/kind-down.sh hack/install-stack.sh
```

- [ ] **Step 5: Run the smoke test to verify it passes** (requires `kind` + a container runtime).

Run: `cd test/e2e && go test -run TestKindClusterLifecycle -v`
Expected: PASS (creates + deletes the cluster) — or SKIP if `kind` is unavailable in the runner.

- [ ] **Step 6: Verify Go builds.**

Run: `go build ./cni/... ./test/e2e/...`
Expected: PASS.

- [ ] **Step 7: Commit.**
```bash
git add go.work cni test/e2e hack && git commit -m "test(e2e): Go workspace + kind harness skeleton"
```

---

### Task 4: Clean `dataplane.v1` proto + codegen

**Files:**
- Create: `api/proto/dataplane/v1/dataplane.proto`
- Modify: `xdp-dp/build.rs` (add the new proto to the compile list)

- [ ] **Step 1: Write the clean node-agent proto.**

Create `api/proto/dataplane/v1/dataplane.proto`:
```proto
syntax = "proto3";

package dataplane.v1;

option go_package = "github.com/trevex/xdp-dp/cni/gen/dataplanev1;dataplanev1";

// DataplaneNode is the node-local API the CNI calls to wire a VM's interface
// into the eBPF dataplane. Purpose-built for this platform (not dpservice).
service DataplaneNode {
  rpc AttachInterface(AttachInterfaceRequest) returns (AttachInterfaceResponse);
  rpc DetachInterface(DetachInterfaceRequest) returns (DetachInterfaceResponse);
  rpc ConfigureNetwork(ConfigureNetworkRequest) returns (ConfigureNetworkResponse);
}

message AttachInterfaceRequest {
  string interface_id = 1; // stable id (e.g. VMI uid + iface name)
  string netns_path = 2;   // target network namespace path
  uint32 vni = 3;
  string mac = 4;          // optional; allocated if empty
  repeated string requested_ips = 5; // optional; allocated if empty
}
message AttachInterfaceResponse {
  string ifname = 1;
  repeated string ips = 2;
  string mac = 3;
  string gateway = 4;
}

message DetachInterfaceRequest { string interface_id = 1; }
message DetachInterfaceResponse {}

message ConfigureNetworkRequest {
  uint32 vni = 1;
  string gateway = 2;
  uint32 mtu = 3;
  repeated string dns = 4;
}
message ConfigureNetworkResponse {}
```

- [ ] **Step 2: Add it to the Rust codegen** — update the `compile_protos` call in `xdp-dp/build.rs`:
```rust
        .compile_protos(
            &[
                "../api/proto/dataplane/v1/dpdk.proto",
                "../api/proto/dataplane/v1/dataplane.proto",
            ],
            &["../api/proto/dataplane/v1"],
        )
```

- [ ] **Step 3: Verify Rust codegen compiles** (add a throwaway `let _ = "dataplane.v1";` usage is unnecessary — just confirm the crate builds; the module is included in Task 5).

Run: `cargo build -p xdp-dp`
Expected: PASS (both protos compile).

- [ ] **Step 4: Generate + compile the Go stubs.** Add a `proto-go` target to the `Makefile` (the `go_package` option is already in `dataplane.proto`):
```make
proto-go:
	protoc -I api/proto/dataplane/v1 \
		--go_out=cni/gen --go_opt=module=github.com/trevex/xdp-dp/cni/gen \
		--go-grpc_out=cni/gen --go-grpc_opt=module=github.com/trevex/xdp-dp/cni/gen \
		api/proto/dataplane/v1/dataplane.proto
```

Run: `make proto-go && go build ./cni/...`
Expected: PASS — generated Go stubs compile into `cni/gen/dataplanev1`.

- [ ] **Step 5: Commit.**
```bash
git add -A && git commit -m "feat(api): clean dataplane.v1 DataplaneNode gRPC + codegen"
```

---

### Task 5: `DataplaneNode` service skeleton on `xdp-dp`

`xdp-dp` is a **binary** crate (no lib target), so external `tests/` can't reach its internals. Test the service **in-crate** by calling the trait method directly — no client/server/lib-target needed (`build.rs` stays server-only).

**Files:**
- Create: `xdp-dp/src/node.rs` (service impl + in-crate unit test)
- Modify: `xdp-dp/src/main.rs` (`mod node;` + service registration at `~355-358`)

- [ ] **Step 1: Write the skeleton with a failing unit test** (`configure_network` returns `unimplemented` so the test is red first).

Create `xdp-dp/src/node.rs`:
```rust
use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("dataplane.v1");
}
use pb::dataplane_node_server::DataplaneNode;
use pb::{
    AttachInterfaceRequest, AttachInterfaceResponse, ConfigureNetworkRequest,
    ConfigureNetworkResponse, DetachInterfaceRequest, DetachInterfaceResponse,
};

#[derive(Default)]
pub struct NodeService;

#[tonic::async_trait]
impl DataplaneNode for NodeService {
    async fn attach_interface(&self, _req: Request<AttachInterfaceRequest>)
        -> Result<Response<AttachInterfaceResponse>, Status> {
        Err(Status::unimplemented("attach_interface: Task 7"))
    }
    async fn detach_interface(&self, _req: Request<DetachInterfaceRequest>)
        -> Result<Response<DetachInterfaceResponse>, Status> {
        Err(Status::unimplemented("detach_interface: Task 7"))
    }
    async fn configure_network(&self, _req: Request<ConfigureNetworkRequest>)
        -> Result<Response<ConfigureNetworkResponse>, Status> {
        Err(Status::unimplemented("configure_network: Step 3")) // RED
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn configure_network_returns_ok() {
        let svc = NodeService::default();
        let resp = svc
            .configure_network(Request::new(ConfigureNetworkRequest {
                vni: 100,
                gateway: "169.254.0.1".into(),
                mtu: 1450,
                dns: vec![],
            }))
            .await
            .unwrap();
        let _ = resp.into_inner();
    }
}
```
Add `mod node;` near the other module declarations in `xdp-dp/src/main.rs`.

- [ ] **Step 2: Run the test to verify it fails.**

Run: `cargo test -p xdp-dp node::tests::configure_network_returns_ok`
Expected: FAIL — `unwrap()` panics on the `unimplemented` status.

- [ ] **Step 3: Make it green** — change `configure_network` to return `Ok(Response::new(ConfigureNetworkResponse {}))`.

- [ ] **Step 4: Run the test to verify it passes.**

Run: `cargo test -p xdp-dp node::tests::configure_network_returns_ok`
Expected: PASS.

- [ ] **Step 5: Register the service on the gRPC server.** In `xdp-dp/src/main.rs` at `~355-358`:
```rust
            tonic::transport::Server::builder()
                .add_service(health_service)
                .add_service(server)
                .add_service(node::pb::dataplane_node_server::DataplaneNodeServer::new(
                    node::NodeService::default(),
                ))
                .serve(addr.parse()?)
```

- [ ] **Step 6: Build to confirm the server wires up.**

Run: `cargo build -p xdp-dp`
Expected: PASS.

- [ ] **Step 7: Commit.**
```bash
git add -A && git commit -m "feat(node): DataplaneNode gRPC service skeleton on xdp-dp"
```

---

### Task 6: Minimal per-network IPAM (Rust, unit-tested)

**Files:**
- Create: `xdp-dp/src/ipam.rs`
- Modify: `xdp-dp/src/main.rs` (`mod ipam;`)

- [ ] **Step 1: Write failing unit tests.**

Create `xdp-dp/src/ipam.rs` with tests first:
```rust
//! Minimal per-network IPv4 allocator for sub-project ① (no CRD/state store yet).
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

pub struct Ipam {
    base: u32,      // network address (host order)
    hosts: u32,     // number of usable host addresses
    gateway: u32,   // reserved
    used: BTreeSet<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allocates_sequential_skipping_gateway() {
        let mut ipam = Ipam::new("10.0.0.0/24".parse().unwrap(), "10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(ipam.allocate().unwrap(), "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(ipam.allocate().unwrap(), "10.0.0.3".parse::<Ipv4Addr>().unwrap());
    }
    #[test]
    fn release_makes_ip_reusable() {
        let mut ipam = Ipam::new("10.0.0.0/24".parse().unwrap(), "10.0.0.1".parse().unwrap()).unwrap();
        let a = ipam.allocate().unwrap();
        ipam.release(a);
        assert_eq!(ipam.allocate().unwrap(), a);
    }
    #[test]
    fn exhaustion_returns_none() {
        // /30 => 2 usable, minus gateway => 1 allocatable
        let mut ipam = Ipam::new("10.0.0.0/30".parse().unwrap(), "10.0.0.1".parse().unwrap()).unwrap();
        assert!(ipam.allocate().is_some());
        assert!(ipam.allocate().is_none());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail.**

Run: `cargo test -p xdp-dp ipam`
Expected: FAIL — `Ipam::{new,allocate,release}` not implemented.

- [ ] **Step 3: Implement `Ipam`** (`new` parses a `ipnet::Ipv4Net`-style prefix; `allocate` returns the lowest free host ≠ gateway; `release` clears it). Use the `ipnet` crate (add to `xdp-dp/Cargo.toml`) or hand-roll the prefix math. Return `Ipv4Addr`.

- [ ] **Step 4: Run tests to verify they pass.**

Run: `cargo test -p xdp-dp ipam`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit.**
```bash
git add -A && git commit -m "feat(ipam): minimal per-network IPv4 allocator"
```

---

### Task 7: `AttachInterface`/`DetachInterface` real implementation (netns-tested)

**Files:**
- Create: `xdp-dp/src/attach.rs`
- Modify: `xdp-dp/src/node.rs` (call into `attach`), `xdp-dp/src/main.rs` (`mod attach;`)
- Create: `test/attach-netns.sh` (mirrors existing `test/netns-e2e.sh` style)

- [ ] **Step 1: Write a failing netns integration test.**

Create `test/attach-netns.sh` that: creates a netns, starts `xdp-dp` with the DataplaneNode service, calls `AttachInterface{interface_id, netns_path=/var/run/netns/X, vni, requested_ips=[]}` via `grpcurl`, then asserts (a) a veth/tap appears in the netns, (b) the returned IP is pingable from the netns to the dataplane gateway, and (c) the eBPF interface map contains the endpoint. Print `PASS`/`FAIL`.

- [ ] **Step 2: Run it to verify it fails.**

Run: `sudo test/attach-netns.sh`
Expected: FAIL — `attach_interface` returns `unimplemented`.

- [ ] **Step 3: Implement `attach.rs`** — `attach_interface(req, &Ipam, &BpfMaps) -> AttachInterfaceResponse`:
  - allocate MAC (if empty) and IP (via `Ipam`, Task 6);
  - create the veth pair, move one end into `netns_path`, name it, set MAC/up;
  - program the eBPF interface/endpoint map for `{vni, ip, mac, ifindex}` reusing the existing datapath maps (`xdp-dp/src/maps.rs`);
  - attach the tc/XDP program to the host-side interface (reuse `xdp-dp/src/loader.rs` helpers);
  - return `{ifname, ips, mac, gateway}`.
  `detach_interface` reverses it (unprogram map, delete veth). Wire both into `node.rs`.

- [ ] **Step 4: Run the netns test to verify it passes.**

Run: `sudo test/attach-netns.sh`
Expected: `PASS` — interface created, IP reachable, endpoint programmed.

- [ ] **Step 5: Run the full Rust test suite (no regressions).**

Run: `cargo test -p xdp-dp`
Expected: PASS.

- [ ] **Step 6: Commit.**
```bash
git add -A && git commit -m "feat(attach): AttachInterface/DetachInterface with netns + eBPF programming"
```

---

## Phase A exit / next plan

At this point the monorepo has: the `api/` proto root, the clean `dataplane.v1` `DataplaneNode` service on `xdp-dp`, a netns-proven interface attach, minimal IPAM, and a working kind harness — all committed and testable. **The primary-UDN mechanism is now known (Task 1).** Re-enter `superpowers:writing-plans` to write **Phase B**: the Go CNI plugin (wiring the VM's primary interface per Task 1's decision), `hack/install-stack.sh` (pinned KubeVirt/Multus/CDI), and the two-VM kind e2e (boot + DHCP + ping + **no-pod-net** assertion) that is ①'s acceptance gate.
