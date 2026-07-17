# Route Distribution & Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the eBPF dataplane dynamically distributed overlay routes so endpoints on different nodes reach each other over the IP-in-IPv6 overlay, via a strict control/data-plane split (dumb Rust datapath + a Go control plane: per-node agent + a single global route reflector).

**Architecture:** `flowplane` (Rust/eBPF) gains a protocol-agnostic `AddRoute`/`WithdrawRoute` on `dataplane.v1` and stays a dumb, gRPC-driven datapath. A new Go module `netplane` provides a central **reflector** (in-memory per-VNI RIB behind a gRPC bidi `Session` stream) and a per-node **agent** (route-bus client that announces local endpoint routes, subscribes by VNI, and drives the local `flowplane` as remote routes arrive). Single global reflector; single-cluster is the degenerate co-located case.

**Tech Stack:** Rust (aya/tonic) for the datapath; Go 1.26 for the control plane (`google.golang.org/grpc`, `google.golang.org/protobuf`, controller-runtime/client-go for CRD reconcile); protoc for codegen; containerlab + kind for the e2e.

**Spec:** `docs/superpowers/specs/2026-07-02-route-distribution-control-plane-design.md`

---

## File Structure

**Datapath (Rust, existing `flowplane` crate):**
- `api/proto/dataplane/v1/dataplane.proto` — add `AddRoute`/`WithdrawRoute` RPCs + messages (Modify).
- `flowplane/src/node.rs` — implement the two RPC handlers (delegate to `AttachState.control.create_route`/`delete_route`); add a CIDR parse helper + its unit tests (Modify).
- `cni/gen/dataplanev1/*.pb.go` — regenerated Go stubs (Generated).
- `test/route-netns.sh` — netns smoke test: attach one endpoint, `AddRoute` a remote /32, assert the datapath programmed it (Create).

**Control plane (new Go module `github.com/trevex/flowplane/netplane` at `./netplane`):**
- `netplane/go.mod` — new module; requires `../api` and `../cni` via replace (Create).
- `api/proto/routebus/v1/routebus.proto` — the route-bus protocol (Create).
- `netplane/gen/routebusv1/*.pb.go` — generated stubs (Generated).
- `netplane/reflector/rib.go` — in-memory per-VNI RIB (pure logic, no networking) (Create).
- `netplane/reflector/server.go` — gRPC `RouteBus.Session` server wrapping the RIB (Create).
- `netplane/agent/bus.go` — route-bus client + `Dataplane` driver interface + adapter (Create).
- `netplane/agent/reconcile.go` — reconcile `NetworkInterface`s on this node → announcements/subscriptions (Create).
- `netplane/cmd/reflector/main.go` — reflector binary (Create).
- `netplane/cmd/agent/main.go` — agent binary (Create).
- `go.work` — add `./netplane` (Modify).
- `Makefile` — add `proto-routebus` target (Modify).

**e2e (existing `test/e2e` module):**
- `test/e2e/routebus_test.go` — two-node cross-node encap ping + liveness-withdraw on the containerlab fabric (Create).

**Design notes locked in here:**
- **Remote routes need no `UNDERLAY` entry.** `forward_decision_v4`/`_v6` (`flowplane-ebpf/src/egress.rs:107-128`, `:155-168`) take the local fast path only when `UNDERLAY[nexthop].tap_ifindex != 0`; a `ROUTES` hit whose nexthop has no local `UNDERLAY` entry falls through to `Encap` using `route.nexthop_ipv6` + the `LOCAL` uplink info. So `AddRoute` for a remote endpoint only calls `create_route` — it must NOT program `UNDERLAY` (that would make the datapath try local delivery). This refines spec §4.1 ("+ ensure UNDERLAY[nexthop]"), which is unnecessary and would be wrong for the encap path.
- **`AddRoute` is idempotent by delete-then-create.** `Control::create_route` bails with `ROUTE_EXISTS` on a duplicate (`control.rs:687-692`); a route bus re-announces and moves prefixes between nodes, so the handler deletes any existing `(vni,prefix)` first, then creates with the new nexthop.
- **v1 liveness = gRPC/stream keepalive + session-close fast-withdraw**, not a separate BFD/UDP daemon (spec §5 explicitly allows "aggressive stream keepalive as a v1 fallback"). When a session's stream ends, the reflector withdraws all routes that node originated. A dedicated BFD/UDP sidecar is a follow-up.
- **ECMP is carried but not yet consumed.** `Announce`/`RouteUpdate` carry a nexthop set; the v1 datapath `AddRoute` takes a single nexthop, so the agent programs `nexthops[0]`. This satisfies spec §7's "Announce carries a set" without widening the datapath yet.

---

### Task 1: `flowplane` `AddRoute`/`WithdrawRoute` on `dataplane.v1`

**Files:**
- Modify: `api/proto/dataplane/v1/dataplane.proto`
- Modify: `flowplane/src/node.rs`
- Test: `flowplane/src/node.rs` (unit test for the CIDR parser), `test/route-netns.sh` (netns smoke)

- [ ] **Step 1: Add the RPCs + messages to the proto**

In `api/proto/dataplane/v1/dataplane.proto`, add two RPCs to the `DataplaneNode` service (after `ConfigureNetwork`) and the four messages at the end of the file:

```proto
service DataplaneNode {
  rpc AttachInterface(AttachInterfaceRequest) returns (AttachInterfaceResponse);
  rpc DetachInterface(DetachInterfaceRequest) returns (DetachInterfaceResponse);
  rpc ConfigureNetwork(ConfigureNetworkRequest) returns (ConfigureNetworkResponse);
  // AddRoute programs a single overlay route (vni, prefix -> nexthop underlay).
  // Idempotent: re-adding an existing (vni, prefix) replaces its nexthop.
  rpc AddRoute(AddRouteRequest) returns (AddRouteResponse);
  // WithdrawRoute removes an overlay route. Removing an absent route is not an error.
  rpc WithdrawRoute(WithdrawRouteRequest) returns (WithdrawRouteResponse);
}
```

Append:

```proto
message AddRouteRequest {
  uint32 vni = 1;
  string prefix = 2;           // CIDR: "10.0.0.5/32" or "2001:db8::5/128"
  string nexthop_underlay = 3; // remote node underlay IPv6, e.g. "fd00:db8:0:2::a"
}
message AddRouteResponse {}

message WithdrawRouteRequest {
  uint32 vni = 1;
  string prefix = 2;           // CIDR, as in AddRouteRequest
}
message WithdrawRouteResponse {}
```

- [ ] **Step 2: Regenerate the Go stubs and verify Rust codegen picks up the change**

Run (inside the dev shell):

```bash
nix develop --command sh -c 'make proto-go && cargo build -p flowplane 2>&1 | tail -5'
```

Expected: `make proto-go` regenerates `cni/gen/dataplanev1/dataplane.pb.go` + `dataplane_grpc.pb.go` (now containing `AddRoute`/`WithdrawRoute`). `cargo build` FAILS to compile `node.rs` because `DataplaneNode` now requires `add_route`/`withdraw_route` methods — that is the expected red state proving the trait grew. (`flowplane/build.rs:44-49` compiles the proto via tonic on every build; `rerun-if-changed` covers the dir.)

- [ ] **Step 3: Add the CIDR parser + its unit test (write the failing test first)**

In `flowplane/src/node.rs`, add to the `tests` module:

```rust
#[test]
fn parse_prefix_v4_and_v6() {
    // (is_v6, 16-byte buffer with the address left-aligned for v4, prefix_len)
    let (v6, bytes, len) = super::parse_prefix("10.0.0.5/32").unwrap();
    assert!(!v6);
    assert_eq!(&bytes[..4], &[10, 0, 0, 5]);
    assert_eq!(len, 32);

    let (v6, bytes, len) = super::parse_prefix("2001:db8::5/128").unwrap();
    assert!(v6);
    assert_eq!(bytes, std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5).octets());
    assert_eq!(len, 128);
}

#[test]
fn parse_prefix_rejects_bad() {
    assert!(super::parse_prefix("10.0.0.5").is_err());     // no /len
    assert!(super::parse_prefix("10.0.0.5/33").is_err());  // v4 len > 32
    assert!(super::parse_prefix("nonsense/32").is_err());
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `nix develop --command cargo test -p flowplane parse_prefix 2>&1 | tail -8`
Expected: FAIL — `parse_prefix` is not defined (also the crate won't yet compile from Step 2; both errors point at the missing function + trait methods).

- [ ] **Step 5: Implement `parse_prefix` and the two RPC handlers**

In `flowplane/src/node.rs`, extend the `use pb::{…}` import to add the new messages:

```rust
use pb::{
    AddRouteRequest, AddRouteResponse, AttachInterfaceRequest, AttachInterfaceResponse,
    ConfigureNetworkRequest, ConfigureNetworkResponse, DetachInterfaceRequest,
    DetachInterfaceResponse, WithdrawRouteRequest, WithdrawRouteResponse,
};
```

Add the parser as a module-level `fn` (above `#[cfg(test)]`):

```rust
/// Parse a CIDR string into (is_v6, 16-byte address buffer, prefix_len). For IPv4 the four
/// octets are left-aligned in the buffer (bytes[0..4]); the datapath route helpers take the
/// v4/v6 slices they need. Rejects a missing "/len" and an out-of-range length.
fn parse_prefix(cidr: &str) -> anyhow::Result<(bool, [u8; 16], u32)> {
    use std::net::IpAddr;
    let (addr, len) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("prefix {cidr:?} missing /len"))?;
    let len: u32 = len.parse().map_err(|_| anyhow::anyhow!("bad prefix len in {cidr:?}"))?;
    let ip: IpAddr = addr.parse().map_err(|_| anyhow::anyhow!("bad address in {cidr:?}"))?;
    let mut buf = [0u8; 16];
    match ip {
        IpAddr::V4(a) => {
            if len > 32 {
                anyhow::bail!("v4 prefix len {len} > 32 in {cidr:?}");
            }
            buf[..4].copy_from_slice(&a.octets());
            Ok((false, buf, len))
        }
        IpAddr::V6(a) => {
            if len > 128 {
                anyhow::bail!("v6 prefix len {len} > 128 in {cidr:?}");
            }
            buf.copy_from_slice(&a.octets());
            Ok((true, buf, len))
        }
    }
}

/// Parse an IPv6 nexthop underlay address into 16 bytes.
fn parse_nexthop6(s: &str) -> anyhow::Result<[u8; 16]> {
    let a: std::net::Ipv6Addr = s
        .parse()
        .map_err(|_| anyhow::anyhow!("bad nexthop underlay ipv6 {s:?}"))?;
    Ok(a.octets())
}
```

Add the two handlers inside `impl DataplaneNode for NodeService` (after `configure_network`):

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
        let (is_v6, bytes, len) =
            parse_prefix(&r.prefix).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let nexthop = parse_nexthop6(&r.nexthop_underlay)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let c = &attach.control;
            // Idempotent: drop any existing (vni, prefix) so a re-announce or a moved prefix
            // replaces the nexthop instead of hitting ROUTE_EXISTS. Remote routes program only
            // ROUTES (no UNDERLAY) so the datapath encaps to `nexthop` (egress.rs falls through
            // to Encap when the nexthop has no local UNDERLAY tap).
            if is_v6 {
                let _ = c.delete_route6(vni, bytes, len)?;
                c.create_route6(vni, bytes, len, nexthop, vni, false)
            } else {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&bytes[..4]);
                let _ = c.delete_route(vni, v4, len)?;
                c.create_route(vni, v4, len, nexthop, vni, false)
            }
        })
        .await
        .map_err(|e| Status::internal(format!("add_route task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!(
            "ROUTE add vni={vni} prefix={} -> nexthop={}",
            r.prefix, r.nexthop_underlay
        );
        Ok(Response::new(AddRouteResponse {}))
    }

    async fn withdraw_route(
        &self,
        req: Request<WithdrawRouteRequest>,
    ) -> Result<Response<WithdrawRouteResponse>, Status> {
        let attach = self
            .attach
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?
            .clone();
        let r = req.into_inner();
        let (is_v6, bytes, len) =
            parse_prefix(&r.prefix).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let vni = r.vni;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let c = &attach.control;
            if is_v6 {
                let _ = c.delete_route6(vni, bytes, len)?;
            } else {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&bytes[..4]);
                let _ = c.delete_route(vni, v4, len)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| Status::internal(format!("withdraw_route task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        println!("ROUTE withdraw vni={vni} prefix={}", r.prefix);
        Ok(Response::new(WithdrawRouteResponse {}))
    }
```

- [ ] **Step 6: Run unit tests + clippy to verify green**

Run: `nix develop --command sh -c 'cargo test -p flowplane parse_prefix 2>&1 | tail -5 && cargo clippy -p flowplane --all-targets 2>&1 | tail -2'`
Expected: `parse_prefix` tests PASS; clippy clean. Also confirm the crate builds: `cargo build -p flowplane 2>&1 | tail -3` → success (the trait now has all methods).

- [ ] **Step 7: Write the netns smoke test**

Create `test/route-netns.sh` (model it on `test/two-endpoint-netns.sh`'s scaffolding — root-netns dummy for underlay inference, `flowplane serve`, `grpcurl` for the RPCs, an EXIT-trap cleanup). The assertion is the greppable `ROUTE add …` line the handler prints and a successful `AddRoute` RPC:

```bash
#!/usr/bin/env bash
# test/route-netns.sh — smoke test for DataplaneNode.AddRoute/WithdrawRoute.
# Attaches ONE endpoint, then programs a REMOTE /32 via AddRoute (nexthop = a bogus
# remote underlay). We can't ping a fake remote from here (that is the two-node e2e in
# test/e2e/routebus_test.go); this proves the RPC parses + programs the route (the
# datapath's own "ROUTE add …" confirmation line) and that WithdrawRoute round-trips.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
DUMMY="dp-dummy"; ULA_ADDR="fd00:db8:0:7::1/64"; ADDR="127.0.0.1:1337"; VNI=100
NS="rt-ep"; LOG="$(mktemp)"
cleanup() {
  [ -n "${SERVE_PID:-}" ] && sudo kill -9 "$SERVE_PID" 2>/dev/null
  sudo ip netns del "$NS" 2>/dev/null
  sudo ip link del "$DUMMY" 2>/dev/null
  rm -f "$LOG"
}
trap cleanup EXIT
sudo ip link add "$DUMMY" type dummy 2>/dev/null || true
sudo ip link set "$DUMMY" up
sudo ip -6 addr replace "$ULA_ADDR" dev "$DUMMY"
sudo ip netns add "$NS"
cargo build -p flowplane 2>&1 | tail -1
sudo ./target/debug/flowplane serve --grpc "$ADDR" >"$LOG" 2>&1 &
SERVE_PID=$!
for i in $(seq 1 30); do grpcurl -plaintext "$ADDR" list >/dev/null 2>&1 && break; sleep 0.3; done
grpcurl -plaintext -d "{\"interface_id\":\"rt0\",\"netns_path\":\"/var/run/netns/$NS\",\"vni\":$VNI,\"requested_ips\":[\"10.0.0.1\"]}" \
  "$ADDR" dataplane.v1.DataplaneNode/AttachInterface
echo "=== AddRoute a remote /32 ==="
grpcurl -plaintext -d "{\"vni\":$VNI,\"prefix\":\"10.0.0.2/32\",\"nexthop_underlay\":\"fd00:db8:0:2::a\"}" \
  "$ADDR" dataplane.v1.DataplaneNode/AddRoute
echo "=== WithdrawRoute it ==="
grpcurl -plaintext -d "{\"vni\":$VNI,\"prefix\":\"10.0.0.2/32\"}" \
  "$ADDR" dataplane.v1.DataplaneNode/WithdrawRoute
echo "=== assertions ==="
grep -q "ROUTE add vni=$VNI prefix=10.0.0.2/32 -> nexthop=fd00:db8:0:2::a" "$LOG" \
  && echo "PASS: AddRoute programmed" || { echo "FAIL: no AddRoute log"; cat "$LOG"; exit 1; }
grep -q "ROUTE withdraw vni=$VNI prefix=10.0.0.2/32" "$LOG" \
  && echo "PASS: WithdrawRoute programmed" || { echo "FAIL: no WithdrawRoute log"; exit 1; }
```

Make it executable: `chmod +x test/route-netns.sh`.

- [ ] **Step 8: Run the netns smoke test**

Run: `nix develop --command sh -c 'sudo env "PATH=$PATH" bash test/route-netns.sh' 2>&1 | tail -15`
Expected: two `PASS:` lines (AddRoute + WithdrawRoute programmed). If `--grpc` is not the serve flag name, check `flowplane serve --help` and adjust; the existing `test/two-endpoint-netns.sh` shows the exact serve invocation this repo uses.

- [ ] **Step 9: Commit**

```bash
git add api/proto/dataplane/v1/dataplane.proto flowplane/src/node.rs cni/gen/dataplanev1 test/route-netns.sh
git commit -m "feat(dataplane): AddRoute/WithdrawRoute on dataplane.v1

flowplane gains a protocol-agnostic route interface: AddRoute(vni, prefix,
nexthop_underlay) / WithdrawRoute(vni, prefix), delegating to the existing
Control::create_route/delete_route. Remote routes program only ROUTES (no
UNDERLAY) so the datapath encaps to the nexthop. Idempotent via delete-then-create.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `routebus.v1` proto + Go module + codegen

**Files:**
- Create: `api/proto/routebus/v1/routebus.proto`
- Create: `netplane/go.mod`
- Modify: `go.work`, `Makefile`
- Generated: `netplane/gen/routebusv1/*.pb.go`

- [ ] **Step 1: Write the proto**

Create `api/proto/routebus/v1/routebus.proto`:

```proto
syntax = "proto3";

package routebus.v1;

option go_package = "github.com/trevex/flowplane/netplane/gen/routebusv1;routebusv1";

// RouteBus is the control-plane route exchange between per-node agents and the
// central reflector. One long-lived bidi stream per agent.
service RouteBus {
  rpc Session(stream ClientMsg) returns (stream ServerMsg);
}

enum RouteOp {
  ROUTE_OP_UNSPECIFIED = 0;
  ROUTE_OP_ADD = 1;
  ROUTE_OP_WITHDRAW = 2;
}

// Agent -> reflector.
message ClientMsg {
  oneof msg {
    Hello hello = 1;             // MUST be the first message on the stream
    Subscribe subscribe = 2;
    Unsubscribe unsubscribe = 3;
    Announce announce = 4;
    Withdraw withdraw = 5;
    KeepAlive keep_alive = 6;
  }
}

// Reflector -> agent.
message ServerMsg {
  oneof msg {
    RouteUpdate route_update = 1;
    EndOfRIB end_of_rib = 2;     // full-table-for-a-vni delivered; safe to prune
    KeepAlive keep_alive = 3;
  }
}

message Hello {
  string node_id = 1;       // stable per-agent identity (== the reflector's origin key)
  string underlay_ipv6 = 2; // this node's underlay /128 (informational for v1)
}
message Subscribe { uint32 vni = 1; }
message Unsubscribe { uint32 vni = 1; }

message Announce {
  uint32 vni = 1;
  string prefix = 2;             // CIDR overlay prefix, e.g. "10.0.0.5/32"
  string nexthop_underlay = 3;   // primary nexthop = this node's underlay IPv6
  repeated string extra_nexthops = 4; // additional ECMP nexthops (carried, not yet used)
}
message Withdraw {
  uint32 vni = 1;
  string prefix = 2;
}

message RouteUpdate {
  uint32 vni = 1;
  string prefix = 2;
  repeated string nexthops = 3;  // nexthops[0] is the primary; rest are ECMP
  RouteOp op = 4;
}
message EndOfRIB { uint32 vni = 1; }
message KeepAlive {}
```

- [ ] **Step 2: Add the `proto-routebus` Makefile target**

In `Makefile`, after the `proto-go` target, add:

```makefile
.PHONY: proto-routebus
proto-routebus: ## Generate Go gRPC stubs for routebus.v1 into netplane/gen/routebusv1
	protoc -I api/proto/routebus/v1 \
		--go_out=netplane/gen --go_opt=module=github.com/trevex/flowplane/netplane/gen \
		--go-grpc_out=netplane/gen --go-grpc_opt=module=github.com/trevex/flowplane/netplane/gen \
		api/proto/routebus/v1/routebus.proto
```

- [ ] **Step 3: Create the module and generate stubs**

```bash
mkdir -p netplane/gen
cd netplane && nix develop "$OLDPWD" --command sh -c 'go mod init github.com/trevex/flowplane/netplane && go mod edit -go=1.26.0 -replace github.com/trevex/flowplane/api=../api -replace github.com/trevex/flowplane/cni=../cni' && cd ..
nix develop --command make proto-routebus
```

Then add `./netplane` to `go.work`:

```
go 1.26.0

use (
	./api
	./cni
	./netplane
	./test/e2e
)
```

- [ ] **Step 4: Verify the generated package compiles**

Run: `nix develop --command sh -c 'cd netplane && go build ./gen/... 2>&1 | tail -5'`
Expected: no output (builds clean). `ls netplane/gen/routebusv1/` shows `routebus.pb.go` + `routebus_grpc.pb.go`.

- [ ] **Step 5: Commit**

```bash
git add api/proto/routebus go.work Makefile netplane/go.mod netplane/go.sum netplane/gen
git commit -m "feat(netplane): routebus.v1 proto + netplane Go module

New Go module github.com/trevex/flowplane/netplane (reflector + agent) with the
route-bus protocol: a single bidi Session stream carrying Hello/Subscribe/
Announce/Withdraw (agent->reflector) and RouteUpdate/EndOfRIB (reflector->agent).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Reflector RIB (pure per-VNI route table)

**Files:**
- Create: `netplane/reflector/rib.go`
- Test: `netplane/reflector/rib_test.go`

- [ ] **Step 1: Write the failing test**

Create `netplane/reflector/rib_test.go`:

```go
package reflector

import (
	"testing"

	pb "github.com/trevex/flowplane/netplane/gen/routebusv1"
)

// fakeSink records everything the RIB sends it.
type fakeSink struct {
	id   string
	msgs []*pb.ServerMsg
}

func (f *fakeSink) ID() string          { return f.id }
func (f *fakeSink) Send(m *pb.ServerMsg) { f.msgs = append(f.msgs, m) }

func updates(f *fakeSink) []*pb.RouteUpdate {
	var out []*pb.RouteUpdate
	for _, m := range f.msgs {
		if ru := m.GetRouteUpdate(); ru != nil {
			out = append(out, ru)
		}
	}
	return out
}

func TestSubscribeGetsSnapshotThenEndOfRIB(t *testing.T) {
	r := NewRIB()
	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"})
	r.Announce("nodeA", 100, "10.0.0.2/32", []string{"fd00::a"})
	r.Announce("nodeA", 200, "10.0.0.9/32", []string{"fd00::a"}) // different vni, must not appear

	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)

	us := updates(sub)
	if len(us) != 2 {
		t.Fatalf("want 2 snapshot routes, got %d", len(us))
	}
	// EndOfRIB is the last message and names vni 100.
	last := sub.msgs[len(sub.msgs)-1].GetEndOfRib()
	if last == nil || last.Vni != 100 {
		t.Fatalf("want trailing EndOfRIB for vni 100, got %+v", sub.msgs[len(sub.msgs)-1])
	}
}

func TestAnnounceFansOutToSubscribersNotOrigin(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	origin := &fakeSink{id: "nodeA"}
	r.Subscribe(100, sub)
	r.Subscribe(100, origin)

	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"})

	if got := updates(sub); len(got) != 1 || got[0].Op != pb.RouteOp_ROUTE_OP_ADD || got[0].Prefix != "10.0.0.1/32" {
		t.Fatalf("subscriber should see one ADD, got %+v", got)
	}
	if got := updates(origin); len(got) != 0 {
		t.Fatalf("origin must NOT receive its own route, got %+v", got)
	}
}

func TestWithdrawFansOut(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)
	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"})
	r.Withdraw("nodeA", 100, "10.0.0.1/32")

	us := updates(sub)
	if len(us) != 2 || us[1].Op != pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("want ADD then WITHDRAW, got %+v", us)
	}
}

func TestDropOriginWithdrawsAllItsRoutes(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)
	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"})
	r.Announce("nodeA", 100, "10.0.0.2/32", []string{"fd00::a"})

	r.DropOrigin("nodeA")

	var withdraws int
	for _, ru := range updates(sub) {
		if ru.Op == pb.RouteOp_ROUTE_OP_WITHDRAW {
			withdraws++
		}
	}
	if withdraws != 2 {
		t.Fatalf("want 2 withdraws after DropOrigin, got %d", withdraws)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `nix develop --command sh -c 'cd netplane && go test ./reflector/ 2>&1 | tail -8'`
Expected: FAIL — `NewRIB`, `RIB`, `Sink` undefined.

- [ ] **Step 3: Implement the RIB**

Create `netplane/reflector/rib.go`:

```go
// Package reflector is the central route reflector: an in-memory per-VNI RIB
// (rib.go) exposed over the routebus.v1 gRPC Session stream (server.go).
package reflector

import (
	"sort"
	"sync"

	pb "github.com/trevex/flowplane/netplane/gen/routebusv1"
)

// Sink is a subscriber's outbound path. Send MUST NOT block — implementations
// enqueue to a buffered channel and drop on overflow (recovered by a resync).
type Sink interface {
	ID() string
	Send(*pb.ServerMsg)
}

type routeKey struct {
	vni    uint32
	prefix string
}

type routeEntry struct {
	nexthops []string
	origin   string
}

// RIB is the reflector's global route table. Safe for concurrent use.
type RIB struct {
	mu          sync.Mutex
	routes      map[routeKey]routeEntry
	byOrigin    map[string]map[routeKey]struct{}
	subscribers map[uint32]map[string]Sink
}

func NewRIB() *RIB {
	return &RIB{
		routes:      map[routeKey]routeEntry{},
		byOrigin:    map[string]map[routeKey]struct{}{},
		subscribers: map[uint32]map[string]Sink{},
	}
}

// Subscribe registers s for vni, streams the current table for that vni in a
// deterministic order, then EndOfRIB (a graceful-restart / prune marker).
func (r *RIB) Subscribe(vni uint32, s Sink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	subs := r.subscribers[vni]
	if subs == nil {
		subs = map[string]Sink{}
		r.subscribers[vni] = subs
	}
	subs[s.ID()] = s

	var keys []routeKey
	for k := range r.routes {
		if k.vni == vni {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].prefix < keys[j].prefix })
	for _, k := range keys {
		e := r.routes[k]
		s.Send(routeUpdate(k, e.nexthops, pb.RouteOp_ROUTE_OP_ADD))
	}
	s.Send(&pb.ServerMsg{Msg: &pb.ServerMsg_EndOfRib{EndOfRib: &pb.EndOfRIB{Vni: vni}}})
}

func (r *RIB) Unsubscribe(vni uint32, sinkID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if subs := r.subscribers[vni]; subs != nil {
		delete(subs, sinkID)
		if len(subs) == 0 {
			delete(r.subscribers, vni)
		}
	}
}

// Announce inserts/replaces a route and fans out an ADD to subscribers of vni
// (except the origin, which already has it).
func (r *RIB) Announce(origin string, vni uint32, prefix string, nexthops []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := routeKey{vni, prefix}
	r.routes[k] = routeEntry{nexthops: nexthops, origin: origin}
	if r.byOrigin[origin] == nil {
		r.byOrigin[origin] = map[routeKey]struct{}{}
	}
	r.byOrigin[origin][k] = struct{}{}
	r.fanout(k, nexthops, pb.RouteOp_ROUTE_OP_ADD, origin)
}

// Withdraw removes a route and fans out a WITHDRAW.
func (r *RIB) Withdraw(origin string, vni uint32, prefix string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := routeKey{vni, prefix}
	if _, ok := r.routes[k]; !ok {
		return
	}
	delete(r.routes, k)
	if m := r.byOrigin[origin]; m != nil {
		delete(m, k)
	}
	r.fanout(k, nil, pb.RouteOp_ROUTE_OP_WITHDRAW, "")
}

// DropOrigin withdraws every route a node originated and clears its
// subscriptions (called when the node's session ends / liveness is lost).
func (r *RIB) DropOrigin(origin string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	owned := r.byOrigin[origin]
	delete(r.byOrigin, origin)
	for k := range owned {
		if _, ok := r.routes[k]; ok {
			delete(r.routes, k)
			r.fanout(k, nil, pb.RouteOp_ROUTE_OP_WITHDRAW, "")
		}
	}
	for vni, subs := range r.subscribers {
		delete(subs, origin)
		if len(subs) == 0 {
			delete(r.subscribers, vni)
		}
	}
}

// fanout sends an update to all subscribers of k.vni except origin. Caller holds r.mu.
// Sink.Send is non-blocking, so holding the lock here is safe.
func (r *RIB) fanout(k routeKey, nexthops []string, op pb.RouteOp, origin string) {
	for id, s := range r.subscribers[k.vni] {
		if id == origin {
			continue
		}
		s.Send(routeUpdate(k, nexthops, op))
	}
}

func routeUpdate(k routeKey, nexthops []string, op pb.RouteOp) *pb.ServerMsg {
	return &pb.ServerMsg{Msg: &pb.ServerMsg_RouteUpdate{RouteUpdate: &pb.RouteUpdate{
		Vni:      k.vni,
		Prefix:   k.prefix,
		Nexthops: nexthops,
		Op:       op,
	}}}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `nix develop --command sh -c 'cd netplane && go test ./reflector/ 2>&1 | tail -5'`
Expected: PASS (all four tests).

- [ ] **Step 5: Commit**

```bash
git add netplane/reflector/rib.go netplane/reflector/rib_test.go
git commit -m "feat(reflector): in-memory per-VNI RIB with subscribe/announce/withdraw

Pure route-table logic: Subscribe streams a vni snapshot + EndOfRIB; Announce/
Withdraw fan out to subscribers (never echoing to the origin); DropOrigin
fast-withdraws everything a departed node announced.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Reflector gRPC server + binary

**Files:**
- Create: `netplane/reflector/server.go`, `netplane/cmd/reflector/main.go`
- Test: `netplane/reflector/server_test.go`

- [ ] **Step 1: Write the failing test (bufconn end-to-end)**

Create `netplane/reflector/server_test.go`:

```go
package reflector

import (
	"context"
	"net"
	"testing"
	"time"

	pb "github.com/trevex/flowplane/netplane/gen/routebusv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func startServer(t *testing.T) pb.RouteBusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterRouteBusServer(srv, NewServer(NewRIB()))
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewRouteBusClient(conn)
}

func hello(t *testing.T, s pb.RouteBus_SessionClient, id string) {
	t.Helper()
	if err := s.Send(&pb.ClientMsg{Msg: &pb.ClientMsg_Hello{Hello: &pb.Hello{NodeId: id}}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
}

func TestSessionAnnounceReachesSubscriber(t *testing.T) {
	cl := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Subscriber first, so it is registered before A announces.
	subStream, err := cl.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, subStream, "nodeB")
	if err := subStream.Send(&pb.ClientMsg{Msg: &pb.ClientMsg_Subscribe{Subscribe: &pb.Subscribe{Vni: 100}}}); err != nil {
		t.Fatal(err)
	}
	// Drain the (empty) snapshot's EndOfRIB.
	if m, err := subStream.Recv(); err != nil || m.GetEndOfRib() == nil {
		t.Fatalf("want EndOfRIB, got %+v err=%v", m, err)
	}

	// Announcer.
	annStream, err := cl.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, annStream, "nodeA")
	if err := annStream.Send(&pb.ClientMsg{Msg: &pb.ClientMsg_Announce{Announce: &pb.Announce{
		Vni: 100, Prefix: "10.0.0.1/32", NexthopUnderlay: "fd00::a",
	}}}); err != nil {
		t.Fatal(err)
	}

	m, err := subStream.Recv()
	if err != nil {
		t.Fatalf("recv update: %v", err)
	}
	ru := m.GetRouteUpdate()
	if ru == nil || ru.Op != pb.RouteOp_ROUTE_OP_ADD || ru.Prefix != "10.0.0.1/32" || ru.Nexthops[0] != "fd00::a" {
		t.Fatalf("bad RouteUpdate: %+v", m)
	}

	// Closing the announcer's stream fast-withdraws its route.
	annStream.CloseSend()
	m, err = subStream.Recv()
	if err != nil {
		t.Fatalf("recv withdraw: %v", err)
	}
	if ru := m.GetRouteUpdate(); ru == nil || ru.Op != pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("want WITHDRAW after peer close, got %+v", m)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command sh -c 'cd netplane && go test ./reflector/ -run TestSession 2>&1 | tail -8'`
Expected: FAIL — `NewServer` undefined.

- [ ] **Step 3: Implement the server**

Create `netplane/reflector/server.go`:

```go
package reflector

import (
	"io"
	"sync"

	pb "github.com/trevex/flowplane/netplane/gen/routebusv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server adapts the RIB to the RouteBus.Session bidi stream.
type Server struct {
	pb.UnimplementedRouteBusServer
	rib *RIB
}

func NewServer(rib *RIB) *Server { return &Server{rib: rib} }

// chanSink is a subscriber's non-blocking outbound queue. A dedicated goroutine
// drains it onto the stream (gRPC allows only one concurrent Send per stream).
type chanSink struct {
	id string
	ch chan *pb.ServerMsg
}

func (c *chanSink) ID() string { return c.id }
func (c *chanSink) Send(m *pb.ServerMsg) {
	select {
	case c.ch <- m:
	default:
		// Slow consumer: drop. Recovered on the next full-table resync (reconnect).
	}
}

func (s *Server) Session(stream pb.RouteBus_SessionServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	h := first.GetHello()
	if h == nil || h.NodeId == "" {
		return status.Error(codes.InvalidArgument, "first message must be Hello with node_id")
	}
	sink := &chanSink{id: h.NodeId, ch: make(chan *pb.ServerMsg, 1024)}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for m := range sink.ch {
			if err := stream.Send(m); err != nil {
				return
			}
		}
	}()
	defer func() {
		s.rib.DropOrigin(sink.id) // fast-withdraw this node's routes on disconnect
		close(sink.ch)
		wg.Wait()
	}()

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch m := msg.Msg.(type) {
		case *pb.ClientMsg_Subscribe:
			s.rib.Subscribe(m.Subscribe.Vni, sink)
		case *pb.ClientMsg_Unsubscribe:
			s.rib.Unsubscribe(m.Unsubscribe.Vni, sink.id)
		case *pb.ClientMsg_Announce:
			a := m.Announce
			nh := append([]string{a.NexthopUnderlay}, a.ExtraNexthops...)
			s.rib.Announce(sink.id, a.Vni, a.Prefix, nh)
		case *pb.ClientMsg_Withdraw:
			s.rib.Withdraw(sink.id, m.Withdraw.Vni, m.Withdraw.Prefix)
		case *pb.ClientMsg_KeepAlive, *pb.ClientMsg_Hello:
			// keepalive: transport-level for v1; duplicate hello ignored.
		}
	}
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command sh -c 'cd netplane && go test ./reflector/ 2>&1 | tail -5'`
Expected: PASS (RIB tests + the session test, including the peer-close fast-withdraw).

- [ ] **Step 5: Write the reflector binary**

Create `netplane/cmd/reflector/main.go`:

```go
// Command reflector runs the central route reflector: it accepts routebus.v1
// Session streams from per-node agents and reflects per-VNI routes between them.
package main

import (
	"flag"
	"log"
	"net"

	"github.com/trevex/flowplane/netplane/gen/routebusv1"
	"github.com/trevex/flowplane/netplane/reflector"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"time"
)

func main() {
	addr := flag.String("listen", ":1338", "gRPC listen address")
	flag.Parse()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	// Aggressive keepalive so a dead agent's session is torn down (and its routes
	// fast-withdrawn) within a bounded budget — the v1 stand-in for BFD.
	srv := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 2 * time.Second, Timeout: 3 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: time.Second, PermitWithoutStream: true}),
	)
	routebusv1.RegisterRouteBusServer(srv, reflector.NewServer(reflector.NewRIB()))
	log.Printf("reflector listening on %s", *addr)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
```

- [ ] **Step 6: Build the binary**

Run: `nix develop --command sh -c 'cd netplane && go build ./... 2>&1 | tail -5'`
Expected: builds clean.

- [ ] **Step 7: Commit**

```bash
git add netplane/reflector/server.go netplane/reflector/server_test.go netplane/cmd/reflector
git commit -m "feat(reflector): RouteBus.Session gRPC server + reflector binary

Wraps the RIB in the bidi Session stream (Hello-first, per-session non-blocking
outbound queue) and fast-withdraws a node's routes when its stream ends. The
reflector binary uses aggressive gRPC keepalive as the v1 liveness stand-in.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Agent route-bus client + flowplane driver + binary

**Files:**
- Create: `netplane/agent/bus.go`, `netplane/cmd/agent/main.go`
- Test: `netplane/agent/bus_test.go`

- [ ] **Step 1: Write the failing test**

Create `netplane/agent/bus_test.go`:

```go
package agent

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	rbv1 "github.com/trevex/flowplane/netplane/gen/routebusv1"
	"github.com/trevex/flowplane/netplane/reflector"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// fakeDP records the routes the agent programs on the local dataplane.
type fakeDP struct {
	mu       sync.Mutex
	added    map[string]string // "vni prefix" -> nexthop
	withdrew map[string]bool
}

func newFakeDP() *fakeDP { return &fakeDP{added: map[string]string{}, withdrew: map[string]bool{}} }

func (f *fakeDP) AddRoute(_ context.Context, vni uint32, prefix, nexthop string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added[key(vni, prefix)] = nexthop
	return nil
}
func (f *fakeDP) WithdrawRoute(_ context.Context, vni uint32, prefix string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdrew[key(vni, prefix)] = true
	return nil
}
func (f *fakeDP) get(vni uint32, prefix string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.added[key(vni, prefix)]
	return v, ok
}
func key(vni uint32, prefix string) string { return prefix } // vni fixed at 100 in the test

func dialReflector(t *testing.T) rbv1.RouteBusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	rbv1.RegisterRouteBusServer(srv, reflector.NewServer(reflector.NewRIB()))
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return rbv1.NewRouteBusClient(conn)
}

func TestAgentLearnsRemoteRouteAndProgramsDataplane(t *testing.T) {
	cl := dialReflector(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Agent A announces one local route (no dataplane needed for the announcer here).
	dpA := newFakeDP()
	busA := NewBus("nodeA", "fd00::a", dpA)
	go busA.Run(ctx, cl, nil, []Route{{Vni: 100, Prefix: "10.0.0.1/32", Nexthop: "fd00::a"}})

	// Agent B subscribes to vni 100 and must program A's route on its dataplane.
	dpB := newFakeDP()
	busB := NewBus("nodeB", "fd00::b", dpB)
	go busB.Run(ctx, cl, []uint32{100}, nil)

	// Poll for the learned route.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if nh, ok := dpB.get(100, "10.0.0.1/32"); ok {
			if nh != "fd00::a" {
				t.Fatalf("nexthop = %q, want fd00::a", nh)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("agent B never programmed A's route")
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command sh -c 'cd netplane && go test ./agent/ 2>&1 | tail -8'`
Expected: FAIL — `NewBus`, `Route`, `Bus` undefined.

- [ ] **Step 3: Implement the bus client**

Create `netplane/agent/bus.go`:

```go
// Package agent is the per-node control plane: a route-bus client that announces
// local endpoint routes, subscribes by VNI, and drives the local flowplane datapath
// as remote routes arrive.
package agent

import (
	"context"
	"io"
	"log"

	dpv1 "github.com/trevex/flowplane/cni/gen/dataplanev1"
	rbv1 "github.com/trevex/flowplane/netplane/gen/routebusv1"
	"google.golang.org/grpc"
)

// Dataplane is the subset of flowplane the agent drives. dpAdapter wraps the real
// DataplaneNode gRPC client; tests supply a fake.
type Dataplane interface {
	AddRoute(ctx context.Context, vni uint32, prefix, nexthop string) error
	WithdrawRoute(ctx context.Context, vni uint32, prefix string) error
}

// Route is a local overlay route this node announces.
type Route struct {
	Vni     uint32
	Prefix  string // CIDR, e.g. "10.0.0.5/32"
	Nexthop string // this node's underlay IPv6
}

// Bus is one agent's route-bus session driver.
type Bus struct {
	nodeID   string
	underlay string
	dp       Dataplane
}

func NewBus(nodeID, underlay string, dp Dataplane) *Bus {
	return &Bus{nodeID: nodeID, underlay: underlay, dp: dp}
}

// Run opens a Session, sends Hello + the initial subscriptions + announcements,
// then pumps RouteUpdates into the dataplane until ctx is done or the stream errors.
func (b *Bus) Run(ctx context.Context, cc rbv1.RouteBusClient, subVNIs []uint32, announce []Route) error {
	stream, err := cc.Session(ctx)
	if err != nil {
		return err
	}
	if err := stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_Hello{
		Hello: &rbv1.Hello{NodeId: b.nodeID, UnderlayIpv6: b.underlay},
	}}); err != nil {
		return err
	}
	for _, v := range subVNIs {
		if err := stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_Subscribe{
			Subscribe: &rbv1.Subscribe{Vni: v},
		}}); err != nil {
			return err
		}
	}
	for _, r := range announce {
		if err := b.announce(stream, r); err != nil {
			return err
		}
	}
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if ru := msg.GetRouteUpdate(); ru != nil {
			b.apply(ctx, ru)
		}
		// EndOfRIB / KeepAlive: v1 no-op (prune-on-EoR is a follow-up).
	}
}

func (b *Bus) announce(stream rbv1.RouteBus_SessionClient, r Route) error {
	return stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_Announce{Announce: &rbv1.Announce{
		Vni: r.Vni, Prefix: r.Prefix, NexthopUnderlay: r.Nexthop,
	}}})
}

func (b *Bus) apply(ctx context.Context, ru *rbv1.RouteUpdate) {
	nh := ""
	if len(ru.Nexthops) > 0 {
		nh = ru.Nexthops[0] // ECMP set carried; v1 programs the primary
	}
	switch ru.Op {
	case rbv1.RouteOp_ROUTE_OP_ADD:
		if err := b.dp.AddRoute(ctx, ru.Vni, ru.Prefix, nh); err != nil {
			log.Printf("AddRoute vni=%d %s -> %s: %v", ru.Vni, ru.Prefix, nh, err)
		}
	case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
		if err := b.dp.WithdrawRoute(ctx, ru.Vni, ru.Prefix); err != nil {
			log.Printf("WithdrawRoute vni=%d %s: %v", ru.Vni, ru.Prefix, err)
		}
	}
}

// dpAdapter wraps the real DataplaneNode gRPC client as a Dataplane.
type dpAdapter struct{ c dpv1.DataplaneNodeClient }

// NewDataplaneAdapter adapts a DataplaneNode client to the agent's Dataplane interface.
func NewDataplaneAdapter(c dpv1.DataplaneNodeClient) Dataplane { return dpAdapter{c: c} }

func (d dpAdapter) AddRoute(ctx context.Context, vni uint32, prefix, nexthop string) error {
	_, err := d.c.AddRoute(ctx, &dpv1.AddRouteRequest{Vni: vni, Prefix: prefix, NexthopUnderlay: nexthop})
	return err
}
func (d dpAdapter) WithdrawRoute(ctx context.Context, vni uint32, prefix string) error {
	_, err := d.c.WithdrawRoute(ctx, &dpv1.WithdrawRouteRequest{Vni: vni, Prefix: prefix})
	return err
}

var _ = grpc.WaitForReady // keep grpc import if unused after edits; remove if the linter objects
```

Note: delete the trailing `var _ = grpc.WaitForReady` line and the `grpc` import if `go vet`/build reports them unused — they are only there to avoid an unused-import churn during editing.

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command sh -c 'cd netplane && go test ./agent/ 2>&1 | tail -5'`
Expected: PASS. If build complains about an unused `grpc` import, remove that import and the `var _` line, then re-run.

- [ ] **Step 5: Write the agent binary**

Create `netplane/cmd/agent/main.go`:

```go
// Command agent runs the per-node control plane: it dials the local flowplane
// DataplaneNode and the central reflector, then reconciles NetworkInterfaces on
// this node into route announcements while programming learned remote routes.
package main

import (
	"context"
	"flag"
	"log"
	"time"

	dpv1 "github.com/trevex/flowplane/cni/gen/dataplanev1"
	"github.com/trevex/flowplane/netplane/agent"
	rbv1 "github.com/trevex/flowplane/netplane/gen/routebusv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

func main() {
	nodeID := flag.String("node-id", "", "stable node identity (required)")
	underlay := flag.String("underlay", "", "this node's underlay IPv6 (required)")
	reflectorAddr := flag.String("reflector", "127.0.0.1:1338", "reflector gRPC address")
	dataplaneAddr := flag.String("dataplane", "127.0.0.1:1337", "local flowplane DataplaneNode address")
	kubeconfig := flag.String("kubeconfig", "", "kubeconfig for the central API (empty = in-cluster)")
	flag.Parse()
	if *nodeID == "" || *underlay == "" {
		log.Fatal("--node-id and --underlay are required")
	}

	dpConn, err := grpc.NewClient(*dataplaneAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial dataplane: %v", err)
	}
	defer dpConn.Close()
	dp := agent.NewDataplaneAdapter(dpv1.NewDataplaneNodeClient(dpConn))

	rbConn, err := grpc.NewClient(*reflectorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 2 * time.Second, Timeout: 3 * time.Second, PermitWithoutStream: true}))
	if err != nil {
		log.Fatalf("dial reflector: %v", err)
	}
	defer rbConn.Close()
	rb := rbv1.NewRouteBusClient(rbConn)

	ctx := context.Background()
	r, err := agent.NewReconciler(*kubeconfig, *nodeID)
	if err != nil {
		log.Fatalf("reconciler: %v", err)
	}
	// Reconcile the desired announcements/subscriptions for this node, then run the
	// bus session. On disconnect, retry with backoff (the reflector fast-withdrew us).
	for {
		subs, ann, err := r.Desired(ctx)
		if err != nil {
			log.Printf("reconcile: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		bus := agent.NewBus(*nodeID, *underlay, dp)
		if err := bus.Run(ctx, rb, subs, ann); err != nil {
			log.Printf("bus session ended: %v; reconnecting", err)
		}
		time.Sleep(time.Second)
	}
}
```

(The `agent.NewReconciler`/`Desired` types are implemented in Task 6; this binary won't build until then. That is intentional — commit the binary with Task 6.)

- [ ] **Step 6: Verify the bus package builds and tests pass (binary deferred to Task 6)**

Run: `nix develop --command sh -c 'cd netplane && go test ./agent/ ./reflector/ 2>&1 | tail -5'`
Expected: PASS. (Do not `go build ./...` yet — `cmd/agent` references Task 6's reconciler.)

- [ ] **Step 7: Commit**

```bash
git add netplane/agent/bus.go netplane/agent/bus_test.go
git commit -m "feat(agent): route-bus client that drives the local flowplane

The agent opens a routebus Session (Hello + subscribe-by-VNI + announce local
routes) and programs learned remote RouteUpdates onto the local DataplaneNode
via AddRoute/WithdrawRoute. ECMP nexthop sets are carried; v1 programs the primary.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Agent CRD reconciler (NetworkInterface → announcements)

**Files:**
- Create: `netplane/agent/reconcile.go`
- Modify: `netplane/cmd/agent/main.go` (already references it; now it compiles)
- Test: `netplane/agent/reconcile_test.go`

**Context:** The reconciler reads `NetworkInterface`s scheduled to this node (`spec.nodeName == nodeID`), resolves each one's VPC VNI (`NetworkInterface.status.vni`, falling back to the referenced `VPC.status.vni`), and produces (a) the set of VNIs to subscribe to and (b) the set of local routes to announce — one `/32` (or `/128`) per overlay IP, nexthop = this node's underlay. It uses a controller-runtime client so tests can supply a fake client. This is the v1 "agent reconciles the CRDs" (spec D5); full watch/requeue is a follow-up — v1 snapshots on each (re)connect, which pairs with the reflector's EndOfRIB resync.

- [ ] **Step 1: Write the failing test (fake client)**

Create `netplane/agent/reconcile_test.go`:

```go
package agent

import (
	"context"
	"sort"
	"testing"

	netv1 "github.com/trevex/flowplane/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ptr[T any](v T) *T { return &v }

func TestDesiredAnnouncesLocalInterfaces(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpc := &netv1.VPC{}
	vpc.Name = "blue"
	vpc.Namespace = "default"
	vpc.Status.VNI = 100

	local := &netv1.NetworkInterface{}
	local.Name = "nic-a"
	local.Namespace = "default"
	local.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	local.Spec.NodeName = ptr("nodeA")
	local.Spec.IPs = []string{"10.0.0.1"}
	local.Status.VNI = 100

	remote := &netv1.NetworkInterface{}
	remote.Name = "nic-b"
	remote.Namespace = "default"
	remote.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	remote.Spec.NodeName = ptr("nodeB") // NOT ours
	remote.Spec.IPs = []string{"10.0.0.2"}
	remote.Status.VNI = 100

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, local, remote).Build()
	r := &Reconciler{client: c, nodeID: "nodeA", underlay: "fd00::a"}

	subs, ann, err := r.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || subs[0] != 100 {
		t.Fatalf("subs = %v, want [100]", subs)
	}
	if len(ann) != 1 {
		t.Fatalf("want 1 local announcement, got %d: %+v", len(ann), ann)
	}
	got := ann[0]
	if got.Vni != 100 || got.Prefix != "10.0.0.1/32" || got.Nexthop != "fd00::a" {
		t.Fatalf("announcement = %+v", got)
	}
	_ = sort.Ints // keep import if needed
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command sh -c 'cd netplane && go test ./agent/ -run TestDesired 2>&1 | tail -8'`
Expected: FAIL — `Reconciler` undefined. (The test also forces `k8s.io/apimachinery`, controller-runtime fake, and the `api` module into `netplane/go.mod`.)

- [ ] **Step 3: Implement the reconciler**

Create `netplane/agent/reconcile.go`:

```go
package agent

import (
	"context"
	"fmt"
	"net"
	"sort"

	netv1 "github.com/trevex/flowplane/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Reconciler reads NetworkInterfaces scheduled to this node and derives the
// VNIs to subscribe to plus the local routes to announce.
type Reconciler struct {
	client   client.Client
	nodeID   string
	underlay string
}

// NewReconciler builds a Reconciler from a kubeconfig path (empty = in-cluster).
func NewReconciler(kubeconfig, nodeID string) (*Reconciler, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig %q: %w", kubeconfig, err)
	}
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register scheme: %w", err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}
	// underlay is threaded in by main via SetUnderlay to avoid a wider signature.
	return &Reconciler{client: c, nodeID: nodeID}, nil
}

// SetUnderlay records this node's underlay IPv6 (used as the announced nexthop).
func (r *Reconciler) SetUnderlay(underlay string) { r.underlay = underlay }

// Desired returns the VNIs to subscribe to and the local routes to announce for
// this node, snapshotting the current NetworkInterface set.
func (r *Reconciler) Desired(ctx context.Context) (subs []uint32, announce []Route, err error) {
	var nics netv1.NetworkInterfaceList
	if err := r.client.List(ctx, &nics); err != nil {
		return nil, nil, fmt.Errorf("list networkinterfaces: %w", err)
	}
	vniSet := map[uint32]struct{}{}
	for i := range nics.Items {
		nic := &nics.Items[i]
		vni, err := r.vniFor(ctx, nic)
		if err != nil {
			return nil, nil, err
		}
		if vni == 0 {
			continue // VPC not yet allocated a VNI; skip until it is
		}
		vniSet[vni] = struct{}{} // subscribe to every VNI we host, local or not
		if nic.Spec.NodeName == nil || *nic.Spec.NodeName != r.nodeID {
			continue // only announce interfaces scheduled to THIS node
		}
		for _, ip := range nic.Spec.IPs {
			prefix, err := hostPrefix(ip)
			if err != nil {
				return nil, nil, fmt.Errorf("nic %s/%s ip %q: %w", nic.Namespace, nic.Name, ip, err)
			}
			announce = append(announce, Route{Vni: vni, Prefix: prefix, Nexthop: r.underlay})
		}
	}
	for v := range vniSet {
		subs = append(subs, v)
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i] < subs[j] })
	return subs, announce, nil
}

// vniFor resolves an interface's VNI: prefer status.vni, else the referenced VPC's status.vni.
func (r *Reconciler) vniFor(ctx context.Context, nic *netv1.NetworkInterface) (uint32, error) {
	if nic.Status.VNI != 0 {
		return uint32(nic.Status.VNI), nil
	}
	var vpc netv1.VPC
	key := types.NamespacedName{Namespace: nic.Namespace, Name: nic.Spec.VPCRef.Name}
	if err := r.client.Get(ctx, key, &vpc); err != nil {
		return 0, fmt.Errorf("get vpc %s: %w", key, err)
	}
	return uint32(vpc.Status.VNI), nil
}

// hostPrefix turns an overlay IP into its host CIDR ("/32" for v4, "/128" for v6).
func hostPrefix(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP")
	}
	if parsed.To4() != nil {
		return ip + "/32", nil
	}
	return ip + "/128", nil
}
```

Update `netplane/cmd/agent/main.go` to set the underlay on the reconciler (the reconciler needs it for the announced nexthop). Change the block after `NewReconciler`:

```go
	r, err := agent.NewReconciler(*kubeconfig, *nodeID)
	if err != nil {
		log.Fatalf("reconciler: %v", err)
	}
	r.SetUnderlay(*underlay)
```

- [ ] **Step 4: Run the reconciler test + build the whole module**

Run: `nix develop --command sh -c 'cd netplane && go mod tidy && go test ./... 2>&1 | tail -8 && go build ./... 2>&1 | tail -3'`
Expected: reconciler + agent + reflector tests PASS; `go build ./...` (including `cmd/agent`) succeeds now that the reconciler exists.

- [ ] **Step 5: Commit**

```bash
git add netplane/agent/reconcile.go netplane/agent/reconcile_test.go netplane/cmd/agent netplane/go.mod netplane/go.sum
git commit -m "feat(agent): reconcile NetworkInterfaces into routebus announcements

The agent lists NetworkInterfaces, subscribes to every VNI it hosts, and
announces a /32 (or /128) per overlay IP for interfaces scheduled to this node
(nexthop = this node's underlay). Completes the agent binary (dataplane +
reflector dials + reconcile-then-run loop).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: mTLS on the route bus

**Files:**
- Create: `netplane/routebus/tls.go` (shared cert loading)
- Modify: `netplane/cmd/reflector/main.go`, `netplane/cmd/agent/main.go`
- Test: `netplane/routebus/tls_test.go`

**Context:** Spec §8 requires mTLS: the client cert identity == the node. v1 scope here is the transport (mutual cert verification) using files on disk; the reflector's per-VNI authorization (which VNIs a node may announce/subscribe) is a follow-up noted in the spec's open questions. The bus/RIB code is unchanged — only the `grpc.Server`/`grpc.NewClient` credentials change, gated behind flags so the insecure path (and all bufconn tests) still work.

- [ ] **Step 1: Write the failing test**

Create `netplane/routebus/tls_test.go`:

```go
package routebus

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServerTLSMissingFilesErrors(t *testing.T) {
	_, err := ServerTLS("/nope/ca.pem", "/nope/srv.pem", "/nope/srv-key.pem")
	if err == nil {
		t.Fatal("want error for missing cert files")
	}
}

func TestLoadClientTLSRequiresAllThree(t *testing.T) {
	dir := t.TempDir()
	// Empty (invalid) files still exercise the "all three required" plumbing.
	for _, f := range []string{"ca.pem", "cli.pem", "cli-key.pem"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ClientTLS(filepath.Join(dir, "ca.pem"), "", filepath.Join(dir, "cli-key.pem")); err == nil {
		t.Fatal("want error when cert path is empty")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command sh -c 'cd netplane && go test ./routebus/ 2>&1 | tail -6'`
Expected: FAIL — package/functions undefined.

- [ ] **Step 3: Implement the TLS helpers**

Create `netplane/routebus/tls.go`:

```go
// Package routebus holds route-bus transport helpers shared by the agent and
// reflector — currently mutual-TLS credential loading.
package routebus

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

func loadCAPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certs parsed from CA %q", caFile)
	}
	return pool, nil
}

// ServerTLS builds server credentials that REQUIRE and verify a client cert (mTLS).
func ServerTLS(caFile, certFile, keyFile string) (credentials.TransportCredentials, error) {
	if caFile == "" || certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("mTLS requires --tls-ca, --tls-cert and --tls-key")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	pool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}), nil
}

// ClientTLS builds client credentials that present a client cert and verify the server.
func ClientTLS(caFile, certFile, keyFile string) (credentials.TransportCredentials, error) {
	if caFile == "" || certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("mTLS requires --tls-ca, --tls-cert and --tls-key")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	pool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}), nil
}
```

- [ ] **Step 4: Wire the flags into both binaries**

In `netplane/cmd/reflector/main.go`, add flags and choose credentials:

```go
	tlsCA := flag.String("tls-ca", "", "CA bundle to verify agent client certs (enables mTLS)")
	tlsCert := flag.String("tls-cert", "", "reflector server cert")
	tlsKey := flag.String("tls-key", "", "reflector server key")
```

Replace the `srv := grpc.NewServer(...)` construction so it appends TLS creds when configured:

```go
	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 2 * time.Second, Timeout: 3 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: time.Second, PermitWithoutStream: true}),
	}
	if *tlsCA != "" || *tlsCert != "" || *tlsKey != "" {
		creds, err := routebus.ServerTLS(*tlsCA, *tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		opts = append(opts, grpc.Creds(creds))
		log.Printf("mTLS enabled")
	}
	srv := grpc.NewServer(opts...)
```

Add `"github.com/trevex/flowplane/netplane/routebus"` to the imports.

In `netplane/cmd/agent/main.go`, add the same three flags and select client transport credentials for the reflector dial:

```go
	tlsCA := flag.String("tls-ca", "", "CA bundle to verify the reflector (enables mTLS)")
	tlsCert := flag.String("tls-cert", "", "agent client cert (identity == node)")
	tlsKey := flag.String("tls-key", "", "agent client key")
```

Replace the reflector dial's transport credential:

```go
	var rbCreds = insecure.NewCredentials()
	if *tlsCA != "" || *tlsCert != "" || *tlsKey != "" {
		tc, err := routebus.ClientTLS(*tlsCA, *tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		rbCreds = tc
	}
	rbConn, err := grpc.NewClient(*reflectorAddr,
		grpc.WithTransportCredentials(rbCreds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 2 * time.Second, Timeout: 3 * time.Second, PermitWithoutStream: true}))
```

Add `"github.com/trevex/flowplane/netplane/routebus"` to the agent imports. (`credentials.TransportCredentials` is the common type of both `insecure.NewCredentials()` and the mTLS creds, so the `var rbCreds` assignment type-checks.)

- [ ] **Step 5: Run tests + build**

Run: `nix develop --command sh -c 'cd netplane && go test ./... 2>&1 | tail -6 && go build ./... 2>&1 | tail -3'`
Expected: all tests PASS (bufconn suites still use insecure), both binaries build.

- [ ] **Step 6: Commit**

```bash
git add netplane/routebus netplane/cmd/reflector/main.go netplane/cmd/agent/main.go netplane/go.mod netplane/go.sum
git commit -m "feat(netplane): optional mTLS on the route bus

Shared ServerTLS/ClientTLS helpers (TLS1.3, RequireAndVerifyClientCert) gated
behind --tls-ca/--tls-cert/--tls-key on both binaries. Insecure path (and all
bufconn tests) unchanged. Per-VNI authz remains a follow-up.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Two-node cross-node encap e2e on the containerlab fabric

**Files:**
- Create: `test/e2e/routebus_test.go`

**Context:** This is spec §11's acceptance test — the first test that exercises the *encap* path. It reuses the existing fabric (`hack/clab/ipv6-fabric.clab.yml`: kind cluster `k01` with nodes `k01-control-plane` = underlay `fd00:db8:0:1::/64` and `k01-worker` = `fd00:db8:0:2::/64`, routed to each other by FRR `sw1`). It follows `test/e2e/fabric_test.go`'s exact skip-style and `clab-up.sh`/`clab-down.sh` harness. On each kind node it runs `flowplane serve` and attaches one endpoint via `AttachInterface`; then it drives the two dataplanes' `AddRoute` directly (the reflector/agent path is unit-tested in Tasks 3-6; here we prove the *datapath encap* end-to-end without needing the agent's k8s wiring inside the fabric) and asserts cross-node ping succeeds over IP-in-IPv6, then that a `WithdrawRoute` breaks it.

- [ ] **Step 1: Write the e2e test**

Create `test/e2e/routebus_test.go`:

```go
package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestCrossNodeOverlayPing brings up the IPv6 fabric, runs flowplane on both kind
// nodes with one endpoint each, programs the cross-node routes via AddRoute, and
// asserts ping works over the IP-in-IPv6 overlay — then that WithdrawRoute breaks
// it. SKIPs (never fails) without containerlab/kind/docker, like the sibling tests.
func TestCrossNodeOverlayPing(t *testing.T) {
	for _, bin := range []string{"containerlab", "kind", "docker"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	const (
		cp   = "k01-control-plane"
		wk   = "k01-worker"
		vni  = "100"
		ipA  = "10.0.0.1"
		ipB  = "10.0.0.2"
		nhA  = "fd00:db8:0:1::a" // control-plane endpoint underlay (within cp's /64)
		nhB  = "fd00:db8:0:2::a" // worker endpoint underlay (within wk's /64)
		grpcAddr      = "127.0.0.1:1337"
		deployTimeout = 15 * time.Minute
		cmdTimeout    = 5 * time.Minute
	)

	up := exec.Command("../../hack/clab-up.sh")
	up.Env = testEnv()
	if out, err := runWithTimeout(up, deployTimeout); err != nil {
		t.Fatalf("clab-up failed: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		down := exec.Command("../../hack/clab-down.sh")
		down.Env = testEnv()
		if out, err := runWithTimeout(down, cmdTimeout); err != nil {
			t.Logf("clab-down failed: %v\n%s", err, out)
		}
	})

	// dockerExec runs a command inside a kind node container.
	dockerExec := func(node string, args ...string) (string, error) {
		full := append([]string{"exec", node}, args...)
		out, err := runWithTimeout(exec.Command("docker", full...), cmdTimeout)
		return out, err
	}
	// grpcurlIn runs grpcurl inside a node against its local flowplane.
	grpcurlIn := func(node, method, body string) (string, error) {
		return dockerExec(node, "grpcurl", "-plaintext", "-d", body, grpcAddr, method)
	}

	// Start flowplane on each node (image already loaded by the fabric; serve in background).
	for _, node := range []string{cp, wk} {
		if _, err := dockerExec(node, "sh", "-c",
			"pkill -f 'flowplane serve' 2>/dev/null; (flowplane serve --grpc "+grpcAddr+" >/tmp/xdp.log 2>&1 &) ; sleep 3"); err != nil {
			t.Fatalf("start flowplane on %s: %v", node, err)
		}
	}

	// Create a netns + endpoint on each node via AttachInterface.
	attach := func(node, ip string) {
		ns := "ep"
		if _, err := dockerExec(node, "ip", "netns", "add", ns); err != nil {
			t.Logf("netns add on %s (may exist): %v", node, err)
		}
		body := fmt.Sprintf(`{"interface_id":"ep0","netns_path":"/var/run/netns/%s","vni":%s,"requested_ips":["%s"]}`, ns, vni, ip)
		if out, err := grpcurlIn(node, "dataplane.v1.DataplaneNode/AttachInterface", body); err != nil {
			t.Fatalf("attach on %s: %v\n%s", node, err, out)
		}
	}
	attach(cp, ipA)
	attach(wk, ipB)

	// Program cross-node routes: cp learns B via wk's underlay, wk learns A via cp's underlay.
	addRoute := func(node, prefix, nexthop string) {
		body := fmt.Sprintf(`{"vni":%s,"prefix":"%s","nexthop_underlay":"%s"}`, vni, prefix, nexthop)
		if out, err := grpcurlIn(node, "dataplane.v1.DataplaneNode/AddRoute", body); err != nil {
			t.Fatalf("AddRoute on %s: %v\n%s", node, err, out)
		}
	}
	addRoute(cp, ipB+"/32", nhB)
	addRoute(wk, ipA+"/32", nhA)

	// Ping B from A's netns over the overlay. Retry to allow neighbor/route settle.
	pingOK := func() bool {
		out, err := dockerExec(cp, "ip", "netns", "exec", "ep", "ping", "-c", "2", "-W", "1", ipB)
		if err == nil && strings.Contains(out, " 0% packet loss") {
			return true
		}
		return false
	}
	var pinged bool
	for i := 0; i < 15; i++ {
		if pingOK() {
			pinged = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !pinged {
		log, _ := dockerExec(cp, "cat", "/tmp/xdp.log")
		t.Fatalf("cross-node overlay ping A->B never succeeded\nflowplane log:\n%s", log)
	}

	// Withdraw A's route to B on the cp node; ping must now fail (route gone => Pass, no encap).
	body := fmt.Sprintf(`{"vni":%s,"prefix":"%s/32"}`, vni, ipB)
	if out, err := grpcurlIn(cp, "dataplane.v1.DataplaneNode/WithdrawRoute", body); err != nil {
		t.Fatalf("WithdrawRoute on %s: %v\n%s", cp, err, out)
	}
	stillDown := false
	for i := 0; i < 5; i++ {
		if !pingOK() {
			stillDown = true
			break
		}
		time.Sleep(time.Second)
	}
	if !stillDown {
		t.Fatal("ping still succeeded after WithdrawRoute; route was not removed")
	}
}
```

- [ ] **Step 2: Run the test (skips if tooling absent; full run needs the fabric)**

Run: `nix develop --command sh -c 'cd test/e2e && go test -run TestCrossNodeOverlayPing -v -timeout 25m 2>&1 | tail -30'`
Expected on a fabric-capable host: PASS (cross-node ping succeeds, then fails after withdraw). On a host without containerlab/kind/docker: `--- SKIP`. If `flowplane serve` isn't on the node's `PATH` or the image entrypoint differs, adjust the `serve` invocation to match how `test/e2e/fabric_test.go` runs flowplane on `k01-control-plane` (it uses the same `ghcr.io/trevex/ectobase/flowplane:dev` image — mirror its exact exec form). If `grpcurl` isn't in the node image, install it in the serve step or shell out from the host with `-import-path`.

- [ ] **Step 3: Verify the whole workspace still builds and unit tests pass**

Run: `nix develop --command sh -c 'go build ./... 2>&1 | tail -3; cd netplane && go test ./... 2>&1 | tail -5; cd ../test/e2e && go vet ./... 2>&1 | tail -3'`
Expected: builds clean; netplane unit tests PASS; `go vet` clean on the e2e module.

- [ ] **Step 4: Commit**

```bash
git add test/e2e/routebus_test.go
git commit -m "test(e2e): cross-node overlay ping over IP-in-IPv6 on the clab fabric

Acceptance test (spec §11): flowplane on both kind nodes, one endpoint each,
AddRoute programs the cross-node routes, and ping A->B succeeds over the encap
path — the first test exercising ENCAP, not the same-node fast path. WithdrawRoute
then breaks it. Skips without containerlab/kind/docker.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:**
- §4.1 `flowplane` AddRoute/WithdrawRoute → Task 1. ✓ (Refinement: remote routes program only ROUTES, no UNDERLAY — justified against egress.rs.)
- §4.2 per-node agent (reconcile CRDs, drive flowplane, route-bus client) → Tasks 5 (bus + driver) + 6 (reconcile). ✓
- §4.3 reflector (per-VNI table, snapshot-then-incremental, fast-withdraw) → Tasks 3 (RIB) + 4 (server). ✓
- §4.4 central controllers (VPC→VNI, scheduling) → **partially deferred.** The agent reads `status.vni`/`status.nodeName`; the controllers that *populate* them are out of this plan's scope. Noted here as the one intentional gap — v1 e2e (Task 8) drives routes directly and does not depend on the controllers. Follow-up plan.
- §5 route bus protocol (Session bidi, Hello/Subscribe/Announce/Withdraw/KeepAlive, RouteUpdate/EndOfRIB, full-table-then-EoR) → Task 2 proto + Tasks 3-5 behavior. ✓
- §6 data flow (endpoint up/down, node death) → Tasks 3-6 (announce/withdraw/DropOrigin) + Task 8 (encap ping + withdraw). ✓
- §7 metalbond improvements: HA consistent state → **deferred** (single reflector instance; noted); graceful-restart/EndOfRIB → ✓ (RIB snapshot + EndOfRIB); ECMP nexthop-sets → carried in proto, primary programmed (✓ partial, noted); BFD liveness → v1 uses aggressive gRPC keepalive + session-close fast-withdraw (Task 4/7), dedicated BFD deferred (noted); mTLS + authz → Task 7 (transport ✓; per-VNI authz deferred, noted). 
- §8 security (mTLS, node==cert) → Task 7. ✓ (authz deferred, noted §7.)
- §11 acceptance e2e (two kind nodes, cross-node encap ping, liveness withdraw) → Task 8. ✓
- §12 repo layout → matches (api/proto/routebus, add to dataplane.proto, cmd/agent, cmd/reflector, flowplane). `cmd/controllers` folded away for v1 per §12's "or fold into agent/reflector." ✓

**2. Placeholder scan:** No TBD/TODO left as work. The one `var _ = grpc.WaitForReady` line in Task 5 is explicitly flagged for deletion with an instruction. The deferred items (HA, per-VNI authz, dedicated BFD, central controllers) are called out as scoped-out follow-ups, not silent gaps.

**3. Type consistency:** `Route{Vni,Prefix,Nexthop}`, `Dataplane.AddRoute(ctx,vni,prefix,nexthop)`, `Sink{ID,Send}`, `RIB.{Subscribe,Announce,Withdraw,DropOrigin,Unsubscribe}`, proto `ClientMsg_*`/`ServerMsg_*` oneof wrappers, `RouteOp_ROUTE_OP_ADD/WITHDRAW`, `Reconciler.{Desired,vniFor,SetUnderlay}` are used identically across tasks. The Rust handlers call the real `Control::{create_route,delete_route,create_route6,delete_route6}` signatures verified in `control.rs:676-766`. The proto go_package (`netplane/gen/routebusv1;routebusv1`) matches the Makefile `--go_opt=module=…/netplane/gen` output path and the `rbv1`/`pb` import aliases.

**Known deferred (follow-up plans):** central VPC→VNI + scheduling controllers; reflector HA/consistency; dedicated BFD/UDP liveness; per-VNI announce/subscribe authorization; ECMP datapath consumption; prune-on-EndOfRIB in the agent; DaemonSet/manifests to deploy agent+reflector in-cluster.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-02-route-distribution-control-plane.md`. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
