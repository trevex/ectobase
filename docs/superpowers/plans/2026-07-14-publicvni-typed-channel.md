# PublicVNI Typed Public-Prefix Channel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generalize the routebus NAT-block broadcast into a typed **PublicPrefix** global channel, migrate NAT blocks onto it, and add an **EDGE_UNDERLAY** record so the WAN edge self-advertises its anycast datapath underlay — making the source's egress nexthop **discovered** instead of hardcoded on `NATGateway.Spec.EdgeUnderlay`.

**Architecture:** A new `PublicPrefix{kind, prefix, owner_underlay, vni, attributes, op}` message rides the *same global all-sinks broadcast* the NAT stream already uses (reflector `nattable.go` sink model). The node agent gains a `DesiredPublic()` producer (edge announces `EDGE_UNDERLAY`; NAT sources announce `NAT_IP`) and an `applyPublic()` consumer that dispatches on `Kind` into the existing dataplane gRPC calls (`AddNeighborNat` for `NAT_IP`, a learned-nexthop table for `EDGE_UNDERLAY`). `NatUpdate`/`AnnounceNat` are kept as a thin back-compat shim during migration so the egress e2e stays green, then removed. No new eBPF maps.

**Tech Stack:** Go (netplane agent + reflector, controller-runtime), protobuf (routebus.proto), existing Rust dataplane gRPC (unchanged). Tests: Go unit tests + reflector/agent tests + the live `test/egress-fabric-e2e.sh`.

**Scope note:** This is subproject §2 of `docs/superpowers/specs/2026-07-14-north-south-edge-identity-lb-ipam.md`. IPAM (§3), Phase D, and external LB (§4) are separate plans.

---

## File Structure

- `api/proto/routebus/v1/routebus.proto` — add `PublicPrefix` msg + `PublicKind` enum + `AnnouncePublic`/`WithdrawPublic` ClientMsg + `PublicUpdate` ServerMsg. Regenerate Go stubs.
- `netplane/reflector/publictable.go` (NEW) — global broadcast table for PublicPrefix, mirroring `nattable.go`'s sink model.
- `netplane/reflector/server.go` — dispatch `AnnouncePublic`/`WithdrawPublic`; register/replay PublicPrefix on `Hello`.
- `netplane/reflector/nattable.go` — keep; `AnnounceNat` internally forwards to the public table as `kind=NAT_IP` (shim).
- `netplane/agent/public.go` (NEW) — `PublicPrefix` domain type, `DesiredPublic()` producer, `applyPublic()` consumer + dispatch.
- `netplane/agent/reconcile.go` — `Desired()` returns `announcePublic []PublicPrefix`; wire producer.
- `netplane/agent/natreconcile.go` — `DesiredExternalRoutes()` uses the **learned** edge underlay (from EDGE_UNDERLAY) instead of `gw.Spec.EdgeUnderlay`; edge announces its own EDGE_UNDERLAY.
- `netplane/agent/bus.go` — send `AnnouncePublic`; receive `PublicUpdate` → `applyPublic()`.
- `api/v1alpha1/natgateway_types.go` — mark `Spec.EdgeUnderlay` **optional/deprecated** (comment only; keep field for back-compat).
- Tests: `netplane/reflector/publictable_test.go`, `netplane/agent/public_test.go`.

---

## Task 1: Proto — PublicPrefix message + channel

**Files:**
- Modify: `api/proto/routebus/v1/routebus.proto`
- Regenerate: the generated Go (`*.pb.go`) via the repo's proto-gen path

- [ ] **Step 1: Add the message, enum, and channel to routebus.proto**

Add inside the proto (alongside the existing NAT messages):

```proto
enum PublicKind {
  PUBLIC_KIND_UNSPECIFIED = 0;
  PUBLIC_KIND_EDGE_UNDERLAY = 1;   // edge's anycast datapath /128; owner_underlay = edge's UNIQUE loopback
  PUBLIC_KIND_NAT_IP = 2;          // a distributed-SNAT nat_ip block (attributes = port range)
  PUBLIC_KIND_LB_VIP = 3;          // reserved (external LB arc)
  PUBLIC_KIND_FLOATING_IP = 4;     // reserved
}

message PublicPrefix {
  PublicKind kind           = 1;
  string     prefix         = 2;   // "fd00:db8:0:9::e/128", "203.0.113.1/32", "64:ff9b::/96"
  string     owner_underlay = 3;   // announcing node's UNIQUE underlay (never an anycast)
  uint32     vni            = 4;   // overlay VNI this record serves (0 = global/all)
  uint32     port_min       = 5;   // NAT_IP: inclusive; else 0
  uint32     port_max       = 6;   // NAT_IP: exclusive; else 0
}
```

Add to `ClientMsg` oneof: `PublicPrefix announce_public = 10; PublicPrefix withdraw_public = 11;`
Add to `ServerMsg` oneof: `PublicUpdate public_update = 10;`
Add: `message PublicUpdate { PublicPrefix prefix = 1; RouteOp op = 2; }`

(Use the next free field numbers in each oneof — check the file; the numbers above are placeholders, pick the actual next-free.)

- [ ] **Step 2: Regenerate Go stubs**

Run the repo's proto generation (find it: `grep -rn "protoc\|buf generate" Makefile hack/ netplane/`). Expected: `routebus.pb.go` gains `PublicPrefix`, `PublicKind`, `PublicUpdate`, and the oneof accessors.

- [ ] **Step 3: Build to verify the stubs compile**

Run: `cd netplane && go build ./...`
Expected: compiles (nothing references the new types yet).

- [ ] **Step 4: Commit**

```bash
git add api/proto/routebus/v1/routebus.proto netplane/**/*.pb.go
git commit -m "feat(routebus): PublicPrefix typed-record proto (edge-underlay/nat/vip channel)"
```

---

## Task 2: Reflector — global PublicPrefix broadcast table

**Files:**
- Create: `netplane/reflector/publictable.go`
- Create test: `netplane/reflector/publictable_test.go`
- Modify: `netplane/reflector/server.go`

- [ ] **Step 1: Write the failing test** (`publictable_test.go`)

Model it on `nattable_test.go`. Test that: a registered sink receives a snapshot replay on register; `AnnouncePublic` fans a `PublicUpdate{op=ADD}` to ALL sinks (including origin — matches NAT semantics, since public records are globally relevant); `WithdrawPublic` fans `op=WITHDRAW`; duplicate announce is idempotent.

```go
func TestPublicTableFanout(t *testing.T) {
    pt := newPublicTable()
    s1 := newFakeSink(); s2 := newFakeSink()
    pt.RegisterSink(s1); pt.RegisterSink(s2)
    pt.AnnouncePublic(PublicRecord{Kind: EdgeUnderlay, Prefix: "fd00:db8:0:9::e/128", OwnerUnderlay: "fd00:db8:0:9::1"})
    // both sinks see one PublicUpdate ADD
    if got := s1.publicAdds(); got != 1 { t.Fatalf("s1 adds=%d want 1", got) }
    if got := s2.publicAdds(); got != 1 { t.Fatalf("s2 adds=%d want 1", got) }
}
```

- [ ] **Step 2: Run it — verify it fails to compile/pass**

Run: `cd netplane && go test ./reflector/ -run TestPublicTableFanout`
Expected: FAIL (newPublicTable undefined).

- [ ] **Step 3: Implement `publictable.go`**

Mirror `nattable.go` exactly: a `publicTable` struct with `sinks map[*sink]struct{}` and `records []PublicRecord`; `RegisterSink` replays the snapshot; `AnnouncePublic`/`WithdrawPublic` mutate + `publicFanout()` to all sinks. Reuse the existing `sink` type's send path — add a `sendPublic(*pb.PublicUpdate)` method to the sink (or route through the existing ServerMsg send). Key records by `(kind, prefix, owner_underlay)`.

- [ ] **Step 4: Run the test — verify pass**

Run: `cd netplane && go test ./reflector/ -run TestPublicTableFanout -v`
Expected: PASS.

- [ ] **Step 5: Wire into `server.go`**

In `Session`: on `Hello`, also `s.pub.RegisterSink(sink)` (and unregister on disconnect). Dispatch `ClientMsg.AnnouncePublic` → `s.pub.AnnouncePublic(...)`, `WithdrawPublic` → `s.pub.WithdrawPublic(...)`. Construct the reflector with the new `publicTable`.

- [ ] **Step 6: Run reflector package tests**

Run: `cd netplane && go test ./reflector/...`
Expected: PASS (existing NAT/route tests unaffected).

- [ ] **Step 7: Commit**

```bash
git add netplane/reflector/publictable.go netplane/reflector/publictable_test.go netplane/reflector/server.go
git commit -m "feat(reflector): global PublicPrefix broadcast table (mirrors NAT fan-out)"
```

---

## Task 3: Agent — announce EDGE_UNDERLAY + learn it (discovered egress nexthop)

**Files:**
- Create: `netplane/agent/public.go`
- Create test: `netplane/agent/public_test.go`
- Modify: `netplane/agent/reconcile.go`, `netplane/agent/natreconcile.go`, `netplane/agent/bus.go`

- [ ] **Step 1: Write the failing test** (`public_test.go`)

Test the consumer dispatch + the discovered-nexthop logic as pure functions:
- `applyPublic(EDGE_UNDERLAY, prefix=anycast, owner=edgeloopback)` records the anycast in the agent's `learnedEdge` set (a `map[string]struct{}` of edge anycast underlays).
- `DesiredExternalRoutes` (edge role) originates `0.0.0.0/0` + `64:ff9b::/96` with nexthop = **the edge's own `--underlay` (anycast)**, for every VNI that has a NATGateway — WITHOUT reading `gw.Spec.EdgeUnderlay`.
- On a **source** node, the external default is installed from the received route (unchanged); assert `learnedEdge` is populated when an EDGE_UNDERLAY arrives.

```go
func TestEdgeUnderlayDiscovery(t *testing.T) {
    r := &Reconciler{nodeID: "edge1", underlay: "fd00:db8:0:9::e", role: RoleEdge}
    // a NATGateway exists for vni 100; edge originates the external default with its own anycast
    got := r.DesiredExternalRoutes([]NatGwView{{VNI: 100}})
    // expect 0.0.0.0/0 + 64:ff9b::/96, External:true, Nexthop == r.underlay, no EdgeUnderlay read
    ...
}
```

- [ ] **Step 2: Run — verify fail**

Run: `cd netplane && go test ./agent/ -run TestEdgeUnderlayDiscovery`
Expected: FAIL.

- [ ] **Step 3: Implement `public.go`**

- `PublicPrefix` domain struct (kind enum mirrored in Go).
- `applyPublic(pp PublicPrefix, op)`: dispatch on kind — `NAT_IP` → `dp.AddNeighborNat` (skip own, matching existing `applyNat`); `EDGE_UNDERLAY` → update `learnedEdge`. (`LB_VIP`/`FLOATING_IP` → no-op stubs with a log line, per "no silent caps".)
- `DesiredPublic()`: on an edge (`role == RoleEdge`), produce `PublicPrefix{kind: EDGE_UNDERLAY, prefix: underlay+"/128", owner_underlay: uniqueLoopback}`; for owned NAT blocks, produce `kind: NAT_IP` records (mirroring the existing NatBlock announce — see Task 4 for the NAT migration).

- [ ] **Step 4: Change `DesiredExternalRoutes` to not read `gw.Spec.EdgeUnderlay`**

In `natreconcile.go`: an edge originates the external defaults for every VNI that has a NATGateway (list NATGateways, collect their VPC VNIs), nexthop = the edge's own `underlay`. Drop the `gw.Spec.EdgeUnderlay == underlay` filter. (The edge's unique loopback comes from a new `--edge-loopback` flag / config; see Task 5.)

- [ ] **Step 5: Wire `bus.go`**

- Send `AnnouncePublic` for each `DesiredPublic()` record (mirror `AnnounceNat`).
- On `ServerMsg.PublicUpdate` → `applyPublic()`.

- [ ] **Step 6: Run agent tests**

Run: `cd netplane && go test ./agent/...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add netplane/agent/public.go netplane/agent/public_test.go netplane/agent/reconcile.go netplane/agent/natreconcile.go netplane/agent/bus.go
git commit -m "feat(agent): announce+learn EDGE_UNDERLAY; derive egress nexthop (drop EdgeUnderlay hardcode)"
```

---

## Task 4: Migrate NAT blocks onto the PublicPrefix channel (shim, keep e2e green)

**Files:**
- Modify: `netplane/reflector/nattable.go`, `netplane/agent/bus.go`, `netplane/agent/public.go`

- [ ] **Step 1: Failing test** — a `NAT_IP` PublicPrefix produces the same `AddNeighborNat` call the old `NatUpdate` did (assert on a fake dataplane recording `AddNeighborNat(natIp, min, max, owner, vni)`), and self-owned NAT_IP is skipped.

- [ ] **Step 2: Run — verify fail.** `cd netplane && go test ./agent/ -run TestNatIpAsPublicPrefix`

- [ ] **Step 3: Implement the shim** — `AnnounceNat` (reflector) forwards to the public table as `kind=NAT_IP` (in addition to, or instead of, the legacy NAT fan-out — keep BOTH firing during migration so old+new agents interop). Agent: `DesiredNat` blocks are emitted as `NAT_IP` PublicPrefix records via `DesiredPublic()`; `applyPublic(NAT_IP)` installs `AddNeighborNat`. Keep the legacy `applyNat` path until the live e2e passes on the new path, then remove.

- [ ] **Step 4: Run — verify pass.**

- [ ] **Step 5: Commit** — `feat(routebus): carry NAT blocks as NAT_IP PublicPrefix records (migration shim)`

---

## Task 5: Edge unique-loopback config + wiring

**Files:**
- Modify: `netplane/agent` main/flags (find `--underlay`, `--role` — likely `netplane/cmd` or `agent` main), `hack/clab/edge-agents-up.sh`

- [ ] **Step 1:** Add an `--edge-loopback <ipv6/128>` flag (the edge's UNIQUE control-plane loopback `fd00:db8:0:9::{1,2}`, already on `dum0` per `hack/clab/vyos/edge{1,2}.boot`). The edge agent uses it as `owner_underlay` in the EDGE_UNDERLAY (and NAT_IP) records so replies return to the specific edge, while `--underlay` (anycast) stays the datapath identity.

- [ ] **Step 2:** Update `hack/clab/edge-agents-up.sh` to pass `--edge-loopback fd00:db8:0:9::1` / `::2` per edge.

- [ ] **Step 3: Commit** — `feat(agent): --edge-loopback for unique edge control-plane identity`

---

## Task 6: Drop `NATGateway.Spec.EdgeUnderlay` reliance + update the e2e

**Files:**
- Modify: `api/v1alpha1/natgateway_types.go` (deprecate field via comment), `test/egress-fabric-e2e.sh`

- [ ] **Step 1:** In `natgateway_types.go`, comment `EdgeUnderlay` as deprecated/optional (kept for back-compat; the edge fleet self-advertises via EDGE_UNDERLAY). Do NOT remove the field (avoids a CRD breaking change this slice).

- [ ] **Step 2:** In `test/egress-fabric-e2e.sh`, drop `edgeUnderlay:` from the NATGateway CR (or leave it — assert it is IGNORED). Add an assertion that the source learned the edge nexthop via an EDGE_UNDERLAY record (grep the edge-xdp / source agent logs for `EDGE_UNDERLAY` / discovered nexthop), not from the spec.

- [ ] **Step 3: Validate on the live fabric** — the fabric is up (Cilium); redeploy the netplane stack and run the e2e:

```bash
K1=/tmp/k01.kubeconfig; kind get kubeconfig --name k01 > "$K1"
kubectl --kubeconfig "$K1" apply -k config/crd && kubectl --kubeconfig "$K1" apply -k config/deploy
# rebuild+load the netplane image first if agent/reflector changed:
make image-netplane && kind load docker-image ghcr.io/trevex/netplane:dev --name k01
kubectl --kubeconfig "$K1" -n ectobase-system rollout restart deploy/reflector deploy/netplane-controller ds/netplane-agent
sudo -E env "PATH=$HOME/go/bin:/run/current-system/sw/bin:$PATH" bash test/egress-fabric-e2e.sh
```
Expected: `PASS ... via distributed SNAT + HA edge (return via BOTH edges)`, now with the discovered edge nexthop.

- [ ] **Step 4: Commit** — `feat(edge): egress nexthop discovered via EDGE_UNDERLAY (NATGateway.EdgeUnderlay deprecated)`

---

## Task 7: Remove the legacy NAT stream (after the new path is proven)

**Files:**
- Modify: `netplane/reflector/nattable.go`, `netplane/reflector/server.go`, `netplane/agent/bus.go`, `api/proto/routebus/v1/routebus.proto`

- [ ] **Step 1:** Once Task 6's e2e passes on the PublicPrefix path, remove the legacy `AnnounceNat`/`NatUpdate` send+apply from the agent and reflector (keep the proto messages one release for interop, or remove if no external consumers). Run the full reflector+agent tests + the live e2e again to confirm no regression.

- [ ] **Step 2: Commit** — `refactor(routebus): retire legacy NatUpdate stream (NAT now rides PublicPrefix)`

---

## Self-Review Checklist (run before executing)

- **Spec coverage:** §2 (typed channel + EDGE_UNDERLAY + NAT migration) ✓; `NATGateway.Spec.EdgeUnderlay` derived ✓. LB_VIP/FLOATING_IP are enum stubs only (deferred to §3/§4) — intentional.
- **e2e stays green:** the migration shim (Task 4) keeps both NAT paths firing until Task 6 proves the new one; Task 7 removes the old one last.
- **No new eBPF:** confirmed — NAT_IP → existing `AddNeighborNat`; EDGE_UNDERLAY → agent-side learned table; no dataplane change.
- **Type consistency:** the Go `PublicPrefix` domain struct mirrors the proto `PublicPrefix`; `PublicKind` values match across proto/Go/agent dispatch.
- **Open item for the executor:** confirm the proto oneof next-free field numbers before editing; confirm the exact `--role`/RoleEdge plumbing in the agent main (Task 3/5).
