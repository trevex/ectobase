# Route Distribution & Control Plane — Design

**Status:** Draft (brainstorm output) — design agreed; next step is `writing-plans`.
**Date:** 2026-07-02
**Parent vision:** `docs/superpowers/specs/2026-07-02-multicluster-kubevirt-dataplane-design.md` (sub-project ④ NetPlane, brought forward)
**Research:** `docs/superpowers/research/2026-07-02-route-distribution.md` (metalbond vs BGP EVPN — custom-Rust-bus recommendation; superseded on language by the control/data-plane split below), `2026-07-02-cni-plumbing.md`.
**Network API:** `docs/superpowers/specs/2026-07-02-network-api-design.md` (VPC/NetworkInterface CRDs).

---

## 1. Summary

Give the eBPF dataplane **dynamic overlay routes** so endpoints on different nodes reach each other over the IP-in-IPv6 overlay. Do it with a **strict control-plane / data-plane split** (as dpservice is driven by metalnet): the **dataplane (`xdp-dp`, Rust/eBPF) stays a dumb, gRPC-driven datapath**; a **separate Go control plane** reconciles the CRDs, drives the dataplane, and runs a **custom route bus** (metalbond-analog) against a **single global route reflector**. Not BGP/EVPN in the hot path (no maintained Rust BGP stack does EVPN Type-5, and Go is the better fit for the CRD-heavy control plane) — EVPN stays a **future, decoupled edge gateway** (§9).

## 2. Goals / Non-goals

**Goals**
- Endpoints on different nodes communicate over the overlay (encap over the underlay IPv6 fabric) via **dynamically distributed routes**.
- **Control/data separation**: `xdp-dp` gains only a protocol-agnostic `AddRoute`/`WithdrawRoute`; all CRD/route logic is in Go, off the datapath.
- **Fast convergence + security**: reliable ordered route exchange (gRPC/mTLS) + sub-second failure detection (BFD-style liveness).
- **Single-cluster works** (central == local); multi-cluster is additive.
- Improve on metalbond's known weak spots (§7).

**Non-goals (now)**
- BGP/EVPN in the node hot path (future edge gateway only, §9).
- Reusing metalbond as-is (we build our own, cleaner protocol).
- Reflector reflector-to-reflector federation (single global reflector for v1).

## 3. Key decisions (with rationale)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Strict control/data split** — `xdp-dp` dumb + gRPC-driven; Go control plane drives it | Mirrors dpservice←metalnet; keeps CRD/route logic off the Rust datapath; Go is far nicer for controllers/k8s. |
| D2 | **Custom route bus** (not metalbond, not EVPN-on-node) | metalbond's `NextHop{underlay,vni}` is a 1:1 map to our eBPF maps, but its protocol has fixable weak spots; **no maintained Rust/Go-embeddable stack does EVPN Type-5 cleanly for a non-VXLAN datapath** (research §), and EVPN-on-every-node drags a BGP stack into the hot path. |
| D3 | **Single global reflector** (central cluster, HA) + **subscribe-by-VNI** | One global route space (matches "single global overlay"); per-VNI subscription means a node only holds routes for VPCs it hosts, bounding fan-out. The reflector **is** NetPlane. |
| D4 | **gRPC bidi-streaming + mTLS** for the exchange; **separate BFD-style UDP liveness** | Route exchange needs reliable ordered delivery (never drop a withdraw) → TCP/gRPC (like BGP-over-TCP); mTLS = per-agent identity. Failure *detection* is the latency-critical part → a BFD-style fast liveness sidecar (like BGP+BFD), not QUIC (grpc-go is HTTP/2-only; transport RTT isn't the bottleneck). |
| D5 | **Agent reconciles the CRDs itself** (metalnet model) | Fewest moving parts; the per-node agent reads `NetworkInterface`/`VPC`, attaches locally, and announces — central controllers only allocate VNI + schedule. |
| D6 | **Protocol-agnostic dataplane route interface** (`AddRoute`/`WithdrawRoute`) | Keeps the datapath decoupled from the distribution mechanism, so a future EVPN gateway (§9) drives the *same* interface. |

## 4. Architecture

```
        ┌──────────────ROUTE REFLECTOR (Go, central cluster, HA) — "NetPlane"───────────┐
        │  global per-VNI route table · redistribute to subscribers · BFD fast-withdraw  │
        └───────▲───────────────────────────▲───────────────────────────▲───────────────┘
    gRPC bidi stream (mTLS) + BFD/UDP liveness │                          │
        ┌───────┴─────────┐          ┌────────┴────────┐        ┌─────────┴──────────┐
        │ node A agent (Go)│          │ node B agent    │  …     │ central controllers │
        │  • watch CRDs    │          │                 │        │  VPC→VNI, schedule  │
        │  • route-bus cli │          │                 │        └─────────────────────┘
        │  • drive xdp-dp  │          │                 │                 ▲ watch/reconcile
        └───────┬──────────┘          └────────┬────────┘        ┌────────┴─────────────┐
   dataplane.v1 │ gRPC                          │                │ CENTRAL AGGREGATED API │
   (Attach + AddRoute/Withdraw)                 │                │ VPC · NetworkInterface │
        ┌───────┴──────────┐          ┌─────────┴────────┐       └────────────────────────┘
        │ xdp-dp (Rust/eBPF)│          │ xdp-dp           │
        │ ROUTES/UNDERLAY   │          │                  │
        └──────────────────┘          └──────────────────┘
                     └────────── IPv6 BGP underlay fabric (encap) ──────────┘
```

### 4.1 `xdp-dp` (Rust/eBPF) — dumb datapath
Unchanged role. Adds to `dataplane.v1`:
- `AddRoute(vni, prefix, nexthop_underlay, [flags]) ` → program `ROUTES`/`ROUTES6` + ensure `UNDERLAY[nexthop]` (remote).
- `WithdrawRoute(vni, prefix)` → remove.
- (`AttachInterface`/`DetachInterface`/`ConfigureNetwork` already exist.)
No CRD awareness, no route exchange. Idempotent, driven entirely over gRPC.

### 4.2 Per-node agent (Go, "metalnet")
One per node. Responsibilities:
1. **Reconcile** the central API for `NetworkInterface`s on its node (+ their `VPC.status.vni`).
2. **Drive local `xdp-dp`**: `AttachInterface` on create; `AddRoute`/`WithdrawRoute` as bus routes arrive.
3. **Route-bus client**: on a local endpoint, **announce** `(vni, overlay_prefix) → this node's underlay IPv6`; **subscribe by VNI** (only VPCs it hosts); on learning a remote route, program `xdp-dp`.
4. **Liveness**: BFD-style keepalive to the reflector; on peer-down, the reflector withdraws this node's routes.

### 4.3 Route reflector (Go, central, HA)
- Holds the **global per-VNI route table**; on a subscriber's `Subscribe(vni)`, sends the full table for that VNI then incremental add/withdraw.
- **Fast-withdraw** a node's routes when its BFD/liveness fails (no blackhole waiting on a slow keepalive).
- HA as a small replicated set with **consistent state** (avoid metalbond's client-side divergence — §7).

### 4.4 Central controllers (Go)
- `VPC` controller: allocate the global VNI → `VPC.status.vni`.
- `NetworkInterface` scheduling: assign to a node → `status.nodeName`.
- Minimal for v1 (the agent does the rest).

## 5. The route bus protocol (`routebus.v1`, gRPC)
A single bidi-streaming RPC, e.g. `Session(stream ClientMsg) returns (stream ServerMsg)`:
- **Client→server:** `Hello{node_id, underlay_ipv6}`, `Subscribe{vni}`/`Unsubscribe{vni}`, `Announce{vni, prefix, nexthop_underlay, [nexthops for ECMP]}`, `Withdraw{vni, prefix}`, `KeepAlive`.
- **Server→client:** `RouteUpdate{vni, prefix, [nexthops], op: ADD|WITHDRAW}`, `EndOfRIB{vni}` (graceful-restart marker), `KeepAlive`.
- **On connect:** server sends the full table for each subscribed VNI then `EndOfRIB` (so the agent can reconcile/prune without blackholing on reconnect).
- **Liveness:** a separate lightweight **BFD-style UDP** exchange (or aggressive stream keepalive as a v1 fallback) drives sub-second peer-down → fast withdraw.
- **Security:** mTLS; the client cert identity = the node; the reflector authorizes which VNIs a node may announce/subscribe.

## 6. Data flow

**Endpoint up:** `NetworkInterface{vpcRef,ips}` created → VNI allocated, scheduled to node N → N.agent `AttachInterface` (veth/tap + local self-route + underlay /128) → N.agent `Announce (vni, 10.0.0.5/32) → N-underlay` → reflector redistributes to VNI subscribers → each other agent `AddRoute` on its `xdp-dp` → their endpoints encap to `10.0.0.5` via N's underlay over the fabric.

**Endpoint down:** delete → N.agent `Withdraw` + local `DetachInterface` → reflector propagates → agents `WithdrawRoute`.

**Node death:** BFD timeout at the reflector → reflector withdraws all of N's routes → agents `WithdrawRoute` (fast, no blackhole).

## 7. Improvements over metalbond (the "do it properly")
- **Reflector HA with consistent state** (not client-side fan-out that can diverge).
- **Graceful restart / EndOfRIB** — full-table-then-EoR on (re)connect; stale-route hold + prune instead of blackhole on restart.
- **ECMP nexthop-sets** — `Announce` carries a set of nexthops; `ROUTES` value + the datapath pick one (or hash).
- **BFD-grade liveness** — sub-second failure detection (metalbond's ~second keepalive is too slow).
- **mTLS + per-node authz** on which VNIs a node may touch.

## 8. Security
mTLS on the bus; node identity = client cert. The reflector enforces that a node may only announce prefixes for VNIs it's authorized for and subscribe only to permitted VNIs. No node holds write-creds to others; the reflector is the only shared trust point (single global — accepted blast radius, mitigated by HA + authz).

## 9. EVPN — future, decoupled edge gateway (not v1)
Because `xdp-dp`'s route interface is protocol-agnostic (D6) and the reflector holds the global table, a later **EVPN gateway** (Go, embedded **gobgp**) on a few route-servers can translate our routes ⇄ **EVPN Type-5** to peer the FRR ToR fabric and drive **switchdev/DPU eswitch offload** (the §7 DPU endgame). Node agents never speak BGP. Feasibility caveats + the tunnel-type-7 "IP-in-IP" encap question are in the research doc; this is gated on a separate spike.

## 10. Multi-cluster fit
The single global reflector lives in the **central cluster** and **is** NetPlane. Agents in any compute cluster peer it (cross-cluster gRPC/mTLS — the same central rendezvous as the aggregated API). **Single-cluster is the degenerate case**: reflector + agents + controllers co-located, central == local.

## 11. v1 scope & acceptance
- `xdp-dp`: `AddRoute`/`WithdrawRoute` on `dataplane.v1`.
- The route-bus proto + reflector + per-node agent, all in **Go**.
- **Acceptance e2e:** on the containerlab fabric's **two kind nodes**, an endpoint on each node; the agents announce/learn via the reflector; **cross-node ping over the IP-in-IPv6 overlay** (real encap over the underlay fabric) — the first test that exercises the *encap* path, not just the same-node fast path.
- Liveness: kill node B's agent/endpoint → node A's route withdrawn within the BFD budget (no lingering blackhole).

## 12. Component / repo layout (Go)
- `api/net.ectobase.dev/v1alpha1` — existing CRDs (+ any status fields for scheduling/VNI).
- `api/proto/routebus/v1/routebus.proto` — the bus protocol (Go + optional Rust if the reflector ever needs it; reflector is Go).
- `api/proto/dataplane/v1/dataplane.proto` — add `AddRoute`/`WithdrawRoute`.
- `cmd/agent` (Go) — the per-node agent.
- `cmd/reflector` (Go) — the route reflector.
- `cmd/controllers` (Go) — VPC/scheduling controllers (or fold into agent/reflector for v1).
- `xdp-dp/src/…` (Rust) — implement `AddRoute`/`WithdrawRoute`.

## 13. Open questions / risks (from the research spike)
- **ECMP** representation in `ROUTES`/protocol (single vs set; datapath selection).
- **Convergence budget** — the exact BFD interval + reflector fan-out latency to hit "latency-sensitive."
- **HA reflector consistency** — replication model (raft-lite? lease + shared store? or single + fast failover for v1).
- **Graceful-restart** semantics — stale-route hold timers.
- **EVPN gateway feasibility** — gobgp Type-5 + tunnel-type-7 round-trip; DPU eswitch actually consuming it (gated spike, §9).
- **Reflector placement in single-cluster** — co-located pod vs the agent embedding a loopback reflector when central==local.
