# Phase 5b — Tier-2 Fence-Gated Cross-Cluster Failover — Design

**Status:** Approved (brainstorm output) — ready for implementation planning.
**Date:** 2026-08-05
**Roadmap:** multi-cluster control plane §10 phase 5 (second half — Tier-2). Builds on `2026-08-01-multicluster-control-plane-design.md` §4.5 (M5/M6) and the Phase-3 failover skeleton (`central/internal/failover`).

## 1. Goal

Make the Phase-3 `Fencer` seam **real** and add the recovery half, so that when a **whole compute pool is lost** (partitioned or dead), VMs bound to it are safely restarted on a healthy pool — with an at-most-one-live-writer guarantee enforced by **external fences central can assert without reaching the lost pool**. Central is the decision *arbiter*; the fence is the *safety mechanism*. Config/control-plane only — no dataplane (eBPF) changes.

## 2. The load-bearing principle: fences, not timeouts

Heartbeat loss ≠ safe to restart a stateful VM. A pool that is merely **partitioned from central** may still be alive — reaching Ceph and the route reflector, holding the RWO RBD, announcing its sticky overlay IP. Safety comes from fences that act on the **storage backend** and the **overlay**, both reachable from central independent of the lost pool's k8s API. **Fail-safe: if a fence cannot be confirmed active, do not re-bind — stay down and alert.** Availability loss is recoverable; dual-writer/dual-IP corruption is not.

## 3. The fence identity: per-cluster set of node /64s

A VNI is an **overlay that spans clusters** — fencing by VNI would blocklist a VPC across healthy clusters. The correct per-cluster identity is its **set of node /64 underlay prefixes** (each node owns a /64, per the fabric node-VIP model). Both fences operate on this same /64 set:

- **Network fence** — at the reflector, withdraw/suppress every overlay route whose **underlay nexthop ∈ the fenced /64 set**, and reject new announcements originating from those /64s.
- **Storage fence** — a csi-addons `NetworkFence` per /64 (the node's RBD-client address lives in its /64) blocklisting those CIDRs at Ceph.
- **Release** is per-/64: when a node's /64 is confirmed drained on recovery, clear its reflector entry + delete its `NetworkFence`.

The /64 set is **reported upward before partition** (see §5), so central can act on it after the pool is unreachable.

## 4. Tier-1 / Tier-2 interaction under partition (the dual-writer resolution)

The dangerous interleaving: pool P is partitioned from central but alive; a node in P dies; **Tier-1** (autonomous, [[phase5a-tier1-failover]]) reschedules VM `v` to another node in P and re-announces; meanwhile central runs **Tier-2** and boots `v` on pool Q → two live writers.

**Resolution — whole-pool fence + preserved Tier-1 autonomy:**

1. Central does **not** fence/evacuate on a blip. It waits out the conservative `poolLost` threshold. During short partitions / node deaths, **Tier-1 self-heals locally, no central action, no conflict.** Self-healing survives central outages.
2. When the partition exceeds the Tier-2 threshold, central fences the **entire pool** (every /64 in `NodePrefixes`), not just the one dead node. Any local Tier-1 reschedule within P — onto *any* node — then lands on fenced storage + a blocked route: its RBD I/O fails and its sticky-IP announce is rejected. The fence actively cuts off the local instance.
3. Central then re-binds to Q as the sole live writer.

Per-node fencing would **not** close this (Tier-1 moves `v` to a different, unfenced node); the fence must be pool-wide. The stricter alternative — gating local provisioning on a fresh central lease — is **rejected as default** because it *loses* Tier-1 during partition (and here actually reduces availability); it is noted as a deferred per-pool opt-in (§9).

## 5. Components & data model

### 5.1 API status — fence coordinates, reported upward before partition

- `ClusterPool.Status.NodePrefixes[]` — the list of **/64 underlay prefixes**, one per node in the cluster; broker-stamped, heartbeated, kept current as nodes join/leave. The fence coordinate.
- `ClusterPool.Status.NodeDrain[]` — `{ prefix, drained bool }` per /64, for GC-confirmed release.
- `VirtualMachine.Status.Placement` — `{ clusterName, nodeName, nodePrefix }`, broker-stamped: the VM's actual running location, so recovery knows which /64 to confirm-drained.
- `VirtualMachine.Spec` gains a **minimal anti-affinity** expression — a group key + spread-across-pools intent (just enough for failover target-selection to honor; richer affinity is deferred).

### 5.2 Central components (`central/internal/`)

- `failover.Reconciler` (extend) — the state machine: `poolLost` → **fence whole pool (per /64)** → barrier (all /64s confirmed active) → capacity+anti-affinity schedule → sticky re-bind; else `FailoverBlocked`. Adds a `PoolFenced` phase + a recovery sub-path (per-/64 drain-confirmed → release).
- `StorageFencer` (real `Fencer` impl) — creates/deletes a csi-addons `NetworkFence` per /64 against an **injected Ceph-management-cluster client**; confirms *active* via the CR status. Degenerate single-cluster lab → same cluster.
- `NetworkFencer` (real impl) — sets/clears a **reflector blocklist** entry per /64.
- `scheduler` (extend) — real per-pool capacity accounting threaded across the failover batch + an anti-affinity predicate (never co-locate anti-affine VMs; only-violating-option → place + record violation in status).

### 5.3 Reflector (`netplane/reflector`)

Add a **blocklist** to the RIB: suppress reflection of and reject announcements from any route whose underlay nexthop ∈ a blocklisted /64. Set it via an **added reflector admin gRPC** (`SetFence(/64)` / `ClearFence(/64)`) that central's `NetworkFencer` dials directly — the reflector is already a gRPC server central controls, so this keeps the actuator a direct central→route-bus call (no new watch loop). This is the active guard against a still-connected partitioned node.

### 5.4 Broker (`central/cmd/broker` + netplane)

1. Stamp the upward status of §5.1 (pool `NodePrefixes`, per-VM `Placement`).
2. On recovery: set-reconcile-GC the rebound CompiledVMs → observe stale VMIs terminate → report `NodeDrain[].drained=true` per /64.

## 6. Control-flow ordering & fail-safe invariants

The re-bind (`Spec.ClusterName` write) is the point of no return; ordering guarantees at-most-one-live-writer:

1. **`poolLost` confirmed** (`Unknown` + lease stale beyond the conservative threshold — unchanged; Tier-1 owns everything before this).
2. **Fence whole pool, per /64:** for every `/64 ∈ NodePrefixes` apply `NetworkFence(/64)` **and** reflector-blocklist(`/64`). Each must report **active** (NetworkFence CR status = blocklisted; reflector ack) — not merely "requested."
3. **Barrier:** proceed only when **all** /64s report both fences active. Any /64 unconfirmed → whole pool stays `FailoverBlocked`, **no re-bind**.
4. **Schedule + re-bind** each VM: capacity-accounted across the batch, anti-affinity-honored, sticky; write `Spec.ClusterName`; downstream broker re-materializes (existing Phase-4 machinery).
5. **Recovery:** returning broker GCs rebound CompiledVMs → stale VMIs stop → reports `/64 drained` → central deletes that `NetworkFence` + clears the reflector entry. Un-drained /64 → fence **holds** indefinitely (fail-safe).

**Uniform fail-safe direction:** every uncertainty (fence unconfirmed, no capacity, drain unconfirmed) resolves toward *staying fenced / not re-binding* — never a speculative write.

**Idempotency:** fences are declarative (CR / blocklist entry present-or-absent); re-reconcile is safe; an already-done re-bind is a no-op.

## 7. Data flow (happy path)

```
broker (steady state) ──> ClusterPool.Status.NodePrefixes[/64...], VM.Status.Placement
        │  (heartbeat up; central holds fence coords before partition)
pool P lost (lease stale > threshold)
        │
central failover.Reconciler:
  for /64 in P.NodePrefixes: StorageFencer.NetworkFence(/64) + NetworkFencer.blocklist(/64)
  barrier: all active?  ── no ──> FailoverBlocked (no re-bind)
        │ yes
  for VM v on P:  schedule(v, healthyPools, capacity, anti-affinity) ──> Q
                  v.Spec.ClusterName = Q   (sticky re-bind)
        │
broker(Q) syncs CompiledVM ──> KubeVirt boots v on Q (sticky overlay IP re-announced)
        │
pool P recovers:
  broker(P) GC rebound CompiledVMs ──> stale VMIs stop ──> NodeDrain[/64].drained=true
central: per drained /64 ──> delete NetworkFence + clear reflector blocklist
```

## 8. Testing

- **Failover state machine (unit, fake fencers):** extend `failover_test.go` — whole-pool barrier (re-bind only after *all* /64s confirm), partial-fence-blocks, burst capacity (N VMs don't over-commit one target), anti-affinity target-selection (no co-location; only-violating → place + violation status), sticky (recovery ≠ fail-back), GC-confirmed release (drain → clear; unconfirmed → holds).
- **Reflector blocklist (unit):** suppresses reflection of routes with nexthop ∈ blocklisted /64, rejects announcements from those /64s, clears on release.
- **Fencer impls:** `StorageFencer` creates/deletes `NetworkFence` CRs against an envtest/fake Ceph-mgmt client + reads status to confirm *active*; `NetworkFencer` writes/clears the reflector blocklist.
- **Broker upward reporting (envtest):** stamps `NodePrefixes` / `Placement` / per-/64 drain.
- **Multi-cluster via multiple envtest instances (in-process integration):** stand up **several envtest apiservers** — one "central" + N "downstream" clusters — with a broker per downstream (loopback, the existing pattern). This models a real cross-cluster failover **off-fabric**: pool P's broker stops heartbeating → central fences P's /64s (fake actuators) → re-binds VMs to pool Q → Q's broker materializes them → P's broker returns and reports drain → release. Exercises the genuine multi-apiserver binding/sync/status paths a single envtest can't, without kind/qemu.
- **Single-cluster kind lab (integration gate):** central + one broker + reflector + csi-addons. Fault-inject a stale pool lease → assert whole-pool fence applied+confirmed → VM re-bound → simulated recovery drain → fence released; plus fail-safe (fence-unconfirmable → stays `FailoverBlocked`).
- **Partition dual-writer scenario, explicit:** a local Tier-1 reschedule onto a node that then gets pool-fenced → assert the fence cuts its storage + suppresses its route (no second live writer).

## 9. Scope boundaries

**In scope:** whole-pool /64 fence (both actuators real) + barrier ordering + fail-safe; capacity + anti-affinity failover scheduling; a **minimal** anti-affinity expression on `VirtualMachine.Spec` (group key + spread-across-pools); sticky re-bind; GC-confirmed release; broker upward reporting; reflector blocklist.

**Deferred:**
- Strict provisioning-gate mode (per-pool opt-in; suspends Tier-1 during partition for that pool).
- Anti-affinity **recovery rebalancer** + any fail-back.
- KubeVirt live-migration path (this is restart-based failover).
- Real multi-cluster **fabric** (cross-cluster underlay/dataplane on real hardware). The control-plane multi-cluster logic IS validated in-process via multiple envtest instances (§8); real-fabric wiring is strictly additive and deferred.
- Hardware/ConnectX; richer affinity beyond the minimal group/spread.

## 10. Success criteria

- The full test suite green, including the single-cluster kind lab fault-injection (fence → re-bind → recovery-release) and the explicit partition dual-writer scenario.
- `poolLost` → whole-pool fence (all /64s confirmed) → sticky, capacity+anti-affinity re-bind; every unconfirmed path stays `FailoverBlocked` with no `Spec` write.
- Recovery clears fences only on per-/64 GC-confirmed drain; unconfirmed drain holds the fence.
- No dataplane (eBPF) changes; Tier-1 autonomy under partition preserved.
