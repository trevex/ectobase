# Phase 3 — Cluster Scheduler, Lease/Health, Tier-2 Failover Skeleton, ClusterRestriction

**Status:** Design (brainstorm output) — approved for planning.
**Date:** 2026-08-02
**Phase of:** `docs/superpowers/specs/2026-08-01-multicluster-control-plane-design.md` (roadmap step 3 + a skeleton of step 5).
**Builds on:** Phase 1 (central aggregated apiserver), Phase 2 (broker sync), Phase 1b (net types in central + compiler binds `CompiledNIC.spec.clusterName` from the owning `VirtualMachine`). See memory `[[central-apiserver-foundation]]`, `[[phase1b-net-types-central]]`.
**Related memory:** `[[multicluster-kubevirt-platform]]`, `[[tiered-multicluster-architecture]]`, `[[agent-reads-only-compilednic]]`.

---

## 1. Summary

Central becomes "a kube-scheduler + kubelets, where the nodes are clusters and the pods are workloads." A **scheduler** binds `VirtualMachine.spec.clusterName` to a `ClusterPool`; Phase 1b's existing chain (VM watch → compiler recompiles `CompiledNIC` with the bound `clusterName` → broker syncs downstream) propagates the placement with **zero datapath/compiler/broker-sync changes**. To make placement real, the per-cluster **broker heartbeats a lease** and reports **capacity** up into its `ClusterPool.Status` (the first upward status flow); a **pool-health controller** turns lease freshness into `Ready`/`Unknown`. A **Tier-2 failover controller** is built as a state machine — a pool going `Unknown` triggers a **fence-gated re-bind** through **injected fence actuators**, failing safe if fences can't be confirmed (real Ceph/overlay actuators + Tier-1 local self-heal are Phase 4+). A **thin ClusterRestriction admission** bounds a broker identity to writing only its own pool's status and forbids it from re-binding `spec.clusterName`.

**One-line frame:** *bind the VM to a healthy, capacity-fitting cluster; keep the binding honest with a broker lease; and stand up the fence-gated failover state machine (fail-safe) ahead of the real actuators.*

## 2. Goals / Non-goals

**Goals**
- **Scheduler:** bind `VirtualMachine.spec.clusterName` from `ClusterPool` health + capacity + an optional pool selector (pod→node analog; a direct spec write).
- **Lease/health:** the broker heartbeats `ClusterPool.Status.Lease` + reports `Status.Allocatable`; a pool-health controller derives `Ready`/`Unknown` from lease freshness.
- **Capacity:** a generic k8s-native resource model (`corev1.ResourceList`) so cpu/memory/gpu/etc. all work; the scheduler does real resource-fit.
- **Tier-2 failover skeleton:** a fence-gated re-bind state machine against **injected** fence actuators, **fail-safe** when fences are unconfirmable; unit- and envtest-covered.
- **ClusterRestriction (thin):** admission that bounds a broker identity to its own pool's status and forbids `spec.clusterName` writes.
- **Single-cluster gate:** a chained envtest (broker heartbeat → pool `Ready` → VM scheduled → `CompiledNIC` propagates), extending the Phase-1b e2e.

**Non-goals (this phase)**
- Real fence actuators (Ceph `NetworkFence`, overlay route-withdrawal) and Tier-1 local self-heal (medik8s + KubeVirt `runStrategy`) — **Phase 4+** (need the VM lifecycle + external storage). Phase 3 ships **injected interfaces + a fail-safe default**.
- KubeVirt VMI lifecycle / real workload movement — a rebind changes `spec.clusterName`; no VMI actually relocates yet (Phase 4).
- The **full** Node-authorizer/graph ClusterRestriction + real broker cert/token issuance — thin admission + an impersonation-testable identity convention only.
- Served `coordination.k8s.io` Leases — the lease is a `ClusterPool.Status` field.
- Container-workload placement — the scheduler binds **VMs**; container NICs keep the compiler `--cluster-name` default until the future container workload type.

## 3. Key design decisions (with rationale)

| # | Decision | Rationale |
|---|----------|-----------|
| **S1** | **Scheduler binds `VirtualMachine.spec.clusterName` (not the compiled objects)** | Reuses the Phase-1b seam: the compiler already inherits `clusterName` from the owning VM and recompiles `CompiledNIC` on VM change. The scheduler works at the workload level; everything downstream propagates for free. |
| **S2** | **Lease = `ClusterPool.Status.Lease{HolderIdentity, RenewTime}` heartbeat field** | Simplest; co-locates health with the pool; no new served group. `coordination.k8s.io` isn't served and isn't needed. Stale `RenewTime` is the health/failover trigger. |
| **S3** | **Capacity = native `corev1.ResourceList` / `corev1.ResourceRequirements`** | Generic and extensible (cpu/memory/`nvidia.com/gpu`/…) exactly like k8s, zero custom types, deepcopy/marshal already provided, openapi already wired (`update-codegen.sh` already `--extra-pkgs "k8s.io/api/core/v1"`). |
| **S4** | **Allocated is derived, not stored** | The scheduler/failover compute `allocated[r] = Σ(bound VMs' Requests[r])` by listing VMs bound to a pool — always consistent, no drift, no second writer to the pool. Only `Allocatable` is stored (reported by the broker). |
| **S5** | **Failover is a Tier-2 state machine against injected `Fencer`; fail-safe default** | The orchestration (lease-stale → fence → re-bind → fail-safe) is the real, testable deliverable; the actuators are seams (vision §5). The default `Fencer` denies (stay down) so the skeleton is safe if wired to prod before real actuators exist. |
| **S6** | **Thin ClusterRestriction admission keyed on `ectobase:cluster:<name>`** | Covers the core safety invariant (a broker can't spoof another cluster's health or re-bind itself) without a full graph authorizer. Identity is a username convention, **testable via client impersonation** now; real cert/token issuance is a deploy concern (deferred). |
| **S7** | **Direct `spec.clusterName` write, not a Binding subresource** | Simpler than the kube-scheduler `pods/binding` mechanism; sufficient for our single-writer scheduler. Revisit if multiple schedulers or audit needs arise. |
| **S8** | **Two thresholds: `healthStale` (→`Unknown`, scheduler stops picking it) < `failoverThreshold` (→ Tier-2 rebind)** | Anti-flap (vision §4.5: "conservative, ~minutes"). A brief central↔broker partition degrades a pool to `Unknown` (no new placements) long before it triggers a destructive rebind. |

## 4. Architecture

### 4.1 Component map (★ new · ✎ extend)

```
╔════════════ CENTRAL (aggregated apiserver + controllers) ════════════╗
║  types:  ✎ ClusterPool.Status (+Lease, +Allocatable ResourceList; Phase Ready/Unknown)
║          ✎ VirtualMachine.Spec (+Resources ResourceRequirements, +PoolSelector)
║          ✎ VirtualMachine.Status (+Conditions: Scheduled/Unschedulable/FailoverBlocked)
║  ★ scheduler        central/internal/scheduler  — pure Schedule() + VM controller
║  ✎ pool-health      central/internal/clusterpool — lease freshness → Ready/Unknown
║  ★ failover (Tier-2)central/internal/failover   — pure state machine + Fencer seam
║  ★ ClusterRestriction admission — bounds ectobase:cluster:<name> writes
╚═▲ Status().Update (lease + capacity) ═══════════ VM.spec.clusterName write ▼═╝
  │
┌─┴ BROKER (per cluster) ─────────────────────────────────────────────┐
│  ✎ heartbeat Runnable — renew ClusterPool.Status.Lease + Allocatable  │
│     via injected CapacityReporter (real: sum downstream Ready nodes)  │
│  (existing) SyncOnce pull — unchanged                                 │
└──────────────────────────────────────────────────────────────────────┘
```

### 4.2 Types

- **`ClusterPool.Status`** (platform group, `central/apis/platform`): add
  - `Allocatable corev1.ResourceList` — total schedulable capacity, reported by the broker.
  - `Lease ClusterPoolLease{ HolderIdentity string; RenewTime metav1.MicroTime }` — heartbeated by the broker.
  - `Phase`: `Pending` (never reported) → `Ready` (lease fresh) → `Unknown` (lease stale). Keep `Conditions` (`Ready`).
- **`VirtualMachine.Spec`** (net group, `api/v1alpha1` + `central/apis/net`): add
  - `Resources corev1.ResourceRequirements` (optional; `.Requests` used for fit, `.Limits` for parity/future).
  - `PoolSelector *metav1.LabelSelector` (optional; matched against `ClusterPool` labels).
- **`VirtualMachine.Status`**: add `Conditions []metav1.Condition` (`Scheduled`, `Unschedulable`, `FailoverBlocked`).
- Codegen: platform types use their real internal↔versioned codegen; net types (VirtualMachine) use the Phase-1b alias + **hand-written conversion** + fuzzer pattern (`[[phase1b-net-types-central]]`). `corev1` types need no new conversion (shared apimachinery type).

### 4.3 Scheduler (`central/internal/scheduler`)

- **Pure core** `Schedule(vm, pools []ClusterPool, boundReqs map[poolName][]ResourceList) (pool string, reason string, ok bool)`:
  - **Filter:** `pool.Status.Phase == Ready` **∧** `PoolSelector` matches `pool.Labels` (if set) **∧** resource-fit — for every resource `r` in `vm.Spec.Resources.Requests`: `Σ(boundReqs[pool][*][r]) + vmReq[r] ≤ pool.Status.Allocatable[r]` (a requested resource the pool doesn't advertise ⇒ no fit).
  - **Score:** most-free — the pool whose **minimum free fraction** across the VM's requested resources is highest (spreads load; a VM with no requests scores by pool emptiness). Deterministic tie-break: lowest pool name.
  - Returns `ok=false` + a human reason when nothing fits.
- **Controller:** watches `VirtualMachine`; on an unbound VM (`spec.clusterName == ""`): list `ClusterPool`s + the VMs already bound to each (for `boundReqs`), run `Schedule`; on success write `spec.clusterName` + set `Scheduled` condition; on failure set `Unschedulable` condition + requeue. Also watches `ClusterPool` (a newly-`Ready`/newly-freed pool re-triggers pending unschedulable VMs).

### 4.4 Broker heartbeat (`central/cmd/broker` + `central/internal/broker`)

- A manager `Runnable` on a `renewInterval` ticker: `heartbeatOnce(ctx)` → Get the broker's own `ClusterPool` (name == `--cluster-name`), set `Status.Lease.RenewTime = now`, `Status.Lease.HolderIdentity = <broker id>`, `Status.Allocatable = CapacityReporter.Report(ctx)`, `Status().Update`.
- **`CapacityReporter` interface** (injected): real impl sums `Allocatable` across `Ready` downstream `corev1.Node`s; test impl returns a static `ResourceList`. Keeps the heartbeat testable off-cluster.
- Existing `SyncOnce` pull path unchanged. `KUBE_FEATURE_WatchListClient=false` retained.

### 4.5 Pool-health controller (`central/internal/clusterpool`)

Extend the existing reconciler: derive `Phase` from lease freshness — `RenewTime` within `healthStale` ⇒ `Ready` (+`Ready` condition True); older ⇒ `Unknown` (+`Ready` condition False, reason `LeaseExpired`); never reported ⇒ `Pending`. Requeue after `healthStale` so staleness is detected without an event.

### 4.6 Failover controller — Tier-2 skeleton (`central/internal/failover`)

- Watches `ClusterPool`s (+ periodic requeue). A pool `Unknown` for longer than `failoverThreshold` (> `healthStale`) is **lost**.
- **Pure state machine** per VM bound to a lost pool:
  1. **Fence** via injected `Fencer{ FenceStorage(ctx, vm) error; FenceNetwork(ctx, vm) error }`.
  2. **Both confirmed →** re-bind: run the scheduler's pure `Schedule` **excluding the lost pool**; set `vm.spec.clusterName = newPool`; set `Scheduled` condition (reason `FailedOver`).
  3. **Either fence errs →** fail-safe: do **not** rebind; set `FailoverBlocked` condition + emit an event; leave the VM bound to the lost pool.
- **Default `Fencer` = deny** (both methods return an error) so an un-wired failover controller stays safe. A **test `Fencer`** (confirm / deny variants) drives the unit + envtest. Real Ceph/overlay actuators are Phase 4+.
- No conflict with the scheduler: the scheduler only touches **unbound** VMs; the failover controller owns re-binding VMs on lost pools and writes the new pool directly (no transient-unbound window).

### 4.7 ClusterRestriction — thin admission

- **Identity convention:** a broker authenticates as username `ectobase:cluster:<name>` (real issuance deferred; **tested via client impersonation**).
- **Admission decision** (for requests whose user matches `ectobase:cluster:<name>`):
  - `ClusterPool` writes: allowed **only** for the pool named `<name>` **and only** the status subresource; reject writes to other pools and non-status writes.
  - **Any object:** reject a create/update that **sets or changes `spec.clusterName`** (a broker may not bind/re-bind).
  - Everything else from that identity: unaffected (this is the thin slice, not a full read-authorizer).
- Non-broker identities (scheduler/failover controllers, admin) are unrestricted.
- **Spike:** confirm apiserver-kit exposes custom admission-plugin registration on its builder; if not, fall back to a validating admission webhook served by central. De-risk with one path before wiring the full rule set.

### 4.8 Data flow

**Happy path:** broker heartbeat → `ClusterPool.Status.Lease` fresh → pool-health sets `Ready` → user creates unbound `VirtualMachine` → scheduler fits + binds `spec.clusterName` → (Phase 1b) compiler recompiles `CompiledNIC` → broker syncs downstream.

**Failure path:** broker stops heartbeating → `RenewTime` stale → pool `Unknown` (scheduler stops picking it) → after `failoverThreshold` → failover fences (injected); both confirm → rebind to another `Ready` pool; else `FailoverBlocked` + stay.

## 5. Component boundaries (units)

- **Types** — additive Status/Spec fields; unit: fuzz roundtrip (net) + build.
- **`Schedule` (pure)** — filter/fit/score; unit: synthetic pools/VMs table (fit, gpu-missing, selector, spread, tie-break, unschedulable).
- **Scheduler controller** — thin; envtest: unbound VM → bound.
- **`heartbeatOnce` + `CapacityReporter`** — unit with a fake pool client + static reporter; the real node-sum reporter is a thin adapter.
- **Pool-health** — pure `phaseFromLease(now, lease, healthStale)`; unit table.
- **Failover state machine** — pure `decide(pool, vms, now) → actions` + the `Fencer` seam; unit: confirm→rebind, deny→FailoverBlocked, not-yet-threshold→noop.
- **ClusterRestriction admission** — pure `review(userInfo, req) → allow/deny+msg`; unit table + envtest via impersonation.

## 6. Testing strategy

- **Unit:** `Schedule` (fit incl. gpu-absent, selector, spread scoring, tie-break, unschedulable); `phaseFromLease`; failover `decide` (confirm/deny/below-threshold); admission `review` (own-pool-status ok, other-pool deny, non-status deny, spec.clusterName deny, non-broker unaffected); `heartbeatOnce`.
- **Envtest (central-aggregated):** broker heartbeat writes lease+capacity → pool `Ready`; unbound VM → scheduler binds `spec.clusterName`; pool goes stale → failover (confirming `Fencer`) rebinds / (denying `Fencer`) sets `FailoverBlocked`; impersonated `ectobase:cluster:c1` client blocked from writing c2's pool status and from setting `spec.clusterName`.
- **Single-cluster gate (chained e2e, extends Phase-1b):** one broker heartbeats its `ClusterPool` → pool `Ready` → create an unbound VM (+ its NIC) → scheduler binds → compiler emits a `CompiledNIC` with the bound `clusterName` → broker syncs downstream. Proves scheduler→compiler→broker end to end.

## 7. Migration & compatibility

- All type changes are **additive** (new optional Spec/Status fields); existing objects and the datapath are unaffected. `CompiledNIC`/broker sync are unchanged (the scheduler operates one level up, on the VM).
- The compiler's `--cluster-name` default stays for **VM-less** NICs; a VM's NICs now get their `clusterName` from the **scheduler-bound VM** (previously a manually-set VM field).
- New controllers register on the existing central controller manager (`central/cmd/controller`); the broker gains a heartbeat Runnable. `central/go.mod` local replaces (kit, api, netplane) unchanged.
- `KUBE_FEATURE_WatchListClient=false` on every central-aggregated informer (Phase-1 carry-over) — now also the scheduler/failover/pool-health controllers.

## 8. Risks & mitigations

- **Admission wiring in apiserver-kit (biggest unknown).** In-process admission-plugin registration may not be exposed. Mitigation: **spike one type first**; fall back to a validating webhook. Keep the decision logic in a pure `review()` so the transport is swappable.
- **`corev1` in the aggregated schema.** Status/Spec now embed `corev1.ResourceList`/`ResourceRequirements`. Mitigation: openapi already `--extra-pkgs "k8s.io/api/core/v1"`; verify CRD + aggregated-schema generation early (the VirtualMachine CRD and the served openapi must render the resource maps).
- **Scheduler/failover write contention on `spec.clusterName`.** Mitigation: disjoint ownership (scheduler = unbound only; failover = lost-pool bound VMs); optimistic-concurrency retries on conflict.
- **Flapping pools.** Mitigation: two thresholds (S8); failover is conservative and fail-safe.
- **Derived-allocated cost.** Listing bound VMs per schedule is O(VMs); fine at this scale. Mitigation: a field index on `spec.clusterName` for VMs if needed (the pattern already exists for CompiledNIC).
- **Hollow failover.** No VMI moves yet (Phase 4). Mitigation: scope is explicit; the state machine + fail-safe + injected seams are the deliverable and are fully tested.

## 9. Single-cluster invariant

Single-cluster is the degenerate case (vision §9): one `ClusterPool`, one broker heartbeating it, the scheduler binding every VM to that sole pool, failover never triggering (pool stays `Ready`). The chained e2e (§6) is the standing gate; multi-cluster placement/failover across real clusters is additive.

## 10. Task shape (for the plan)

1. **Types:** `ClusterPool.Status` (+Lease, +Allocatable), `VirtualMachine.Spec` (+Resources, +PoolSelector) + `Status.Conditions`; regen api deepcopy/CRDs + central codegen (net hand-conversions + fuzzer; platform codegen).
2. **Broker heartbeat + `CapacityReporter`** (TDD): `heartbeatOnce` + Runnable + real node-sum reporter; unit + wire into `cmd/broker`.
3. **Pool-health** (TDD): `phaseFromLease` + extend the clusterpool controller; unit + envtest (heartbeat → Ready → stale → Unknown).
4. **Scheduler** (TDD): pure `Schedule` + controller; unit table + envtest (unbound VM → bound).
5. **Failover Tier-2 skeleton** (TDD): pure `decide` + `Fencer` seam + default-deny + controller; unit + envtest (confirm→rebind, deny→FailoverBlocked).
6. **ClusterRestriction thin admission:** spike the apiserver-kit admission seam; pure `review` + wire; unit + impersonation envtest.
7. **Chained single-cluster e2e + wrap:** heartbeat→Ready→schedule→compile→sync; memory; finish branch.

Sequential git; per-task spec + quality review; branch off main.

## 11. Open questions / deferred

- **Real fence actuators + Tier-1** (medik8s/`runStrategy`, Ceph `NetworkFence`, overlay route-withdraw) — Phase 4+ (need the VM lifecycle + storage).
- **Full ClusterRestriction** (read-authorizer + real broker identity issuance) — follow-up; thin admission covers writes now.
- **Scheduler sophistication** — bin-packing vs spread, affinity/anti-affinity, multi-scheduler, preemption — start with fit + spread.
- **`ClusterPool.Status.Allocated` for observability** — currently derived; add if a UI needs it.
- **Served `coordination.k8s.io` Leases** — if leader-election-style semantics are later wanted for the broker.
- **HA of the central controllers** — leader election among central controller replicas.
