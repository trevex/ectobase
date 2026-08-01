# Multi-Cluster Control Plane — Central Extension Apiserver, Broker Sync, Cross-Cluster Scheduling & Failover

**Status:** Draft / Vision (brainstorm output) — architecture agreed at a high level; each phase below gets its own detailed spec + plan.
**Date:** 2026-08-01
**Supersedes/refines:** the central-control-plane decisions (D5 aggregated API, D6 distribution model) of `2026-07-02-multicluster-kubevirt-dataplane-design.md`. That vision's datapath, network model (`2026-07-02-network-api-design.md`), route distribution (`2026-07-02-route-distribution-control-plane-design.md`), and storage/mobility posture remain in force except where noted here.
**Related memory:** `[[tiered-multicluster-architecture]]`, `[[multicluster-kubevirt-platform]]`, `[[metalbond-metalnet-ipam-lineage]]`, `[[agent-reads-only-compilednic]]`, `[[compiled-nic-synthetic-testing]]`, `[[crd-rename-firewallpolicy-floatingip]]`.

---

## 1. Summary

A central cluster manages KubeVirt VM workloads across many attached clusters. The central cluster runs an **extension (aggregated) apiserver** — not a normal CRD-on-etcd apiserver — holding both the high-level tenant API and the low-level **compiled** objects the controllers produce. Each attached cluster runs **one broker** (a kubelet-analog) that syncs the compiled objects **bound to its cluster** down into local CRDs, where the existing per-node agents reconcile them into the eBPF dataplane and KubeVirt. Scheduling is modelled exactly like the Kubernetes scheduler binding a pod to a node: central sets a **cluster binding field** on each compiled object; the broker watches its own bindings by field selector. The whole system is resilient to short central outages, and cross-cluster VM rescheduling (including on host death) is a **fence-gated** operation arbitrated by central.

**One-line frame:** *the central control plane is "a Kubernetes scheduler + kubelets, where the nodes are clusters and the pods are compiled workload objects" — plus fencing, which plain k8s doesn't need but stateful cross-cluster VMs do.*

## 2. Goals / Non-goals

**Goals**
- **Central desired state without etcd blow-up:** an extension apiserver backed by a non-etcd store (kine → Postgres); high-churn live data (routes/endpoints) stays off the API entirely (on the route bus).
- **Broker sync, not fan-out watch:** central fan-out is O(clusters), not O(nodes); downstream node agents never talk to central. The compiled objects central computes are materialized as CRDs downstream.
- **Kubernetes-native scheduling semantics:** placement = binding a `spec.clusterName` field (pod→node analogy); reschedule = re-binding it.
- **Resilience to short central interruptions:** a partitioned cluster keeps running and self-heals node failures locally from its cached local CRDs.
- **Safe cross-cluster VM rescheduling on host/cluster death:** two-tier failover with external fencing (storage + overlay IP) so a stateful VM is never dual-run.
- **Single-cluster is the degenerate case**, never a separate mode (§9).

**Non-goals (for now)**
- Building cross-cluster **live** migration — consume KubeVirt Decentralized/Storage Live Migration (Alpha) later; **cold reschedule is v1**.
- Building storage — consume ceph-csi (external-cluster mode) + csi-addons NetworkFence.
- Full 3-pool disaggregation / DPU split up front — keep the `realizationPoint` API seam, defer the runtime (§8).
- Replacing the datapath, network model, or route bus — those are settled in prior specs.

## 3. Key design decisions (with rationale)

| # | Decision | Rationale |
|---|----------|-----------|
| **M1** | **Central = extension apiserver (apiserver-kit) backed by kine → Postgres** | Full k8s API ergonomics (kubectl/RBAC/informers/typed clients, selectable fields) for the high-level + compiled objects, with **no etcd anywhere** — best honours "don't blow up etcd." apiserver-kit's pluggable `RESTOptionsGetter` supports swapping the backend; kine gives correct watch/resourceVersion semantics without hand-rolling `storage.Interface`. |
| **M2** | **Per-cluster broker (kubelet-analog), not per-node fan-out** | Central sees O(clusters) connections; each broker syncs its slice down to local CRDs; node agents watch the **local** apiserver (unchanged). Bounds central load and blast radius; matches OCM klusterlet / Karmada pull-agent. |
| **M3** | **Placement = binding `spec.clusterName` (field selector), tenants = namespaces** | Faithful pod→node model. Namespaces retain their real purpose (tenant isolation). Scheduling/rescheduling are field writes — auditable, simple. Requires selectable fields (an extension-apiserver strength) + a **ClusterRestriction** authorizer for per-cluster isolation (kubelet Node-authorizer analog). |
| **M4** | **Individual compiled typed objects, synced 1:1 — no bundle/envelope** | We own the types (`CompiledNIC` today; `CompiledVM`, `CompiledVolumeAttachment` to add), so OCM-style opaque envelopes buy nothing. Per-type declarative **set-reconcile** downstream (the clear-and-write pattern from `[[crd-rename-firewallpolicy-floatingip]]`/firewall fix) gives GC; deny-by-default makes eventual consistency correct (no torn-state hazard). Grouping via a `workload=<id>` label. |
| **M5** | **Two-tier failover** | **Tier-1** (node dies, cluster healthy) = autonomous local self-heal (KubeVirt `runStrategy` + in-cluster fencing), works during central partition. **Tier-2** (cluster lost / no local capacity) = central-arbitrated, **fence-gated** cross-cluster reschedule. Keeps central off the fast path and the resilience story intact. |
| **M6** | **Fencing, not timeouts, gates cross-cluster reschedule; central is arbiter, not safety mechanism** | Heartbeat loss ≠ safe to restart a stateful VM (RWO disk + sticky overlay IP = dual-writer + dual-IP risk). Safety comes from **external fences we can assert without reaching the dead cluster**: Ceph `NetworkFence` (storage) + overlay route withdrawal (network — we own the dataplane). **Fail-safe: if fencing can't be confirmed, stay down + alert.** |
| **M7** | **Live route/endpoint churn stays on the route bus (routebus), not the API** | The compiled objects are low-churn (change on policy/placement/reschedule). The sticky-IP/global-overlay endpoint+route distribution is the high-churn path and already has a purpose-built bus (metalbond-analog); it becomes the cross-cluster overlay registry. Keeps the API store small and slow-changing. |
| **M8** | **Consume upstream for mobility & storage** | KubeVirt Decentralized/Storage Live Migration (Alpha, gate `DecentralizedLiveMigration`, Beta target ~v1.10) for the live path later; ceph-csi external-cluster + csi-addons NetworkFence for storage. We build only the network-identity cutover + the fence-gated reschedule orchestrator. |

## 4. Architecture

### 4.1 Component map (★ new · ✎ generalize existing)

```
╔══════════════════ CENTRAL CLUSTER ══════════════════╗
║ ★ Extension apiserver (apiserver-kit) → kine → Postgres         (no etcd)
║     high-level API:  VirtualMachine, Network/VPC, NetworkInterface,
║                      FirewallPolicy, FloatingIP, LoadBalancer, NATGateway,
║                      VPCPeering, Volume, ClusterPool
║     compiled API:    CompiledVM, CompiledNIC, CompiledVolumeAttachment
║                      (each has spec.clusterName — the binding)
║ ✎ Compiler            (netplane/controllers) high-level → compiled objects
║ ★ Cluster scheduler   sets compiled.spec.clusterName  (pod→node analog)
║ ★ Failover controller cluster-lease watch → Tier-2 fence-gated re-bind
║ ✎ Allocators          (netplane/allocator) VNI, NAT blocks
║ ✎ Overlay registry    (netplane/reflector + routebus) sticky-IP routes  ── M7
║ ★ ClusterRestriction  authorizer/admission (kubelet Node-authorizer analog)
╚═▲ status / cluster-lease ═══════════════ field-selector watch ▼═════════╝
  │  O(clusters) connections — one per attached cluster
┌─┴────────────────── ATTACHED CLUSTER ───────────────────┐
│ ★ Broker (kubelet-analog, HA/leader-elected)             │
│    - watch central: {CompiledVM,CompiledNIC,...} where    │
│         spec.clusterName == myCluster   (field selector)  │
│    - set-reconcile → write/delete LOCAL CRDs              │
│    - report cluster + node + VMI health up; hold lease    │
│    - Tier-1 local failover; execute fence actions         │
│ ✎ Node agent          (netplane/agent) local CompiledNIC → dataplane
│ ✎ Dataplane           (flowplane eBPF) datapath + network-fence actuator
│   KubeVirt + CDI + ceph-csi(external) + csi-addons        │
│   (opt) medik8s NHC + fencing  (Tier-1 node fencing)      │
└──────────────── UNDERLAY FABRIC (routed IPv6) ────────────┘
       carries overlay + storage traffic + shared Ceph
```

The node agent and dataplane are **unchanged in spirit**: today they read a `CompiledNIC` brokered from central; here they read a `CompiledNIC` **CRD the local broker wrote**.

### 4.2 Resource model

**High-level (tenant-facing, in tenant namespaces):**
- `VirtualMachine` — refs `NetworkInterface`(s) + `Volume`(s); carries placement intent (pool/affinity); user-facing.
- `Network`/`VPC`, `NetworkInterface`, `FirewallPolicy`, `FloatingIP`, `LoadBalancer`, `NATGateway`, `VPCPeering` — the network API (existing types, moved into the extension apiserver).
- `Volume` — shared-Ceph RBD handle + portable typed access bundle.
- `ClusterPool` — an attached cluster: capacity, health, lease, labels/taints (the "node" in the analogy).

**Compiled (controller-produced; each carries `spec.clusterName` + `workload=<vm-id>` label):**
- `CompiledVM` — denormalized KubeVirt VMI spec + volume attachment refs + placement.
- `CompiledNIC` — per-NIC static policy (firewall/NAT/LB/peering/VNI); **exists today**.
- `CompiledVolumeAttachment` — the movable Volume→node binding for the current placement.

Compiled objects are **cluster-scoped or in a system namespace on central** (they are infrastructure, not tenant objects); their tenant linkage is by owner ref/label, and downstream they land wherever the local agents expect them (as today).

### 4.3 Data flow (happy path)

1. User creates `VirtualMachine` (refs Network + Volume) in a tenant namespace on central.
2. **Compiler** resolves NICs/IPAM(underlay)/firewall/NAT → produces `CompiledVM` + `CompiledNIC`(s) + `CompiledVolumeAttachment`, initially unbound (`spec.clusterName == ""`).
3. **Scheduler** picks a `ClusterPool` and sets `spec.clusterName` on all of the workload's compiled objects (one labelled update).
4. That cluster's **broker** (only) matches them via its field-selector watch → **set-reconcile** writes the corresponding local CRDs into the attached cluster.
5. **Node agent** reconciles the local `CompiledNIC` → programs the eBPF dataplane. **Broker** creates the KubeVirt VMI and rbd-refs the shared Ceph volume.
6. The node's dataplane registers the VM's overlay IP on the **route bus**; the global overlay converges — the VM boots with a sticky IP independent of cluster/node.

### 4.4 Scheduling & the binding model (M3)

- **Central scheduler = kube-scheduler analog.** Inputs: `ClusterPool` capacity/health (reported by brokers), tenant/affinity/anti-affinity, `realizationPoint` requirements. Output: `spec.clusterName` on the workload's compiled objects. Node-level placement is delegated to the **local** kube-scheduler/KubeVirt in the chosen cluster.
- **Broker = kubelet analog.** One field-selector watch per compiled type (`spec.clusterName == me`); declarative set-reconcile to local CRDs (create/update/delete to exactly match the bound set → GC for free).
- **Isolation = ClusterRestriction authorizer/admission** (kubelet Node-authorizer + NodeRestriction analog): a broker authenticating as cluster X may read only objects bound to X and may write only their status (never re-bind itself, never read another cluster's objects). This is the cost of the field-binding model over per-namespace RBAC, and is well-precedented.

### 4.5 Two-tier failover & fencing (M5, M6)

**Detection:** each broker holds a **cluster lease** to central and reports node/VMI health. Central marks a `ClusterPool` `Unknown` when its lease goes stale (conservative, ~minutes, anti-flap). A broker also surfaces *individual* node death within a healthy cluster.

**Tier-1 — node dies, cluster healthy (autonomous, central-independent):**
- In-cluster: medik8s NHC + fencing (BMC/watchdog) confirms the node is dead; KubeVirt `runStrategy` (`RerunOnFailure`) restarts the VM on another local node; the local `CompiledVolumeAttachment` controller re-maps the RBD after storage fence; the node agent reprograms the dataplane; the route bus re-registers the sticky IP at the new node.
- Works while central is unreachable. Central is informed via status when reachable.

**Tier-2 — cluster lost / no local capacity (central-arbitrated, fence-gated):**
1. Central observes stale `ClusterPool` lease (or a broker "no local capacity" signal).
2. **Fence from outside the cluster** (does not require reaching it): Ceph `NetworkFence` on the old node/cluster IPs **and** withdraw the sticky-IP route(s) in the overlay (central controls the dataplane/route bus).
3. Only when **both** fences are confirmed, the failover controller **re-binds** `spec.clusterName` to a healthy `ClusterPool`.
4. Target broker materializes local CRDs → starts the VM re-referencing the same RBD → route bus re-registers the IP at the new location.
5. **Fail-safe:** if either fence cannot be confirmed, **do not re-bind** — surface an alert and stay down. Availability loss is recoverable; dual-writer/dual-IP corruption is not.

**The partition dilemma, resolved:** central being unreachable to cluster A does not block safety, because the fences act on the storage backend and the overlay — both reachable from central independent of cluster A's k8s API. Central is the *decision arbiter*; the *safety invariant* ("at most one instance holds the disk + IP") is enforced by the fences, not by central's liveness.

### 4.6 Storage & mobility (M8)

- **Storage:** single shared external Ceph reachable from all clusters (v1 assumption); disk = RBD image; ceph-csi external-cluster mode; cross-cluster move = **re-reference the same RBD** (cheap; no copy).
- **Fencing:** csi-addons `NetworkFence` (RBD blocklist; CephFS eviction where needed).
- **Cold reschedule is v1.** Pin MAC in the VM spec; overlay owns the IP; cloud-init idempotent.
- **Live path deferred:** consume KubeVirt Decentralized/Storage Live Migration behind its Alpha gate; our contribution is the sticky-IP cutover the feature explicitly does not provide.

### 4.7 Resilience / partition semantics

- Steady-state reconcile is **local**: node agents reconcile local CRDs; VMs keep running; **Tier-1 failover still works** — all independent of central.
- During a central partition, what pauses: new scheduling, Tier-2 reschedule, fresh central status, authoring new desired state for that cluster (queued centrally until reconnect).
- On reconnect: broker delta-syncs to current bound set (set-reconcile), buffered status flushes upward.
- Durability: the broker's applied-state is anchored by the **local CRDs themselves + finalizers**, never in-memory (the `appliedFw`/Karmada-#5406 restart-fragility lesson) — a broker restart re-derives from the local CRDs + the central bound set.

## 5. Component boundaries (units, for isolation/testability)

- **Extension apiserver (types + storage wiring)** — apiserver-kit scheme, selectable `clusterName` field, kine/Postgres backend. Testable via envtest against the aggregated server.
- **Compiler** — pure high-level→compiled function (extends today's `Compile`), unit-testable with fakes; no cluster I/O.
- **Scheduler** — `ClusterPool` + compiled-object binding; pure placement function + a thin controller. Testable with synthetic pools.
- **Failover controller** — lease→fence→re-bind state machine; the fence actuators are injected interfaces (storage-fence, network-fence) so it's testable without a real Ceph/dataplane.
- **Broker (kubelet-analog)** — field-selector watch + per-type set-reconcile + lease/status; the "sync engine." Testable with a fake central + a local envtest.
- **ClusterRestriction authorizer/admission** — pure authorization decision; unit-testable.
- **Node agent / dataplane / route bus** — **unchanged**; consume local CRDs + register endpoints (existing, already tested).

Each unit has one job and a typed interface; the fence actuators and the central/local clients are the seams that keep the failover + broker logic testable off-fabric.

## 6. Testing strategy

- **Unit:** compiler, scheduler placement, failover state machine (injected fence actuators), set-reconcile GC, ClusterRestriction decisions.
- **Envtest:** extension apiserver types + selectable field watch; broker set-reconcile against a real in-process apiserver (both central and local).
- **Single-cluster kind lab (standing gate, §9):** central + broker (loopback) + node agent + dataplane in one cluster; a VM boots on the overlay. Every phase passes here first.
- **Multi-cluster clab fabric:** 2–3 kind clusters on the IPv6 fabric; cross-cluster schedule, then cross-cluster **cold reschedule with fencing** e2e (the acceptance milestone).
- **Fault injection:** central partition (steady-state + Tier-1 survive); cluster-lease-stale → Tier-2 fence-gated reschedule; fence-unconfirmable → fail-safe stay-down.

## 7. Security

- **No central write-creds into attached clusters** — brokers pull; central never holds spoke admin creds (M2).
- **ClusterRestriction** bounds each broker to its own bound objects + status-only writes (M3/§4.4).
- **Tenant isolation** via namespaces (high-level) + VNI/overlay + per-tenant IPAM (datapath, existing).
- **Dynamic, tenant-scoped storage secrets** delivered at attach, revoked (+ fenced) on detach/reschedule.
- **Fencing on handoff** prevents split-brain writes (M6).

## 8. Relationship to the 2026-07-02 vision

This spec **refines the central control plane** of `2026-07-02-multicluster-kubevirt-dataplane-design.md`:
- **D5 (aggregated API)** → sharpened to **kine/Postgres backing (no etcd)** + selectable-field scheduling (M1, M3).
- **D6 (uniform pull poollets, central rendezvous)** → **kept and made precise**: the poollet is the per-cluster broker; "assigned to its pool" = `spec.clusterName` binding; rendezvous stays central. (Not a reversal — a concretization.)
- **Disaggregation (D2/D8, 3 pools + DPU)** → **north star retained**; v1 runs **co-located compute+dataplane + shared Ceph**, keeps the `realizationPoint ∈ {host,smartnic,dpu}` seam, defers DPU runtime.
- Network model, route distribution, storage/mobility, single-cluster invariant → **unchanged**.

## 9. Single-cluster invariant (cross-cutting)

Single-cluster is the degenerate case: central apiserver + one broker (watching the local aggregated apiserver via loopback) + compute + dataplane co-located. The binding model, set-reconcile, and Tier-1 failover all collapse cleanly; multi-cluster (extra clusters, cross-cluster fabric, ClusterRestriction across trust boundaries, Tier-2) is strictly additive. **Every phase must pass in a one-cluster kind lab before any multi-cluster wiring.**

## 10. How we get there (phased roadmap, builds on existing code)

Each phase is its own spec → plan → implementation cycle; each satisfies §9 first.

1. **Central extension apiserver.** Stand up apiserver-kit + kine/Postgres; move the high-level network types + `CompiledNIC` into it; add `CompiledVM`/`CompiledVolumeAttachment` and the `clusterName` selectable field; run the existing compiler against it. *(single cluster; envtest)*
2. **Broker (kubelet-analog) + local materialization.** Field-selector watch → per-type set-reconcile → local CRDs + finalizers; node agent reads local CRDs (as today). *(loopback single cluster, then 2 clusters on the clab fabric)*
3. **ClusterPool + lease/health + scheduler.** Broker reports capacity/health + holds a lease; central scheduler binds `spec.clusterName`. **ClusterRestriction** authorizer/admission.
4. **KubeVirt VM lifecycle via broker + shared-Ceph volume + sticky IP.** Broker creates VMIs; `CompiledVolumeAttachment` → rbd map; route bus extended to the cross-cluster overlay registry (sticky IP across clusters).
5. **Two-tier failover + fencing.** Tier-1 (medik8s + `runStrategy`) local; Tier-2 central failover controller with Ceph `NetworkFence` + overlay route-withdraw actuators; fail-safe.
6. **Cross-cluster cold reschedule e2e** on the clab fabric (the acceptance milestone) + partition fault-injection.
7. **(Additive, later)** DPU `realizationPoint` + full 3-pool disaggregation; KubeVirt DLM live path behind its gate; north-south gateways; Cluster-API-managed cluster attachment.

## 11. Open questions / deferred

- **Route bus at cross-cluster scale** — federated/regional reflectors vs a single global registry; the central scalability risk carried over from the 2026-07-02 vision (§4.4 there).
- **apiserver-kit maturity** — pre-1.0; validate its `RESTOptionsGetter`/kine wiring and selectable-field support by reading source before committing (research flagged the repo path was unconfirmed).
- **ClusterRestriction implementation** — custom authorizer + admission webhook vs a lighter token-scoping scheme.
- **Fence coverage gaps** — environments without external storage/overlay fencing get **Tier-1 only** (no automatic Tier-2 for RWO VMs); make this explicit per `ClusterPool`.
- **CephFS fencing** (eviction) is newer than RBD blocklist — validate if RWX state PVCs are needed (KubeVirt live DLM requires them).
- **Compiler placement coupling** — does the compiler run fully before scheduling (unbound compiled objects) or partly after (some fields need the target cluster's node-local facts, e.g. underlay)? Underlay is node-local today; confirm which compiled fields are placement-independent vs resolved downstream by the agent.
- **Scheduler scope** — single central scheduler vs pluggable/multi-scheduler; HA of the central controllers.

## 12. Glossary

- **Broker** — the per-cluster kubelet-analog: field-selector watch on central + set-reconcile to local CRDs + lease/health + Tier-1 failover + fence execution.
- **Binding** — `compiled.spec.clusterName`; set by the central scheduler (placement) / failover controller (reschedule).
- **ClusterPool** — an attached cluster as a schedulable capacity domain (the "node").
- **Compiled object** — a controller-produced, denormalized low-level desired-state object (`CompiledVM`/`CompiledNIC`/`CompiledVolumeAttachment`).
- **ClusterRestriction** — the authorizer/admission bounding a broker to its own bound objects (kubelet Node-authorizer analog).
- **Tier-1 / Tier-2 failover** — local-autonomous vs central-arbitrated-fence-gated.
- **Fence** — externally-asserted exclusion of a lost instance from storage (Ceph NetworkFence) and network (overlay route withdrawal) to prevent split-brain.
