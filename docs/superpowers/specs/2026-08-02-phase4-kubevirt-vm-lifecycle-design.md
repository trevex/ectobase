# Phase 4 — KubeVirt VM Lifecycle (containerDisk) via CompiledVM + Downstream Materializer

**Status:** Design (brainstorm output) — approved for planning.
**Date:** 2026-08-02
**Phase of:** `docs/superpowers/specs/2026-08-01-multicluster-control-plane-design.md` (roadmap step 4, VM-lifecycle slice — Ceph storage + cross-cluster sticky-IP deferred).
**Builds on:** Phase 1b (net types in central + compiler binds `spec.clusterName`), Phase 2 (broker sync), Phase 3 (scheduler + VirtualMachine placement). See memory `[[phase1b-net-types-central]]`, `[[phase3-scheduler-failover]]`, `[[kubevirt-vm-primary-network-tap]]`.

---

## 1. Summary

A high-level `VirtualMachine` (placement anchor since Phase 1b, scheduled since Phase 3) now boots a real VM. The compiler produces a **`CompiledVM`** — a denormalized, node-local-fact-resolved boot intent carrying `spec.clusterName` exactly like `CompiledNIC`. The broker syncs `CompiledVM` down into the attached cluster; a new **downstream vm-materializer** turns it into a `kubevirt.io/v1.VirtualMachine`. The VM boots from a **containerDisk image** (no Ceph this phase); `runStrategy: RerunOnFailure` delivers Tier-1 local restart. The VM's overlay IP is announced on the route bus by the existing agent (per-cluster sticky IP). Storage-mobility (Ceph RBD) and cross-cluster sticky-IP are deferred to later phases.

**One-line frame:** *compile the scheduled VirtualMachine into a `CompiledVM`, sync it down like a `CompiledNIC`, and let a downstream materializer boot it as a KubeVirt VM — containerDisk now, Ceph later.*

## 2. Goals / Non-goals

**Goals**
- **`CompiledVM`** compiled type (net.ectobase.dev), produced by the compiler from a scheduled `VirtualMachine`, carrying the `spec.clusterName` binding + `workload` label (Phase-1b pattern).
- **Broker** syncs `CompiledVM` central→downstream (a second synced type alongside `CompiledNIC`).
- **Downstream vm-materializer** reconciles local `CompiledVM` → `kubevirt.io/v1.VirtualMachine` (containerDisk boot, cpu/mem, pinned-MAC interface on the flowplane NAD, `runStrategy`).
- **Tier-1 (partial):** `runStrategy: RerunOnFailure` for KubeVirt-native VMI restart on node death.
- **Fully envtest-gated control plane:** central serves `CompiledVM`; broker loopback syncs it; the materializer builds a correct KubeVirt `VirtualMachine` against installed KubeVirt CRDs (no running virt-controller).
- **`kubevirt.io/api` isolated to `netplane`** (the materializer); central stays KubeVirt-free.

**Non-goals (this phase)**
- **Ceph/RBD storage + `Volume`/`CompiledVolumeAttachment` + cross-cluster volume mobility** — a later phase (needs external Ceph). containerDisk (ephemeral) is the boot source now.
- **Cross-cluster sticky-IP / route-bus federation** — later; the existing per-cluster overlay announcement is unchanged.
- **Real KubeVirt boot, live migration, live Tier-1 (medik8s NHC fencing), Tier-2 real fence actuators** — infra-gated; deferred acceptance milestones.
- **Full VMI spec surface** (device passthrough, GPUs, cloud-init beyond a minimal hook, instancetypes) — minimal bootable VM this phase.

## 3. Key design decisions (with rationale)

| # | Decision | Rationale |
|---|----------|-----------|
| **K1** | **`CompiledVM` is a net.ectobase.dev compiled type (Phase-1b pattern)** | Mirrors `CompiledNIC`: the compiler produces it with `spec.clusterName` from placement; the broker field-selects + syncs it; a downstream consumer materializes. Reuses the proven shared-versioned + hand-conversion + fuzzer + serve machinery. |
| **K2** | **containerDisk boot (image string), no Ceph** | Decouples the VM-materialization mechanism from the storage-mobility story. A containerDisk VM boots from an image with zero external storage — fully testable now. Ceph RBD + mobility is a coherent separate phase. |
| **K3** | **Broker-syncs-CRD + downstream materializer (not broker-creates-KubeVirt)** | Keeps the broker a generic sync engine (CompiledNIC + CompiledVM, both net CRDs); the KubeVirt coupling lives in one downstream component. Consistent with CompiledNIC's broker-syncs / agent-materializes split. Both halves stay envtestable. |
| **K4** | **`kubevirt.io/api` only in `netplane`** | Only the materializer touches KubeVirt. central serves `CompiledVM` (a net type), not KubeVirt objects, so it needs no KubeVirt dep. Keeps the aggregated-apiserver build lean. |
| **K5** | **Materializer is a new downstream binary (`netplane/cmd/vm-materializer`)** | It's cluster-level (creates a KubeVirt `VirtualMachine`, which KubeVirt then schedules to a node) — distinct from the node-local agent. Its own controller-runtime manager on the downstream config. |
| **K6** | **`runStrategy: RerunOnFailure` default → Tier-1 for free** | KubeVirt natively restarts the VMI on another node when its node dies. Delivers the Tier-1 self-heal by setting a field; full node-fencing (medik8s) is deferred. |
| **K7** | **Materializer creates a KubeVirt `VirtualMachine` (not a bare VMI)** | The `VirtualMachine` object owns `runStrategy` (Tier-1) + lifecycle; KubeVirt manages the VMI beneath it. |
| **K8** | **Interface wiring: pinned MAC + flowplane NAD via multus + the KubeVirt tap binding** | The overlay is the VM's primary network via the flowplane binding NAD (`config/deploy/kubevirt-binding.yaml`, domainAttachmentType=tap). The compiler resolves each `InterfaceRef`→NIC MAC; the materializer wires `spec.template.spec.domain.devices.interfaces[]` (macAddress + binding) + `networks[]` (multus: the NAD). See `[[kubevirt-vm-primary-network-tap]]`. |

## 4. Architecture

### 4.1 Component map (★ new · ✎ extend)

```
CENTRAL (aggregated apiserver + controllers)
  ✎ VirtualMachine.Spec           +Image (containerDisk), +RunStrategy
  ★ CompiledVM (net type)          denormalized boot intent + spec.clusterName + workload label
  ✎ compiler (netplane, →central)  ★ CompiledVMReconciler + pure CompileVM()  (alongside CompiledNICReconciler)
  ✎ scheduler / broker             broker now syncs CompiledNIC AND CompiledVM
        │ field-selector watch (spec.clusterName) + set-reconcile ▼
ATTACHED CLUSTER (downstream)
  ✎ broker                         syncs both CompiledNIC + CompiledVM CRDs down
  ✎ node agent (netplane/agent)    CompiledNIC → dataplane + routebus overlay-IP announce   (unchanged)
  ★ vm-materializer                local CompiledVM → kubevirt.io/v1.VirtualMachine (containerDisk, runStrategy)
     (netplane/cmd/vm-materializer; kubevirt.io/api)      │ KubeVirt boots the VMI
  KubeVirt + flowplane NAD (config/deploy/kubevirt-binding.yaml)
```

### 4.2 Types

- **`VirtualMachine.Spec`** (`api/v1alpha1`, shared): add
  - `Image string` — containerDisk image ref (e.g. `quay.io/containerdisks/fedora:41`).
  - `RunStrategy string` — KubeVirt run strategy; default `RerunOnFailure`. (Plain string; the materializer maps to `kubevirtv1.VirtualMachineRunStrategy`.)
  - (existing) `Resources` (cpu/mem) + `InterfaceRefs` reused.
- **`CompiledVM`** (new; namespaced; status subresource; `spec.clusterName` selectable field + `workload` label):
  - `ClusterName string` (binding), `Image string`, `Resources corev1.ResourceRequirements` (copied from the VM; maps to KubeVirt `Domain.Resources`), `RunStrategy string`,
  - `Interfaces []CompiledVMInterface{ MAC string; NetworkName string }` (resolved from the VM's NICs; `NetworkName` = the flowplane binding NAD).
  - Status: `Phase string` + `Conditions`.
  - Shared versioned type in `api/v1alpha1` + central internal mirror (`central/apis/net`) + hand-written conversion + fuzzer + served aggregated + downstream CRD (the Phase-1b recipe).

### 4.3 Compiler (`netplane/controllers`)

A new `CompiledVMReconciler` + pure `CompileVM(vm *VirtualMachine, nics []NetworkInterface, placement Placement) CompiledVM`:
- Watches `VirtualMachine` (+ `NetworkInterface` for MAC changes).
- `resolvePlacement` (existing) → `ClusterName` + `workload` label.
- Copies `Resources`, `Image`, `RunStrategy` (default `RerunOnFailure` when empty).
- For each `vm.Spec.InterfaceRefs` → find the NIC → `CompiledVMInterface{ MAC: nic.Spec.MAC, NetworkName: <flowplane NAD, a compiler flag/const> }`.
- Upserts `CompiledVM` (owner ref = the VirtualMachine), name `{ns}-{vm}` (mirrors CompiledNIC naming).
- Registered on the netplane controller manager next to `CompiledNICReconciler`.

### 4.4 Broker (extend to a second synced type)

The broker syncs **both** `CompiledNIC` and `CompiledVM` central→downstream (namespaced set-reconcile, `spec.clusterName` field selector, GC). Generalize the set-reconcile engine so the second type is not a copy of `SyncOnce` (a small generic helper over `client.ObjectList` + a spec-equality/namespace-key function); if generics fight controller-runtime, fall back to an explicit `SyncCompiledVMs`. The broker watches both types (both trigger a full declarative resync). `KUBE_FEATURE_WatchListClient=false` unchanged.

### 4.5 Downstream vm-materializer (`netplane/cmd/vm-materializer` + `netplane/controllers`)

A controller-runtime controller on the **downstream** config:
- Watches local `CompiledVM` CRDs; `Owns(&kubevirtv1.VirtualMachine{})`.
- Pure `buildVM(cvm *CompiledVM) *kubevirtv1.VirtualMachine`:
  - `Spec.RunStrategy` = mapped from `cvm.Spec.RunStrategy`.
  - `Spec.Template.Spec.Domain.Resources` from `cvm.Spec.Resources`.
  - `Spec.Template.Spec.Domain.Devices.Disks` = one `containerdisk` disk; `Spec.Template.Spec.Volumes` = one `ContainerDisk{Image: cvm.Spec.Image}`.
  - Per `cvm.Spec.Interfaces`: `Domain.Devices.Interfaces[]` (name + `MacAddress` + the flowplane/tap binding) + `Networks[]` (`Multus{NetworkName: iface.NetworkName}`).
  - Owner/labels: `workload` label carried; name `{cvm.Name}`.
- Set-reconcile: create/update (by spec)/delete-GC the KubeVirt `VirtualMachine` to match the local `CompiledVM` set.
- `kubevirt.io/api` added to `netplane/go.mod`; scheme registers `kubevirtv1`.

### 4.6 Data flow

User creates `VirtualMachine`(+NICs) → scheduler binds `spec.clusterName` → compiler emits `CompiledNIC` **and** `CompiledVM` → broker syncs both downstream → (a) agent programs the dataplane from `CompiledNIC` + announces the overlay IP on the routebus (existing), (b) vm-materializer creates the KubeVirt `VirtualMachine` from `CompiledVM` → KubeVirt boots the VMI on the flowplane overlay.

### 4.7 Tier-1 failover (partial)

`runStrategy: RerunOnFailure` → KubeVirt restarts the VMI on another node when its node goes NotReady. This is the Tier-1 self-heal, delivered by the field. Full Tier-1 (medik8s NHC node-fencing to confirm death) + the Phase-3 Tier-2 real fence actuators remain deferred (need infra).

## 5. Component boundaries (units)

- **Types** — additive `VirtualMachine` fields + new `CompiledVM`; unit: fuzz roundtrip.
- **`CompileVM` (pure)** — VM+NICs+placement → CompiledVM; unit table (image/cpu/mem/runStrategy default, interface MAC/NAD, placement).
- **CompiledVM compiler controller** — thin; envtest: VM → CompiledVM in central.
- **Broker CompiledVM sync** — set-reconcile; unit + loopback envtest.
- **`buildVM` (pure)** — CompiledVM → kubevirt VirtualMachine; unit (domain, containerDisk volume+disk, interfaces macAddress+multus, runStrategy mapping).
- **vm-materializer controller** — thin; envtest with KubeVirt CRDs installed.

## 6. Testing strategy

- **Unit:** `CompileVM` mapping table; `buildVM` (KubeVirt object shape — disks/volumes/interfaces/networks/runStrategy); broker CompiledVM namespaced set-reconcile.
- **Central envtest:** serve `CompiledVM` (CRUD + `spec.clusterName` field selector); net roundtrip fuzz includes CompiledVM.
- **Broker loopback envtest:** central-aggregated `CompiledVM{clusterName:c1}` → downstream CRD (bounded/update/GC), alongside the existing CompiledNIC loopback.
- **Materializer envtest (netplane):** install `kubevirt.io/api` CRDs; create a `CompiledVM`; run the materializer; assert a correct `kubevirt.io/v1.VirtualMachine` (containerDisk volume with the image, cpu/mem, interface macAddress + multus NAD, runStrategy). No running virt-controller.
- **Chained e2e (extends Phase 3):** VirtualMachine (Image+Resources+NICs) → schedule → compile (CompiledNIC + CompiledVM) → broker sync both → materializer creates the KubeVirt VM; assert the VM object + the CompiledNIC downstream.
- **Deferred (infra-gated):** real KubeVirt boot on the fabric, Ceph, cross-cluster sticky-IP, live Tier-1/Tier-2.

## 7. Migration & compatibility

- All type changes are **additive** (`VirtualMachine` optional fields; new `CompiledVM`). Existing CompiledNIC / datapath / scheduler / broker-NIC-sync are unaffected.
- The compiler gains a second reconciler (CompiledVM) on the same manager; the broker gains a second synced type; a new downstream binary (vm-materializer) is added — none change existing behavior.
- `netplane/go.mod` gains `kubevirt.io/api`; `central` unchanged (no KubeVirt). The Phase-1b/2/3 local replaces (kit, api) unchanged.
- `KUBE_FEATURE_WatchListClient=false` on every central-aggregated informer (the compiler's CompiledVM watch, the broker) — the materializer runs against a plain downstream cluster (no flag needed).

## 8. Risks & mitigations

- **KubeVirt API surface / envtest CRDs (biggest unknown).** `kubevirt.io/api` version + whether its CRDs load cleanly in envtest, and the exact `VirtualMachine` spec shape for a containerDisk + multus interface. Mitigation: de-risk the materializer with a small spike — add the dep, register the scheme, install the CRDs in one envtest, build a minimal VM object end-to-end before the full mapping.
- **Interface/NAD binding correctness.** The KubeVirt interface must use the flowplane tap binding + the right multus network name; a wrong binding = no overlay. Mitigation: mirror `config/deploy/kubevirt-binding.yaml` + `[[kubevirt-vm-primary-network-tap]]`; the unit test asserts the exact interface/network shape; real-boot validation is the deferred e2e.
- **Broker generalization.** Adding a second synced type risks regressing the CompiledNIC sync. Mitigation: keep the CompiledNIC path byte-identical; TDD the generic/second engine; the existing CompiledNIC loopback test must still pass.
- **CompiledVM ↔ CompiledNIC coherence.** Both must carry the same `spec.clusterName` (same placement) so they land in the same cluster. Mitigation: both use the same `resolvePlacement`; the chained e2e asserts both compile to the same cluster.
- **`Image`/`RunStrategy` as strings.** Loose typing. Mitigation: the materializer validates/maps `RunStrategy` to the KubeVirt enum (unknown → default `RerunOnFailure` + a condition); acceptable for the slice.

## 9. Single-cluster invariant

Single-cluster is the degenerate case (vision §9): one cluster, the broker (loopback) syncs `CompiledVM`, the materializer boots the VM locally. The chained e2e is the standing gate; multi-cluster placement/mobility is additive. Every part passes the one-cluster envtest before any fabric wiring.

## 10. Task shape (for the plan)

1. **Types:** `VirtualMachine.Spec` +Image/+RunStrategy; new `CompiledVM` (api versioned + central internal + hand-conversion + fuzzer + serve + downstream CRD) — the Phase-1b recipe; regen.
2. **CompileVM (TDD):** pure `CompileVM` + `CompiledVMReconciler` (placement, resource→cpu/mem, interface MAC/NAD) + register on the netplane manager; unit + central envtest (VM→CompiledVM).
3. **Broker CompiledVM sync (TDD):** generalize the set-reconcile to also sync `CompiledVM`; unit + loopback envtest (CompiledNIC path unchanged).
4. **vm-materializer spike + build (TDD):** add `kubevirt.io/api` to netplane, register scheme, install CRDs in one envtest (de-risk); then pure `buildVM` + the materializer controller + `netplane/cmd/vm-materializer`; unit + materializer envtest (CompiledVM → correct KubeVirt VM).
5. **Chained e2e + wrap:** VM→schedule→compile(NIC+VM)→broker sync→materialize; full build/test; memory; finish branch.

Sequential git; per-task spec + quality review; branch off main.

## 11. Open questions / deferred

- **Ceph storage-mobility** (`Volume` + `CompiledVolumeAttachment` + broker→PVC/DataVolume + re-reference-same-RBD move) — the next phase; the stateful-VM thesis.
- **Cross-cluster sticky-IP** (route-bus federation / regional reflector) — deferred; per-cluster announce unchanged.
- **Full Tier-1 (medik8s NHC) + Tier-2 real fence actuators** — infra-gated; Phase-3 skeleton stands.
- **cloud-init / SSH keys / user-data** — a minimal or absent cloud-init this phase; richer VM config later.
- **KubeVirt `instancetype`/`preference`** — inline domain now; profiles later.
- **VM status back-propagation** (VMI phase → VirtualMachine.Status → central) — the materializer/broker could surface boot status upward; deferred.
