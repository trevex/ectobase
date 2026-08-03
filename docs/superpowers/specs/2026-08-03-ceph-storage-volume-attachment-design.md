# Ceph Storage — Volume + CompiledVolumeAttachment + Rook Backend

**Status:** Design (brainstorm output) — approved for planning.
**Date:** 2026-08-03
**Phase of:** `docs/superpowers/specs/2026-08-01-multicluster-control-plane-design.md` (roadmap step 4 storage tail — the shared-Ceph volume half; cross-cluster sticky-IP + live fence-gated reschedule remain later).
**Builds on:** Phase 4 (KubeVirt VM lifecycle via CompiledVM + downstream materializer). See memory `[[phase4-kubevirt-vm-lifecycle]]`, `[[phase3-scheduler-failover]]`, `[[multicluster-kubevirt-platform]]`.

---

## 1. Summary

A VM's disk becomes persistent, RBD-backed storage. A first-class **`Volume`** (RBD handle: size, storageClass, optional boot image) is referenced by a `VirtualMachine`. The compiler emits a **`CompiledVolumeAttachment`** per (VM, Volume) — bound to a cluster via `spec.clusterName` exactly like `CompiledNIC`/`CompiledVM`. Downstream, a **VolumeMaterializer** turns each attachment into a CDI **`DataVolume`** (an RBD PVC via ceph-csi), and the **VMMaterializer** builds the KubeVirt VM to boot from / mount those PVCs (joining VM↔attachments by the shared `workload` label). A minimal **Rook Ceph** (single-mon, replica-1) provides the RBD `StorageClass`. containerDisk boot stays as the ephemeral fallback for VMs with no boot Volume.

**One-line frame:** *a Volume is an RBD disk; the compiler binds it to a cluster as a CompiledVolumeAttachment; the materializer makes it a CDI DataVolume the VM boots from — Rook Ceph provides the RBD.*

## 2. Goals / Non-goals

**Goals**
- **`Volume`** high-level type (RBD disk: size + storageClass + optional bootImage) referenced by `VirtualMachine.spec.volumeRefs`.
- **`CompiledVolumeAttachment`** compiled type (one per (VM, Volume), `spec.clusterName`-bound, `workload`-labelled).
- **Compiler** emits CompiledVolumeAttachments; **broker** syncs them (a third synced type); **VolumeMaterializer** → CDI `DataVolume` (RBD PVC); **VMMaterializer** boots the VM from the resulting PVCs (label-join).
- **Persistent, RBD-backed disks** that survive VM restart and follow the VM across nodes within a cluster (real stateful Tier-1).
- **Minimal Rook Ceph** (`hack/rook-ceph-up.sh`) + a `ceph-rbd` StorageClass; best-effort live "VM boots from RBD PVC" on the fabric.
- **Envtest-gated control plane** (types, compiler, broker, both materializers) — no real Ceph/KubeVirt needed for the gate.

**Non-goals (this phase)**
- **Cross-cluster shared-RBD mobility** (a Volume re-referencing the same RBD in a *different* cluster on reschedule) — needs shared/external Ceph + the Tier-2 fence actuators; a later phase. This phase is per-cluster RBD.
- **Ceph `NetworkFence` / RBD-blocklist fencing** — the Phase-3 Tier-2 skeleton's real actuators; later.
- **Snapshots, clones, resize, RWX/CephFS, multiple access modes** — RWO block disks only.
- **A separate `storage.ectobase.dev` API group** — reuse `net.ectobase.dev` now; group-split is a noted future cleanup.
- **Redundant/production Rook** — single-mon replica-1, no HA; a dev backend.

## 3. Key design decisions (with rationale)

| # | Decision | Rationale |
|---|----------|-----------|
| **S1** | **`Volume` is a first-class type, not fields on the VM** | The vision wants storage that can outlive/move independently of the VM. A `Volume` object + a per-(VM,Volume) `CompiledVolumeAttachment` gives the movable Volume→node binding; the VM just references PVCs. |
| **S2** | **RBD boot disk via a CDI `DataVolume`** | CDI imports the `BootImage` (a containerDisk/registry image) into an RBD PVC; the VM boots from it. `kubevirt.io/containerized-data-importer-api v1.64.0` is already transitively available in netplane — no new dep. |
| **S3** | **Materializer joins VM↔attachments by the `workload` label; CompiledVM unchanged** | Avoids a redundant volume list on CompiledVM. The VMMaterializer lists downstream CompiledVolumeAttachments labelled `workload=<vm>` and wires their PVCs as disks. Both compiled objects already carry the same `workload` label + `spec.clusterName`. |
| **S4** | **Two downstream materializers: Volume→DataVolume + VM→VirtualMachine** | Separation of concerns: the DataVolume (RBD PVC) lifecycle is independent of the VM (the mobility seam). KubeVirt waits for the referenced DataVolume, so no strict ordering is needed between the two reconcilers. |
| **S5** | **Reuse `net.ectobase.dev`** | Avoids the codegen overhead of a new group; the group is really "the ectobase workload API." Split to `storage.ectobase.dev` later if desired (pure rename). |
| **S6** | **containerDisk stays as the ephemeral fallback** | A VM with `Image` but no boot Volume keeps booting ephemeral (Phase 4 behavior, byte-unchanged). Persistence is opt-in via a boot `Volume`. |
| **S7** | **Rook Ceph single-mon replica-1, in-cluster, per-cluster** | The user-chosen simple backend; RBD is what the future `NetworkFence` fencing needs. Per-cluster (not shared) now; shared/external Ceph is the mobility phase. |
| **S8** | **Server-side apply for the DataVolume + VM (as Phase 4)** | CDI/KubeVirt webhooks default many fields; SSA lets the materializers own only their intent and avoids churn. |

## 4. Architecture

### 4.1 Component map (★ new · ✎ extend)

```
CENTRAL (aggregated apiserver + controllers)
  ★ Volume (net type)               high-level RBD disk: Size, StorageClass, BootImage
  ✎ VirtualMachine.Spec             +VolumeRefs []LocalObjectReference
  ★ CompiledVolumeAttachment (net)  per (VM,Volume): clusterName + Size/StorageClass/BootImage/Boot + workload label
  ★ compiler                        CompiledVolumeAttachmentReconciler + pure CompileVolumeAttachments()
  ✎ broker                          +SyncCompiledVolumeAttachments (3rd synced type)
        │ field-selector watch (spec.clusterName) + set-reconcile ▼
ATTACHED CLUSTER (downstream)
  ✎ broker                          syncs CompiledNIC + CompiledVM + CompiledVolumeAttachment
  ★ VolumeMaterializer              CompiledVolumeAttachment → cdiv1.DataVolume (RBD PVC via ceph-csi)
  ✎ VMMaterializer                  buildVM joins CompiledVolumeAttachments by workload label → dataVolume disks
  KubeVirt + CDI + ceph-csi + ★ Rook Ceph (single-mon replica-1) + ceph-rbd StorageClass
```

### 4.2 Types (net.ectobase.dev, Phase-1b recipe)

- **`Volume`** (namespaced, status subresource): `Spec{ Size resource.Quantity; StorageClass string (optional); BootImage string (optional) }`, `Status{ Phase string }`. A `BootImage` makes it a bootable volume (CDI imports it); empty ⇒ a blank data disk of `Size`.
- **`VirtualMachine.Spec`** += `VolumeRefs []LocalObjectReference` (optional). The referenced Volume whose `BootImage` is set is the boot disk; others are data disks. `Image` (containerDisk) stays as the ephemeral fallback.
- **`CompiledVolumeAttachment`** (namespaced, status subresource, `spec.clusterName` selectable): `Spec{ ClusterName string; Size resource.Quantity; StorageClass string; BootImage string; Boot bool }`. Name `{vm}-{volume}`; label `workload=<vm>`. Status `{ State string }`.
- Central internal mirror + hand-conversion + fuzzer + served aggregated + downstream CRD for both new types (the `[[phase1b-net-types-central]]` recipe; `CompiledVM` in Phase 4 is the exact template).

### 4.3 Compiler (`netplane/controllers`)

`CompiledVolumeAttachmentReconciler` + pure `CompileVolumeAttachments(vm *VirtualMachine, volumes []Volume, placement Placement) []CompiledVolumeAttachment`:
- Watches `VirtualMachine` (+ `Volume` for size/image changes).
- For each `vm.Spec.VolumeRefs` → resolve the `Volume` → one `CompiledVolumeAttachment{ ClusterName: placement.ClusterName, Size, StorageClass, BootImage, Boot: (BootImage != "") }`, name `{vm}-{volume}`, label `workload=<vm>`, owner ref the VM.
- Set-reconcile the VM's attachments (create/update/delete-GC extras when a VolumeRef is removed) — mirror how CompiledNIC upserts, but a VM owns *N* attachments, so GC the ones no longer referenced.
- Registered next to the CompiledNIC/CompiledVM compilers. **CompiledVM is unchanged.**

### 4.4 Broker

`SyncCompiledVolumeAttachments` — a third explicit twin of `SyncOnce` (namespaced set-reconcile of `CompiledVolumeAttachment`, `spec.clusterName` field selector, GC). cmd/broker field-selects + watches the type; the reconcile calls all three syncs. (Concrete-over-generic; this is the 3rd type — note the generic-refactor trigger is now reached, but defer the refactor to keep this phase additive + low-risk; flag it.)

### 4.5 Materializer (`netplane`, downstream)

- **`VolumeMaterializerReconciler`**: `CompiledVolumeAttachment` → a `cdiv1.DataVolume` (`kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1`). `Spec.PVC`/`Storage`: `AccessModes: [ReadWriteOnce]`, `Resources.Requests[storage]=Size`, `StorageClassName=StorageClass` (or omit for the cluster default). `Spec.Source`: `Registry{URL: docker://<BootImage>}` (or `Blank{}` when `BootImage==""`). Name == the attachment name. Server-side apply; owner ref the CompiledVolumeAttachment.
- **`VMMaterializerReconciler`** (extend): the reconcile lists downstream `CompiledVolumeAttachment`s with the VM's `workload` label; passes them to `buildVM`. `buildVM(cvm, attachments)` (pure): if `attachments` non-empty → for each, a `dataVolume` volume (`VolumeSource{DataVolume:{Name}}`) + a `Disk` (boot attachment first, virtio bus), and DROP the containerDisk; else → the `Image` containerDisk (Phase-4 behavior). Network interfaces unchanged.

### 4.6 Rook backend (`hack/`, best-effort live)

`hack/rook-ceph-up.sh`: install the Rook operator; apply a minimal `CephCluster` (`mon.count: 1`, `mgr.count: 1`, a directory/PVC-backed OSD so it runs on kind without a spare block device, `storage` tuned for a single node) + a `CephBlockPool{replicated.size: 1, requireSafeReplicaSize: false}` + a `ceph-rbd` `StorageClass` (ceph-csi RBD provisioner). Wire it into the stack install (`hack/install-stack.sh` or a sibling). A best-effort live check: on the fabric, create a `Volume`(BootImage) + `VirtualMachine`(VolumeRef), let the stack materialize, and assert the RBD PVC binds + the VMI boots — **DONE_WITH_CONCERNS** if the kind+Rook+KubeVirt-emulation stack is finicky.

### 4.7 Data flow

User creates `Volume`(BootImage=fedora, Size=10Gi) + `VirtualMachine`(VolumeRefs=[vol]) → scheduler binds `spec.clusterName` → compiler emits `CompiledNIC` + `CompiledVM` + `CompiledVolumeAttachment`(vm-vol, Boot) all bound to the same cluster → broker syncs all three → downstream: VolumeMaterializer creates the RBD `DataVolume` (imports fedora → RBD PVC); VMMaterializer builds the VM booting from that PVC (workload-label join) → CDI + ceph-csi provision the RBD; KubeVirt boots the VMI from the persistent disk.

## 5. Component boundaries (units)

- **Types** — Volume + CompiledVolumeAttachment; unit: fuzz roundtrip.
- **`CompileVolumeAttachments` (pure)** — VM+Volumes+placement → []attachment; unit table (boot vs data, size/class/image, placement, GC on removed ref).
- **CompiledVolumeAttachment compiler controller** — thin; envtest: VM+Volume → attachment in central.
- **Broker sync** — the 3rd set-reconcile; unit + loopback envtest.
- **`buildDataVolume` (pure)** — attachment → cdiv1.DataVolume (RBD, registry-import vs blank); unit.
- **`buildVM` (pure, extended)** — cvm + attachments → VM disks (dataVolume vs containerDisk fallback, boot ordering); unit.
- **VolumeMaterializer / VMMaterializer controllers** — thin; envtest with the CDI DataVolume + KubeVirt VM CRD fixtures.
- **Rook script** — infra; live best-effort.

## 6. Testing strategy

- **Unit:** `CompileVolumeAttachments` (boot/data, GC); `buildDataVolume` (registry import vs blank, RBD storageClass/size/RWO); extended `buildVM` (dataVolume disks + boot-first ordering + containerDisk dropped when a boot Volume exists, else containerDisk kept); broker `SyncCompiledVolumeAttachments` set-reconcile.
- **Central envtest:** serve `Volume` + `CompiledVolumeAttachment` (CRUD + `spec.clusterName` selector); net roundtrip fuzz includes both.
- **Broker loopback envtest:** central-aggregated `CompiledVolumeAttachment{clusterName:c1}` → downstream CRD (bounded/update/GC), alongside CompiledNIC/CompiledVM.
- **Materializer envtest (netplane):** install the CDI `DataVolume` CRD fixture (hand-written preserve-unknown-fields, like the KubeVirt one) + the KubeVirt VM CRD fixture; create a `CompiledVolumeAttachment` → assert a correct `cdiv1.DataVolume` (RBD PVC, image source); create a `CompiledVM` + the attachment → assert the `VirtualMachine` boots from the DataVolume PVC (workload-join).
- **Chained e2e (extends Phase 4):** `Volume`+`VirtualMachine` → schedule → compile (NIC+VM+VolumeAttachment) → broker sync all → VolumeMaterializer DataVolume + VMMaterializer VM-referencing-it.
- **Live (best-effort):** Rook Ceph + KubeVirt/CDI on the fabric; a `Volume`-backed VM boots from an RBD PVC.

## 7. Migration & compatibility

- Additive: new `Volume` + `CompiledVolumeAttachment` types; `VirtualMachine.Spec.VolumeRefs` optional. **CompiledNIC / CompiledVM / scheduler / broker-NIC-VM paths byte-unchanged.** A VM with only `Image` (no VolumeRefs) is Phase-4-identical (ephemeral containerDisk).
- `buildVM` gains an `attachments` param — Phase-4 callers pass empty ⇒ unchanged output.
- `kubevirt.io/containerized-data-importer-api` moves from indirect → direct in `netplane/go.mod` (already in the graph; no version change). No new dep in api/central.
- `KUBE_FEATURE_WatchListClient=false` on the compiler's CompiledVolumeAttachment watch (central-aggregated); not on the downstream materializers.

## 8. Risks & mitigations

- **CDI DataVolume API surface + envtest CRD (main unknown).** The exact `cdiv1.DataVolume` spec shape (Source.Registry vs PVC vs Storage) for the pinned v1.64.0. Mitigation: a small spike — hand-write the CDI DataVolume CRD fixture + build one DataVolume object end-to-end before the full mapping (mirrors the Phase-4 KubeVirt spike).
- **Boot-from-DataVolume wiring.** The VM's disk must reference the DataVolume/PVC correctly (dataVolume volume source vs persistentVolumeClaim). Mitigation: unit-assert the exact volume/disk shape; the boot ordering (boot disk first) is explicit.
- **Rook-on-kind fiddliness.** No spare block device on kind → OSD-on-directory/PVC config; single-mon replica-1 is non-standard. Mitigation: it's best-effort/live-only; the control-plane gate doesn't depend on it; document the exact minimal manifest.
- **Broker third-type duplication.** `SyncCompiledVolumeAttachments` is a 3rd near-identical set-reconcile — the generic-refactor trigger. Mitigation: stay concrete this phase (additive, low-risk); flag the refactor as a follow-up.
- **Attachment GC.** A VM owns N attachments; removing a VolumeRef must GC its attachment. Mitigation: the compiler set-reconciles the VM's attachment set (delete extras), unit-tested.

## 9. Single-cluster invariant

Single-cluster is the degenerate case (vision §9): one cluster with Rook, one broker (loopback) syncing the attachment, the materializer creating the DataVolume + the VM booting from it locally. The chained e2e is the standing gate; cross-cluster shared-RBD mobility is strictly additive (and deferred). Every part passes the one-cluster envtest before any fabric wiring.

## 10. Task shape (for the plan)

1. **Types:** `Volume` + `CompiledVolumeAttachment` (api versioned + central internal + hand-conversion + fuzzer + serve + downstream CRD, the Phase-1b recipe); `VirtualMachine.Spec.VolumeRefs`; regen.
2. **Compiler (TDD):** pure `CompileVolumeAttachments` + `CompiledVolumeAttachmentReconciler` (per-VolumeRef, boot flag, GC of removed refs, placement) + register; unit + central envtest.
3. **Broker (TDD):** `SyncCompiledVolumeAttachments` (3rd synced type) + cmd wiring; unit + loopback envtest.
4. **VolumeMaterializer spike + build (TDD):** CDI DataVolume CRD fixture + `buildDataVolume` (RBD, registry-import vs blank) + the reconciler + `netplane/cmd/vm-materializer` (or a sibling) runs it; unit + envtest.
5. **VMMaterializer disk wiring (TDD):** extend `buildVM(cvm, attachments)` (dataVolume disks + boot ordering + containerDisk fallback) + the reconcile's workload-label join; unit + envtest.
6. **Rook backend + chained e2e + wrap:** `hack/rook-ceph-up.sh` + stack wiring + best-effort live boot; the chained schedule→compile→sync→materialize(DataVolume+VM) e2e; full build/test; memory; finish branch.

Sequential git; per-task spec + quality review; branch off main.

## 11. Open questions / deferred

- **Cross-cluster shared-RBD mobility** (re-reference the same RBD in a new cluster on reschedule) — needs shared/external Ceph + the Tier-2 fence actuators; the next storage phase.
- **Ceph `NetworkFence` / RBD-blocklist** — the Phase-3 Tier-2 skeleton's real actuators.
- **`storage.ectobase.dev` group split** — cosmetic future cleanup.
- **Broker generic set-reconcile** — the 3rd type reaches the refactor trigger; defer.
- **Volume status back-propagation** (PVC bound / DataVolume phase → Volume.Status → central) — deferred.
- **Resize / snapshot / clone / RWX / additional access modes** — later.
- **Rook HA / real block devices / production tuning** — this is a dev backend.
