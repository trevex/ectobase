# Phase 1b — Migrate `net.ectobase.dev` Types into the Central Aggregated Apiserver + Repoint the Compiler

**Status:** Design (brainstorm output) — approved for planning.
**Date:** 2026-08-02
**Phase of:** `docs/superpowers/specs/2026-08-01-multicluster-control-plane-design.md` (roadmap step 1, "Central extension apiserver").
**Builds on:** Phase 1 (central aggregated apiserver + kine/Postgres) and Phase 2 (broker/binding/sync loop), both merged to main. See memory `[[central-apiserver-foundation]]`.
**Related memory:** `[[central-apiserver-foundation]]`, `[[agent-reads-only-compilednic]]`, `[[compiled-nic-synthetic-testing]]`, `[[crd-rename-firewallpolicy-floatingip]]`, `[[multicluster-kubevirt-platform]]`.

---

## 1. Summary

Today the `net.ectobase.dev` types (`VPC`, `NetworkInterface`, `FirewallPolicy`, `FloatingIP`, `LoadBalancer`, `NATGateway`, `VPCPeering`, `CompiledNIC`) live in the `api` Go module and are served to the **netplane** control plane as ordinary CRDs; the `central` aggregated apiserver is orthogonal and only serves `platform.ectobase.dev` (`ClusterPool`, `CompiledWorkload`). Phase 1b brings the network API — and crucially the **compiled** object `CompiledNIC` — into central's aggregated apiserver, adds a `spec.clusterName` **binding** to `CompiledNIC`, and repoints the existing compiler (`netplane/controllers`) to read high-level types from central and write `CompiledNIC` to central carrying that binding. The Phase-2 broker then syncs the **real** `CompiledNIC` (not the `CompiledWorkload` stand-in) down to the attached cluster, where the unchanged node agent consumes it.

Placement is expressed on the **workload**: a new minimal high-level `VirtualMachine` type carries `spec.clusterName`; the compiler propagates that binding (plus a `workload=<vm-id>` label) onto the workload's compiled objects so the whole workload moves as a unit. Container/bare NICs (no owning VM) fall back to a configured `--cluster-name` default; a dedicated cross-cluster-scheduled container workload type is a later phase.

**One-line frame:** *make central the authoring home of the network API, teach the compiler to stamp a cluster binding inherited from the workload's VM, and let the broker sync the real `CompiledNIC` — single-cluster keeps working throughout.*

## 2. Goals / Non-goals

**Goals**
- Central's aggregated apiserver serves the `net.ectobase.dev` group (all 8 existing types) alongside `platform.ectobase.dev`.
- `CompiledNIC` gains a `spec.clusterName` selectable binding field.
- A minimal high-level `VirtualMachine` **placement anchor** exists; the compiler propagates its `spec.clusterName` (+ `workload=<vm-id>` label) onto the `CompiledNIC`s it owns.
- The compiler (`netplane/controllers`) runs against central: reads high-level types from central, writes `CompiledNIC` to central.
- The broker syncs the **real, namespaced** `CompiledNIC` central→downstream (generalized from the cluster-scoped `CompiledWorkload`).
- **Single-cluster is the standing gate** (§9 of the vision): a loopback envtest proves compile→bind→sync→(downstream CRD) end to end before any multi-cluster wiring.
- **One shared versioned type definition** — `api/v1alpha1` — serves both the CRD/agent role and central's versioned layer; no drift.

**Non-goals (this phase)**
- KubeVirt VMI lifecycle from `VirtualMachine` — the VM type is a **placement anchor only** here; VMI creation, volumes, and `CompiledVM`/`CompiledVolumeAttachment` are Phase 4.
- The cross-cluster container workload type (containers use the `--cluster-name` default for now).
- The central scheduler / failover — `spec.clusterName` is set manually or flag-defaulted; Phase 3 adds the scheduler that writes it.
- `ClusterRestriction` authorizer (Phase 3), status-back-to-central plumbing beyond what exists.
- 2-cluster kind smoke is best-effort; loopback envtest is the authoritative gate.
- Retiring `CompiledWorkload` — kept to avoid churn; `CompiledNIC` is added as the real second synced type.

## 3. Key design decisions (with rationale)

| # | Decision | Rationale |
|---|----------|-----------|
| **P1** | **All 8 `net.ectobase.dev` types move into central's aggregated apiserver** (full migration, not a slice) | The compiler reads *all* of them; running it against central requires them all present. Chosen explicitly over a thin slice for a coherent end state. |
| **P2** | **Shared versioned package = `api/v1alpha1`, imported by both roles** | One definition, zero drift. `api` keeps generating deepcopy + CRD manifests (agent/CNI import unchanged); `central` adds an internal package + conversion to the *imported* versioned types. Cross-module conversion-gen is the main mechanical cost, accepted for DRY. |
| **P3** | **Placement lives on the workload (`VirtualMachine.spec.clusterName`), propagated to compiled objects** | Faithful pod→node model (vision M3/§4.4): the workload is the placement unit; its compiled objects inherit the binding + a `workload=<id>` label and move atomically. Container NICs (no VM) default via `--cluster-name`. |
| **P4** | **`VirtualMachine` is a placement anchor only in Phase 1b** | Gives the "placement on the VM, everything moves with it" model now without pulling KubeVirt VMI lifecycle (Phase 4) forward. YAGNI on the runtime. |
| **P5** | **Compiler repointed to central; agent unchanged, reads downstream CRD** | Central is the authoring home; the broker materializes `CompiledNIC` downstream where the node agent already reads it (`[[agent-reads-only-compilednic]]`). Single-cluster = loopback (central + downstream in-process). |
| **P6** | **Broker generalized to namespaced set-reconcile; declarative, no in-memory diff** | `CompiledNIC` is namespaced (vs cluster-scoped `CompiledWorkload`). Keep the `ReplaceInterfaceFirewall`/`appliedFw` lesson: derive desired+have from live sets each pass. |
| **P7** | **`--cluster-name` default for VM-less NICs** | Keeps single-cluster + the CNI/container path working while VMs are the placement-anchored case; the future container workload type replaces the default. |

## 4. Architecture

### 4.1 Type ownership (P2)

```
api/ module  (github.com/trevex/ectobase/api)
  v1alpha1/                         ← the SINGLE shared versioned definition
    vpc_types.go, networkinterface_types.go, firewallpolicy_types.go,
    floatingip_types.go, loadbalancer_types.go, natgateway_types.go,
    vpcpeering_types.go, compilednic_types.go   (+ ClusterName on CompiledNICSpec)
    virtualmachine_types.go          ★ new placement-anchor type
    zz_generated.deepcopy.go          (controller-gen object)
  → config/crd/bases/*.yaml           (controller-gen crd — agent/CNI/downstream CRDs)

central/ module  (github.com/trevex/ectobase/central)
  apis/net/            ★ new INTERNAL types (mirror api/v1alpha1 fields)
    <type>_types.go, <type>_rest.go   (resource.Object + status subresource impls)
    compilednic_rest.go               → SelectableFields{spec.clusterName} +
                                        SupportedFieldSelectors{spec.clusterName}
    register.go, doc.go
  apis/net/  ←→ api/v1alpha1          conversion-gen (internal ↔ imported versioned),
                                       defaults, openapi (kube::codegen, cross-module)
  cmd/apiserver/main.go               .With(apiserver.Resource(&net.<T>{}, apiv1alpha1.SchemeGroupVersion)) ×8+1
```

`api` and `agent`/`cni` import `api/v1alpha1` exactly as today. `central` imports `api/v1alpha1` as its versioned layer and owns the internal types + conversion. The downstream `CompiledNIC` CRD is generated from the shared versioned type → wire-identical to what central serves and the agent reads.

> **Codegen note.** `central/hack/update-codegen.sh` (kube::codegen) currently generates deepcopy/conversion/defaults/openapi/clientset over `central/apis/platform`. It must be extended to also cover `central/apis/net` with the versioned package being the **external** `api/v1alpha1`. Conversion-gen supports an external versioned package via import; validate the `--extra-peer-dirs`/input-package wiring early (this is the single biggest unknown — de-risk it in Task 2 before the other 7 types are wired).

### 4.2 Placement propagation (P3, P4, P7)

- **`VirtualMachine`** (high-level, namespaced, status subresource): `spec.clusterName` (binding), `spec.interfaceRefs []LocalObjectReference` (its NICs), a stable workload id (name/uid). Status: `Phase`. No VMI creation.
- **Compiler** (`Compile()` in `netplane/controllers/compilednic.go`): resolve the NIC's owning `VirtualMachine` (via the VM's `interfaceRefs` or an owner ref on the NIC). If found → `CompiledNIC.Spec.ClusterName = VM.Spec.ClusterName`, label `workload=<vm-id>`. If not found → `ClusterName = <--cluster-name default>`, no workload label. Everything else in `Compile()` is unchanged.
- The `CompiledNICReconciler` watch set gains `VirtualMachine` (re-enqueue owned NICs on VM placement change).

### 4.3 Data flow (single cluster, after Phase 1b)

1. User creates `VirtualMachine` + `NetworkInterface`(s) + `VPC`/policies **in central**.
2. **Compiler** (repointed to central) reads high-level types from central, resolves owning VM, writes `CompiledNIC` **to central** with `spec.clusterName` (VM binding or default) + `workload` label.
3. **Broker** watches central `CompiledNIC` where `spec.clusterName == me` → namespaced set-reconcile into the downstream cluster's `CompiledNIC` CRDs.
4. **Node agent** reads the downstream `CompiledNIC` CRD → programs the eBPF dataplane (unchanged).

In loopback single-cluster, "central" and "downstream" are two in-process apiservers (the Phase-2 test topology): central = kit-aggregated, downstream = controller-runtime envtest with the `CompiledNIC` CRD.

## 5. Component boundaries (units)

- **Shared versioned types (`api/v1alpha1`)** — struct definitions + deepcopy + CRD manifests; the wire contract. Unit: fuzz roundtrip.
- **Central internal net types + REST (`central/apis/net`)** — `resource.Object`/status/selectable-field impls + conversion to the versioned layer. Unit: conversion roundtrip fuzz; envtest serve + field-selector list.
- **Apiserver wiring (`central/cmd/apiserver`)** — registers the net group resources. Envtest: CRUD + watch for a representative type + `CompiledNIC` field selector.
- **Compiler (`netplane/controllers`)** — pure `Compile()` + reconciler; placement propagation is a pure function of (NIC, owning VM, default). Unit: propagation table (owned→VM binding, unowned→default) with fakes.
- **Broker (`central/internal/broker`)** — namespaced set-reconcile of `CompiledNIC`. Unit: create/update/GC across namespaces with fakes; loopback envtest for the real path.
- **Node agent / dataplane** — **unchanged**; reads downstream `CompiledNIC` CRD (existing, already tested).

## 6. Testing strategy

- **Unit:** compiler placement propagation (owned vs default); broker namespaced set-reconcile GC; conversion roundtrip fuzz for all migrated types.
- **Central envtest:** net group served aggregated (CRUD+watch on a representative type, e.g. `NetworkInterface`); `CompiledNIC` `spec.clusterName` field-selector list returns exactly the bound set; `VirtualMachine` CRUD.
- **Loopback broker envtest (the §9 gate):** central-aggregated `CompiledNIC{clusterName:c1}` + `{clusterName:c2}` → after sync, downstream has exactly the c1 one (bounded pull); update converges; delete GCs; stop central → downstream object survives (partition). Reuses the Phase-2 harness with the real namespaced type.
- **Single-cluster compile e2e (envtest-level):** create `VirtualMachine`+`NetworkInterface`+`VPC` in central → compiler emits `CompiledNIC{clusterName}` with the `workload` label → broker materializes it downstream → assert. Kind smoke best-effort.

## 7. Migration & compatibility

- **`CompiledNICSpec.ClusterName` is additive** — existing consumers ignore it; the agent is unaffected.
- **`api/v1alpha1` stays the import path** for `agent`, `cni`, and the api CRDs → those modules do **not** change their imports (P2 pays off here).
- **netplane controllers repoint their client config to central** (env/flag), and their envtests point at a central-aggregated server instead of a plain CRD apiserver. This is the main test-migration surface; keep the `Compile()` logic byte-identical (only the client target + placement stamping change).
- **`central/go.mod`** keeps the local `replace go.opendefense.cloud/kit => /home/nik/Development/apiserver-kit` (Phase-1 blocker unchanged) and gains a `replace github.com/trevex/ectobase/api => ../api` (workspace already wires this via `go.work`).
- **`KUBE_FEATURE_WatchListClient=false`** on every informer against the aggregated apiserver (Phase-1 finding) — now also the compiler's central-side informers, not just the broker.

## 8. Risks & mitigations

- **Cross-module conversion-gen (biggest unknown).** Internal types in `central`, versioned in `api`. Mitigation: de-risk in an early task with **one** type (e.g. `VPC`) end-to-end (internal + conversion + serve + envtest) before wiring the other seven; if the external-versioned-package wiring proves intractable, fall back to a `central/apis/net/v1alpha1` re-export shim that aliases `api/v1alpha1` (still one definition, an extra thin package).
- **Compiler test migration churn.** Repointing envtests to central-aggregated is broad. Mitigation: keep `Compile()` pure and unchanged; test placement propagation as a pure unit; only the reconciler integration test moves to central.
- **Namespaced broker generalization.** Off-by-one on namespace keying → cross-namespace GC. Mitigation: TDD the namespaced set-reconcile with a multi-namespace fake before the envtest.
- **OpenAPI/aggregation for two groups.** Central now serves two API groups. Mitigation: mirror exactly how `platform` is wired; add the net group's openapi to the same `GetOpenAPIDefinitions`.
- **apiserver-kit still pre-1.0 / local replace.** Unchanged Phase-1 posture; merge is fine per the Phase-1 decision (memory). No new dependency risk beyond scale of use.

## 9. Single-cluster invariant

Per the vision §9: single-cluster is the degenerate case, and every phase passes a one-cluster lab first. Here the loopback broker envtest (§6) is that gate — central + downstream in-process, the compiler stamps a single `--cluster-name`, the broker syncs it, the agent's read path is exercised via the downstream CRD. Multi-cluster (real second cluster, field-selector isolation across trust boundaries) is strictly additive and not required to land Phase 1b.

## 10. Task shape (for the plan)

1. **Shared versioned changes:** add `VirtualMachine` type + `ClusterName` on `CompiledNICSpec` in `api/v1alpha1`; regen deepcopy + CRD manifests; api module builds/tests green.
2. **De-risk central net internal types with ONE type (`VPC`):** internal package + `_rest.go` + conversion/openapi codegen wiring (`update-codegen.sh` extended); serve it; conversion roundtrip + CRUD envtest. Proves the cross-module codegen path.
3. **Migrate the remaining 7 net types** (`NetworkInterface`, `FirewallPolicy`, `FloatingIP`, `LoadBalancer`, `NATGateway`, `VPCPeering`, `CompiledNIC`) **plus the new `VirtualMachine`** into `central/apis/net`; `CompiledNIC` gets the `spec.clusterName` selectable-field hook; serve all from `cmd/apiserver`; envtest CRUD + `CompiledNIC` field selector.
4. **Repoint the compiler to central + placement propagation (TDD):** owning-VM resolution, `ClusterName` + `workload` label stamping, default fallback; `WatchListClient=false`; VM added to the watch set; reconciler integration test against central-aggregated envtest.
5. **Generalize the broker to namespaced `CompiledNIC` (TDD) + loopback envtest:** namespaced set-reconcile; the §9 gate test (bounded/update/GC/partition) with the real type.
6. **Single-cluster compile e2e + wrap:** VM→NIC→CompiledNIC→downstream assertion; full build/test; update memory; finish branch.

Sequential git; per-task spec + quality review; branch off main.

## 11. Open questions / deferred

- **Owning-VM resolution mechanism** — VM `interfaceRefs` (VM points at NICs) vs owner refs on the NIC (NIC points at VM). Lean: `interfaceRefs` on the VM (explicit, matches "VM owns its NICs"); confirm during planning.
- **Workload id form** — VM `name` vs `uid` for the `workload=<id>` label. Lean: name within namespace (human-legible, stable); revisit if collisions matter.
- **Does the compiler run fully before scheduling?** Vision §11 open item — for Phase 1b the compiler stamps a default/placeholder `clusterName`; Phase 3's scheduler decides whether compiled objects are emitted unbound then bound, or bound at compile time.
- **`CompiledWorkload` retirement** — kept this phase; revisit once `CompiledNIC` is the proven synced type.
- **CNI/container placement** — the future cross-cluster container workload type (out of scope) replaces the `--cluster-name` default for VM-less NICs.
