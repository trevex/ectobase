# Phase 1b — Net Types into Central + Compiler Repoint — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve the `net.ectobase.dev` types (all 8, plus a new placement-anchor `VirtualMachine`) from the central aggregated apiserver, add a `spec.clusterName` binding to `CompiledNIC`, repoint the compiler to run against central and stamp that binding from the owning VM, and switch the broker to sync the real namespaced `CompiledNIC`.

**Architecture:** The versioned type structs stay in `api/v1alpha1` (the single shared definition — `api` still generates deepcopy + CRDs; agent/CNI import unchanged). `central` gains an internal package `central/apis/net` with `resource.Object`/`_rest.go` impls + conversion to the imported versioned types, and serves group `net.ectobase.dev` alongside `platform.ectobase.dev`. The compiler (`netplane/controllers`) points its client at central, resolves each NIC's owning `VirtualMachine`, and stamps `CompiledNIC.spec.clusterName` (+ `workload` label). The broker set-reconciles the real `CompiledNIC` central→downstream (namespaced).

**Tech Stack:** Go 1.26.4 (workspace); `api` + `central` + `netplane` modules; apiserver-kit v0.3.4 (local `replace`, kine/Postgres); `k8s.io/code-generator` (kube::codegen) + `controller-gen`; controller-runtime v0.24.1; envtest (kit-aggregated + controller-runtime); `go.work` wires the modules.

**Design doc:** `docs/superpowers/specs/2026-08-02-phase1b-net-types-into-central-design.md`.

**Non-negotiable carry-overs (Phase-1 findings):**
- Every informer against the aggregated apiserver MUST run with `KUBE_FEATURE_WatchListClient=false` (client-go streaming list-watch unsupported → informer stalls silently). This now also covers the **compiler's** central-side informers.
- Declarative set-reconcile only — no in-memory diff (the `appliedFw`/`ReplaceInterfaceFirewall` lesson).
- envtest needs the nix devShell (`KUBEBUILDER_ASSETS`). Run all `go test`/codegen via `nix develop --command ...` if the assets/tools aren't already on PATH.
- `go 1.26.4` is the real toolchain; ignore stale go-1.26.0 LSP diagnostics.
- `central/go.mod` keeps `replace go.opendefense.cloud/kit => /home/nik/Development/apiserver-kit` and needs `replace github.com/trevex/ectobase/api => ../api` (go.work already resolves this locally).

**Branch:** create `feat/phase1b-net-types-central` off main before Task 1. *(Already created in this session; verify with `git branch --show-current`.)*

---

## File structure

**`api` module (shared versioned definitions):**
- Modify: `api/v1alpha1/compilednic_types.go` — add `ClusterName` to `CompiledNICSpec`.
- Create: `api/v1alpha1/virtualmachine_types.go` — new `VirtualMachine` placement-anchor type.
- Modify: `api/v1alpha1/register.go` — register `VirtualMachine`/`VirtualMachineList`.
- Regenerated: `api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/bases/net.ectobase.dev_*.yaml`.

**`central` module (internal types + serve + broker):**
- Create: `central/apis/net/doc.go`, `register.go`, and per-type `*_types.go` + `*_rest.go` (internal; `resource.Object` impls).
- Create: `central/apis/net/v1alpha1/` — versioned **alias** package re-exporting `api/v1alpha1` types (so kube::codegen sees an internal↔versioned pair under `central/apis`). *(Exact shape validated in Task 2.)*
- Create: `central/apis/net/install/install.go` — scheme install for the net group.
- Modify: `central/hack/update-codegen.sh` — cover `central/apis/net` (deepcopy/conversion/defaults/openapi/client).
- Modify: `central/cmd/apiserver/main.go` — serve the net group resources.
- Modify: `central/internal/broker/broker.go` — switch the engine to namespaced `CompiledNIC`.
- Modify: `central/cmd/broker/main.go` — `For`/cache `CompiledNIC` instead of `CompiledWorkload`.
- Modify: `central/test/broker_test.go`, `central/test/envtest_test.go` — real-type assertions.
- Create: `central/config/crd/net.ectobase.dev_compilednics.yaml` — downstream CRD (generated from the shared versioned type; may reuse `config/crd/bases`).

**`netplane` module (compiler repoint + placement):**
- Modify: `netplane/controllers/compilednic.go` — placement propagation in `Compile()` + reconciler owning-VM resolution + VM watch.
- Modify: `netplane/controllers/compilednic_test.go` (or the existing compiler test file) — placement unit tests.
- Modify: netplane manager entrypoint (`netplane/cmd/.../main.go`) — point client at central + `WatchListClient=false`.

---

## Task 1: Shared versioned changes — `VirtualMachine` type + `CompiledNICSpec.ClusterName`

**Files:**
- Modify: `api/v1alpha1/compilednic_types.go`
- Create: `api/v1alpha1/virtualmachine_types.go`
- Modify: `api/v1alpha1/register.go`
- Regenerate: `api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/bases/*.yaml`

- [ ] **Step 1: Add `ClusterName` to `CompiledNICSpec`.** In `api/v1alpha1/compilednic_types.go`, add to the `CompiledNICSpec` struct (near `NodeName`):

```go
	// ClusterName is the cluster this compiled NIC is bound to (the pod->node
	// binding). Set by the compiler from the owning VirtualMachine's placement,
	// or the compiler's --cluster-name default for NICs with no owning VM.
	// The per-cluster broker selects on this field.
	ClusterName string `json:"clusterName,omitempty"`
```

- [ ] **Step 2: Create the `VirtualMachine` placement-anchor type.** Create `api/v1alpha1/virtualmachine_types.go`. It is namespaced, has a status subresource, and carries placement + NIC ownership ONLY (no KubeVirt VMI fields — that is Phase 4). Mirror the marker/style of `compilednic_types.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VirtualMachineSpec defines the desired state of a VirtualMachine.
//
// In Phase 1b the VirtualMachine is a PLACEMENT ANCHOR only: it names the
// cluster the workload is bound to and the NetworkInterfaces it owns. The
// compiler propagates ClusterName (and a workload=<name> label) onto the
// CompiledNICs of the referenced interfaces. VMI/volume lifecycle is Phase 4.
type VirtualMachineSpec struct {
	// ClusterName is the cluster this workload is bound to. Set manually or by
	// the compiler default in Phase 1b; the Phase-3 scheduler writes it later.
	ClusterName string `json:"clusterName,omitempty"`
	// InterfaceRefs names the NetworkInterfaces (same namespace) this VM owns.
	InterfaceRefs []LocalObjectReference `json:"interfaceRefs,omitempty"`
}

// VirtualMachineStatus defines the observed state of a VirtualMachine.
type VirtualMachineStatus struct {
	// Phase is the current lifecycle phase of the VirtualMachine.
	Phase string `json:"phase,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VirtualMachine is the placement anchor for a workload.
type VirtualMachine struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VirtualMachineSpec   `json:"spec,omitempty"`
	Status VirtualMachineStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// VirtualMachineList is a list of VirtualMachine objects.
type VirtualMachineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []VirtualMachine `json:"items"`
}
```

NOTE: `LocalObjectReference` — check whether `api/v1alpha1` already defines one (grep `type LocalObjectReference` in `api/v1alpha1`). If a suitable ref type already exists (e.g. the type used by `nic.Spec.VPCRef`), reuse it instead of adding a new one. If none exists, add `type LocalObjectReference struct { Name string \`json:"name"\` }` in a shared file (e.g. `api/v1alpha1/common_types.go`).

- [ ] **Step 3: Register the new type.** In `api/v1alpha1/register.go`, add to the `SchemeBuilder.Register(...)` / `addKnownTypes` list (mirror the existing `&CompiledNIC{}, &CompiledNICList{}` entry): `&VirtualMachine{}, &VirtualMachineList{}`.

- [ ] **Step 4: Regenerate deepcopy + CRDs.** From the repo root:

Run: `nix develop --command bash -c 'cd api && make generate' 2>&1 | tail -20`
(Or the api module's documented generate path — see the root `Makefile` `generate` target: `controller-gen object paths=./v1alpha1/...` then `controller-gen crd paths=./v1alpha1/... output:crd:artifacts:config=../config/crd/bases`. Run whichever the repo uses.)
Expected: `api/v1alpha1/zz_generated.deepcopy.go` gains `VirtualMachine`/`VirtualMachineList` DeepCopy + `ClusterName` carried; `config/crd/bases/net.ectobase.dev_virtualmachines.yaml` created; `..._compilednics.yaml` gains `spec.clusterName`.

- [ ] **Step 5: Build + vet the api module.**

Run: `nix develop --command bash -c 'cd api && go build ./... && go vet ./...' 2>&1 | tail`
Expected: exit 0.

- [ ] **Step 6: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add api/v1alpha1 config/crd/bases
git commit -m "feat(api): VirtualMachine placement anchor + CompiledNIC.spec.clusterName

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: CODEGEN SPIKE — one net type (`VPC`) served aggregated from central

**Purpose:** De-risk the single biggest unknown — generating internal↔versioned conversion for a versioned package that lives in the *external* `api` module. Wire ONE type end-to-end, prove it serves + round-trips, and **document the working codegen recipe in this task's commit message** so Task 3 is pure repetition.

**Files:**
- Create: `central/apis/net/doc.go`, `central/apis/net/register.go`, `central/apis/net/vpc_types.go`, `central/apis/net/vpc_rest.go`
- Create: `central/apis/net/v1alpha1/` (versioned alias package — exact shape TBD by this spike)
- Create: `central/apis/net/install/install.go`
- Modify: `central/hack/update-codegen.sh`
- Modify: `central/cmd/apiserver/main.go`
- Create: `central/test/net_envtest_test.go`

- [ ] **Step 1: Add the internal `VPC` type.** Create `central/apis/net/vpc_types.go` mirroring `api/v1alpha1/vpc_types.go`'s Spec/Status **fields** but in internal style (no json/protobuf tags), exactly as `central/apis/platform/clusterpool_types.go` mirrors its versioned form. Read `api/v1alpha1/vpc_types.go` first and copy field names/types verbatim into `VPCSpec`/`VPCStatus`. VPC is namespaced (do NOT add `+genclient:nonNamespaced`).

- [ ] **Step 2: Add `central/apis/net/vpc_rest.go`** implementing `resource.Object` (+ status subresource) exactly like `central/apis/platform/compiledworkload_rest.go`, EXCEPT `NamespaceScoped()` returns **true** and `GetGroupResource()` uses `SchemeGroupVersion.WithResource("vpcs")`. No SelectableFields for VPC (only CompiledNIC needs the field selector — Task 3).

```go
package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"go.opendefense.cloud/kit/apiserver/resource"
)

var (
	_ resource.Object                      = &VPC{}
	_ resource.ObjectWithStatusSubResource = &VPC{}
)

func (o *VPC) GetObjectMeta() *metav1.ObjectMeta { return &o.ObjectMeta }
func (o *VPC) NamespaceScoped() bool             { return true }
func (o *VPC) New() runtime.Object               { return &VPC{} }
func (o *VPC) NewList() runtime.Object           { return &VPCList{} }
func (o *VPC) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("vpcs").GroupResource()
}
func (o *VPC) CopyStatusTo(to runtime.Object) { to.(*VPC).Status = *o.Status.DeepCopy() }
```

- [ ] **Step 3: Add `central/apis/net/register.go` + `doc.go`.** Mirror `central/apis/platform/register.go` with `GroupName = "net.ectobase.dev"` and `addKnownTypes` registering `&VPC{}, &VPCList{}`. `doc.go`: package doc + `// +k8s:deepcopy-gen=package` + `// +groupName=net.ectobase.dev` (mirror `central/apis/platform/doc.go`).

- [ ] **Step 4: Establish the versioned package + codegen recipe (THE SPIKE).** The goal: kube::codegen must generate deepcopy/conversion/defaults for the internal `central/apis/net` against the versioned `net.ectobase.dev/v1alpha1` types, where the *canonical* versioned structs live in `api/v1alpha1`. Try, in order, and KEEP the first that produces a clean `go build` + generated conversions:

  **(a) Versioned alias package.** Create `central/apis/net/v1alpha1/aliases.go`:
  ```go
  package v1alpha1
  import netv1 "github.com/trevex/ectobase/api/v1alpha1"
  type VPC = netv1.VPC
  type VPCList = netv1.VPCList
  // ... + SchemeGroupVersion re-exported from netv1
  var SchemeGroupVersion = netv1.SchemeGroupVersion
  ```
  Extend `update-codegen.sh` so `gen_helpers` covers `central/apis` (already does) and the conversion pass sees this versioned subdir. Run codegen; if conversion-gen resolves the aliases to `api/v1alpha1` and emits `zz_generated.conversion.go`, **(a) wins**.

  **(b) Fallback — external peer dirs.** If aliases don't convert, drop the alias package and point kube::codegen/conversion-gen at the external versioned package via `--extra-peer-dirs`/input-package pointing at `github.com/trevex/ectobase/api/v1alpha1`. Consult `kube_codegen.sh` in the code-generator module for the exact flag names.

  **(c) Last-resort — thin re-export with hand-written conversion.** If neither generates, hand-write `Convert_net_VPC_To_v1alpha1_VPC` / reverse in `central/apis/net` (they are field-identical copies) and register them. Costs manual conversion funcs but unblocks; note it loudly in the commit as tech debt.

  Extend `central/hack/update-codegen.sh` accordingly (add the net group to whatever package args it passes). Then run:

  Run: `nix develop --command bash -c 'cd central && bash hack/update-codegen.sh' 2>&1 | tail -30`
  Expected: `central/apis/net/zz_generated.deepcopy.go` + `zz_generated.conversion.go` (+ defaults) generated; `central/client-go` updated with net types; no error.

- [ ] **Step 5: Install + serve VPC.** Create `central/apis/net/install/install.go` mirroring `central/apis/platform/install/install.go` (install internal + versioned + set conversions/defaults into the scheme). In `central/cmd/apiserver/main.go`: import `netapi "github.com/trevex/ectobase/central/apis/net"` + its install + `netv1 "github.com/trevex/ectobase/api/v1alpha1"`; call the net install in `init()` alongside `install.Install(scheme)`; add `.With(apiserver.Resource(&netapi.VPC{}, netv1.SchemeGroupVersion))` to the builder chain. Add the net group's openapi to `WithOpenAPIDefinitions` if the generator produced a separate defs func (check `central/client-go/openapi`).

- [ ] **Step 6: Build.**

Run: `nix develop --command bash -c 'cd central && go build ./...' 2>&1 | tail`
Expected: exit 0.

- [ ] **Step 7: Envtest — serve + roundtrip VPC.** Create `central/test/net_envtest_test.go` mirroring the ClusterPool CRUD test in `central/test/envtest_test.go` (same kit-aggregated fixture; add the net APIService if the harness needs a per-group APIService — check how `envtest_test.go` registers the platform APIService and replicate for `net.ectobase.dev`). Assert: create a `VPC` (namespaced) in a namespace, Get it back, fields intact.

Run: `nix develop --command bash -c 'cd central && go test ./test/ -run "VPC|ClusterPool" -v' 2>&1 | tail -30`
Expected: PASS.

- [ ] **Step 8: Commit — with the recipe documented.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/apis/net central/hack/update-codegen.sh central/cmd/apiserver/main.go central/client-go central/test/net_envtest_test.go central/go.mod central/go.sum
git commit -m "feat(central): serve net.ectobase.dev VPC from aggregated apiserver (codegen spike)

Establishes the internal(central/apis/net) <-> versioned(api/v1alpha1) codegen
recipe: <RECORD WHICH OF a/b/c WORKED AND THE EXACT update-codegen.sh CHANGE>.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Migrate the remaining net types + `VirtualMachine`; add `CompiledNIC` field selector

**Files:** `central/apis/net/<type>_types.go` + `<type>_rest.go` for each of `NetworkInterface`, `FirewallPolicy`, `FloatingIP`, `LoadBalancer`, `NATGateway`, `VPCPeering`, `CompiledNIC`, `VirtualMachine`; `central/apis/net/register.go`; `central/apis/net/v1alpha1/aliases.go`; `central/cmd/apiserver/main.go`; regenerated codegen; `central/test/net_envtest_test.go`.

- [ ] **Step 1: Add internal types for all remaining types.** For EACH type, read `api/v1alpha1/<type>_types.go` and create `central/apis/net/<type>_types.go` mirroring its Spec/Status/nested structs in internal style (no tags), exactly as VPC was done in Task 2. Include all nested types the type references (e.g. `CompiledNIC` pulls in `CompiledFirewall`, `CompiledFwRule`, `CompiledNATSource`, `CompiledLB`, `CompiledLBPort`, `CompiledPeerImport`, `PortStatus`; `VirtualMachine` pulls in `LocalObjectReference`). Field names/types must match verbatim so conversion is identity.

- [ ] **Step 2: Add `_rest.go` for each type.** Mirror Task 2's `vpc_rest.go`: all namespaced (`NamespaceScoped()→true`), each with its own `GetGroupResource()` plural (`networkinterfaces`, `firewallpolicies`, `floatingips`, `loadbalancers`, `natgateways`, `vpcpeerings`, `compilednics`, `virtualmachines`) and `CopyStatusTo`. **`CompiledNIC` additionally implements the field-selector hook** (mirror `compiledworkload_rest.go`):

```go
var (
	_ kitrest.SelectableFieldsProvider        = &CompiledNIC{}
	_ kitrest.SupportedFieldSelectorsProvider = &CompiledNIC{}
)

func (o *CompiledNIC) SelectableFields() fields.Set {
	return fields.Set{"spec.clusterName": o.Spec.ClusterName}
}
func (o *CompiledNIC) SupportedFieldSelectors() []string { return []string{"spec.clusterName"} }
```

- [ ] **Step 3: Register all + extend the alias package.** Add every type + its List to `central/apis/net/register.go` `addKnownTypes`, and add the corresponding `type X = netv1.X` aliases to `central/apis/net/v1alpha1/aliases.go` (all 8 high-level + VirtualMachine + all List types).

- [ ] **Step 4: Regenerate codegen.**

Run: `nix develop --command bash -c 'cd central && bash hack/update-codegen.sh' 2>&1 | tail -30`
Expected: deepcopy/conversion/defaults/openapi/client updated for all net types; no error. If conversion fails for a type, the field mirror drifted — diff it against `api/v1alpha1/<type>_types.go`.

- [ ] **Step 5: Serve all net types.** In `central/cmd/apiserver/main.go`, add a `.With(apiserver.Resource(&netapi.<T>{}, netv1.SchemeGroupVersion))` line for each of the remaining types (next to the VPC line).

- [ ] **Step 6: Build.**

Run: `nix develop --command bash -c 'cd central && go build ./...' 2>&1 | tail`
Expected: exit 0.

- [ ] **Step 7: Conversion roundtrip fuzz.** The platform types have a fuzz roundtrip test proving internal↔versioned conversion is lossless (memory: "Roundtrip fuzz-conversion test passes"). Find it (`grep -rl "roundtrip\|fuzzer\|RoundTripTest" central/apis`) and register the net internal types with the same fuzzer/roundtrip harness so all 9 net types are covered (mirror exactly how the platform types are wired into it). If the harness is per-group, add a net-group roundtrip test alongside it.

Run: `nix develop --command bash -c 'cd central && go test ./apis/... -run "RoundTrip|Roundtrip|Fuzz" -v' 2>&1 | tail -20`
Expected: PASS (lossless conversion for every net type).

- [ ] **Step 8: Envtest — CRUD a representative type + CompiledNIC field selector.** Extend `central/test/net_envtest_test.go`: (a) create/get a `NetworkInterface`; (b) create `CompiledNIC{spec.clusterName:c1}` in ns `default` + `CompiledNIC{spec.clusterName:c2}`, then `List(MatchingFields{"spec.clusterName":"c1"})` → exactly the c1 one (mirror `TestClusterPool_SpecFieldSelector` / the CompiledWorkload selector test). Namespaced list across namespaces.

Run: `nix develop --command bash -c 'cd central && go test ./test/ -run "Net|VPC|CompiledNIC|NetworkInterface" -v' 2>&1 | tail -30`
Expected: PASS (bounded selector returns exactly the bound set).

- [ ] **Step 9: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/apis/net central/cmd/apiserver/main.go central/client-go central/test/net_envtest_test.go
git commit -m "feat(central): serve all net.ectobase.dev types incl CompiledNIC (spec.clusterName selector)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Repoint the compiler to central + placement propagation (TDD)

**Files:** `netplane/controllers/compilednic.go`, its test file (`netplane/controllers/compilednic_test.go` — check exact name), netplane manager entrypoint.

- [ ] **Step 1: Write failing placement unit tests.** In the compiler test file, add tests for a new pure helper `resolvePlacement`. Contract: given a NIC and the list of VirtualMachines in its namespace + a default cluster name, return `Placement{ClusterName, WorkloadID}` — the owning VM's `spec.clusterName` + VM name when a VM's `interfaceRefs` names the NIC, else `{default, ""}`. And extend the `Compile` test: `Compile(...)` now takes a `Placement` and stamps `compiled.Spec.ClusterName` + (when `WorkloadID != ""`) `compiled.Labels["workload"] = WorkloadID`.

```go
func TestResolvePlacement(t *testing.T) {
	nic := &netv1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "nic-a"}}
	vms := []netv1.VirtualMachine{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1"},
		Spec:       netv1.VirtualMachineSpec{ClusterName: "edge1", InterfaceRefs: []netv1.LocalObjectReference{{Name: "nic-a"}}},
	}}
	got := resolvePlacement(nic, vms, "default-cluster")
	if got.ClusterName != "edge1" || got.WorkloadID != "vm1" {
		t.Fatalf("owned NIC: got %+v", got)
	}
	// NIC with no owning VM -> default, no workload id.
	orphan := &netv1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "nic-x"}}
	got = resolvePlacement(orphan, vms, "default-cluster")
	if got.ClusterName != "default-cluster" || got.WorkloadID != "" {
		t.Fatalf("orphan NIC: got %+v", got)
	}
}

func TestCompile_StampsPlacement(t *testing.T) {
	nic := &netv1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "nic-a"}, Spec: netv1.NetworkInterfaceSpec{IPs: []string{"10.0.0.1"}}}
	c := Compile(nic, 100, nil, nil, nil, nil, Placement{ClusterName: "edge1", WorkloadID: "vm1"})
	if c.Spec.ClusterName != "edge1" {
		t.Fatalf("clusterName not stamped: %q", c.Spec.ClusterName)
	}
	if c.Labels["workload"] != "vm1" {
		t.Fatalf("workload label not stamped: %v", c.Labels)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail.**

Run: `nix develop --command bash -c 'cd netplane && go test ./controllers/ -run "ResolvePlacement|Compile_StampsPlacement" -v' 2>&1 | tail`
Expected: FAIL (undefined `resolvePlacement`, `Placement`, and `Compile` arity mismatch).

- [ ] **Step 3: Implement `Placement` + `resolvePlacement` + `Compile` stamping.** In `netplane/controllers/compilednic.go`:

```go
// Placement is the cluster binding for a compiled object, resolved from the
// owning VirtualMachine (or the compiler default for NICs with no owning VM).
type Placement struct {
	ClusterName string
	WorkloadID  string // owning VM name; "" when defaulted (no workload label)
}

// resolvePlacement finds the VirtualMachine (same namespace) that owns nic via
// its spec.interfaceRefs and returns its placement; falls back to the default
// cluster name with no workload id when no VM owns the NIC.
func resolvePlacement(nic *netv1.NetworkInterface, vms []netv1.VirtualMachine, defaultCluster string) Placement {
	for i := range vms {
		for _, ref := range vms[i].Spec.InterfaceRefs {
			if ref.Name == nic.Name {
				return Placement{ClusterName: vms[i].Spec.ClusterName, WorkloadID: vms[i].Name}
			}
		}
	}
	return Placement{ClusterName: defaultCluster}
}
```

Change `Compile`'s signature to accept `placement Placement` (append it as the last param) and, after building `compiled`, stamp it:

```go
	compiled.Spec.ClusterName = placement.ClusterName
	if placement.WorkloadID != "" {
		if compiled.Labels == nil {
			compiled.Labels = map[string]string{}
		}
		compiled.Labels["workload"] = placement.WorkloadID
	}
```

- [ ] **Step 4: Run unit tests to verify pass.**

Run: `nix develop --command bash -c 'cd netplane && go test ./controllers/ -run "ResolvePlacement|Compile_StampsPlacement" -v' 2>&1 | tail`
Expected: PASS.

- [ ] **Step 5: Wire placement into the reconciler + add a default-cluster field + VM watch.** In `CompiledNICReconciler`: add field `DefaultClusterName string`. In `Reconcile`, before calling `Compile`, list VMs in the NIC namespace and resolve placement:

```go
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms, client.InNamespace(nic.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list virtualmachines: %w", err)
	}
	placement := resolvePlacement(&nic, vms.Items, r.DefaultClusterName)
	compiled := Compile(&nic, vni, policies.Items, lbs.Items, peerImports, natBySource, placement)
```

The existing `reflect.DeepEqual(existing.Spec, compiled.Spec)` short-circuit now also covers `ClusterName` (in Spec). The `workload` label lives in ObjectMeta, not Spec — on the update branch, also copy labels: after `existing.Spec = compiled.Spec`, add `existing.Labels = compiled.Labels`; and gate the "unchanged" short-circuit on labels too:

```go
	default:
		if reflect.DeepEqual(existing.Spec, compiled.Spec) && existing.Labels["workload"] == compiled.Labels["workload"] {
			return ctrl.Result{}, nil
		}
		existing.Spec = compiled.Spec
		if existing.Labels == nil {
			existing.Labels = map[string]string{}
		}
		existing.Labels["workload"] = compiled.Labels["workload"]
		if err := r.Client.Update(ctx, &existing); err != nil {
			return ctrl.Result{}, fmt.Errorf("update compilednic: %w", err)
		}
```

In `SetupWithManager`, add a VirtualMachine watch that re-enqueues its referenced NICs:

```go
		Watches(&netv1.VirtualMachine{}, handler.EnqueueRequestsFromMapFunc(r.nicsForVM)).
```

And add `nicsForVM` (mirror `nicsForVPC`): map a VM to reconcile requests for each `spec.interfaceRefs[].Name` in the VM's namespace.

- [ ] **Step 6: Repoint the netplane manager to central + `WatchListClient=false`.** Read the netplane manager entrypoint (find it: `grep -rl "NewManager\|SetupWithManager" netplane/cmd netplane/*.go`). Mirror `central/cmd/broker/main.go`: set `os.Setenv("KUBE_FEATURE_WatchListClient","false")` at the top of `main`; build the manager's rest.Config from a `--central-kubeconfig` flag (falling back to in-cluster/KUBECONFIG); add a `--cluster-name` flag wired into `CompiledNICReconciler.DefaultClusterName`. Keep the manager's scheme = `api/v1alpha1` AddToScheme (unchanged — central serves the same GVKs). If netplane has an envtest that stood up a plain CRD apiserver, it keeps working (the compiler logic is unchanged); only the live entrypoint targets central.

- [ ] **Step 7: Build + full netplane tests.**

Run: `nix develop --command bash -c 'cd netplane && go build ./... && go test ./controllers/... 2>&1 | tail -20'`
Expected: exit 0; existing compiler tests + the new placement tests PASS. (If an existing test constructs `Compile(...)` with the old arity, update those call sites to pass `Placement{ClusterName: "test"}`.)

- [ ] **Step 8: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add netplane/controllers netplane/cmd
git commit -m "feat(netplane): compiler stamps CompiledNIC.spec.clusterName from owning VM; target central

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Broker syncs the real namespaced `CompiledNIC` (TDD) + loopback envtest (the §9 gate)

**Files:** `central/internal/broker/broker.go`, `central/internal/broker/broker_test.go`, `central/cmd/broker/main.go`, `central/test/broker_test.go`.

Design note: `CompiledNIC` is **namespaced** (vs cluster-scoped `CompiledWorkload`). The engine switches its synced type to `CompiledNIC` and keys by `namespace/name`. `CompiledWorkload` stays a served type but is no longer brokered (it was always a stand-in). The broker imports the shared `api/v1alpha1` type. Downstream objects are created in the same namespace as central — the namespace must exist downstream (assume present, as with the existing agent CRD pattern; the loopback test creates it).

- [ ] **Step 1: Rewrite the broker unit test for namespaced `CompiledNIC`.** Replace `central/internal/broker/broker_test.go`'s `CompiledWorkload` usage with `netv1 "github.com/trevex/ectobase/api/v1alpha1"` `CompiledNIC`. Cover create/update/GC across TWO namespaces + bounded-by-clusterName. Register a field index on the fake central client for `spec.clusterName` (as the existing test does) so the same `MatchingFields` code path runs.

```go
func TestSync_NamespacedCreateUpdateGC(t *testing.T) {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil { t.Fatal(err) }
	wl := func(ns, name, cn, node string) *netv1.CompiledNIC {
		return &netv1.CompiledNIC{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec: netv1.CompiledNICSpec{ClusterName: cn, NodeName: node}}
	}
	idx := func(o client.Object) []string { return []string{o.(*netv1.CompiledNIC).Spec.ClusterName} }
	central := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&netv1.CompiledNIC{}, "spec.clusterName", idx).
		WithObjects(wl("ns1","a","c1","n1"), wl("ns2","b","c1","n2"), wl("ns1","c","c2","n3")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(wl("ns1","stale","c1","old"), wl("ns1","a","c1","OLD")).Build()

	b := &broker.Broker{Central: central, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncOnce(context.Background()); err != nil { t.Fatal(err) }

	list := &netv1.CompiledNICList{}
	if err := downstream.List(context.Background(), list); err != nil { t.Fatal(err) }
	// exactly {ns1/a(n1), ns2/b(n2)}: c is c2 (bounded out), stale GC'd, a updated.
	if len(list.Items) != 2 { t.Fatalf("want 2, got %d: %+v", len(list.Items), list.Items) }
	// (assert names/namespaces/NodeName == n1/n2)
}
```

Run → FAIL (broker still on CompiledWorkload).

- [ ] **Step 2: Generalize `SyncOnce` to namespaced `CompiledNIC`.** In `central/internal/broker/broker.go`: switch the import to `netv1 "github.com/trevex/ectobase/api/v1alpha1"`, the list/type to `CompiledNIC`/`CompiledNICList`, and key maps by `namespace/name` instead of `name`. Preserve `Namespace` on downstream create.

```go
func key(o *netv1.CompiledNIC) string { return o.Namespace + "/" + o.Name }

func (b *Broker) SyncOnce(ctx context.Context) error {
	desired := &netv1.CompiledNICList{}
	if err := b.Central.List(ctx, desired, client.MatchingFields{"spec.clusterName": b.ClusterName}); err != nil {
		return fmt.Errorf("list central: %w", err)
	}
	want := make(map[string]netv1.CompiledNIC, len(desired.Items))
	for _, o := range desired.Items { want[key(&o)] = o }

	have := &netv1.CompiledNICList{}
	if err := b.Downstream.List(ctx, have); err != nil { return fmt.Errorf("list downstream: %w", err) }
	haveKeys := make(map[string]bool, len(have.Items))
	for i := range have.Items {
		cur := &have.Items[i]
		haveKeys[key(cur)] = true
		w, ok := want[key(cur)]
		if !ok {
			if err := b.Downstream.Delete(ctx, cur); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("gc %s: %w", key(cur), err)
			}
			continue
		}
		if !equality.Semantic.DeepEqual(cur.Spec, w.Spec) {
			cur.Spec = w.Spec
			if err := b.Downstream.Update(ctx, cur); err != nil { return fmt.Errorf("update %s: %w", key(cur), err) }
		}
	}
	for k, w := range want {
		if haveKeys[k] { continue }
		local := &netv1.CompiledNIC{}
		local.Namespace = w.Namespace
		local.Name = w.Name
		local.Spec = w.Spec
		if err := b.Downstream.Create(ctx, local); err != nil { return fmt.Errorf("create %s: %w", k, err) }
	}
	return nil
}
```

NOTE: `CompiledNICSpec` has slices, so `cur.Spec != w.Spec` won't compile — use `equality.Semantic.DeepEqual` (`k8s.io/apimachinery/pkg/api/equality`). Update imports.

Run → PASS.

- [ ] **Step 3: Point `cmd/broker` at `CompiledNIC`.** In `central/cmd/broker/main.go`: replace the platform scheme install with `netv1.AddToScheme` (import `api/v1alpha1`), and the cache `ByObject`/controller `For` from `v1alpha1.CompiledWorkload{}` to `netv1.CompiledNIC{}` (field selector unchanged). Keep `KUBE_FEATURE_WatchListClient=false`.

- [ ] **Step 4: Rewrite the loopback envtest for `CompiledNIC`.** In `central/test/broker_test.go`, switch the synced type to `CompiledNIC`: central = kit-aggregated (now serving `CompiledNIC`), downstream = controller-runtime envtest with the `net.ectobase.dev_compilednics.yaml` CRD (from `config/crd/bases`). Create a downstream namespace `ns1`. Assert (mirror the existing structure): create `CompiledNIC{ns1, clusterName:c1}` + `{ns1, clusterName:c2}` in central → after `SyncOnce`, downstream has exactly the c1 one; update its `NodeName` → converges; delete → GC; stop central env → downstream object survives (partition).

Run: `nix develop --command bash -c 'cd central && go test ./test/ -run TestBroker_Loopback -v' 2>&1 | tail -30`
Expected: PASS.

- [ ] **Step 5: Full central build + test.**

Run: `nix develop --command bash -c 'cd central && go build ./... && go test ./... 2>&1 | grep -vE "no test files" | tail -20'`
Expected: green (some pre-existing `//go:build kine` durability test is skipped without the kine harness — that's fine).

- [ ] **Step 6: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/internal/broker central/cmd/broker central/test/broker_test.go
git commit -m "feat(central): broker syncs real namespaced CompiledNIC (loopback gate)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Single-cluster compile e2e + wrap

**Files:** `central/test/phase1b_e2e_test.go` (new), memory, branch finish.

- [ ] **Step 1: Write the single-cluster compile→bind→sync envtest.** New `central/test/phase1b_e2e_test.go`: central = kit-aggregated (serves the net group). In-process: create a `VirtualMachine{ns:default, clusterName:c1, interfaceRefs:[nic-a]}`, a `VPC`, and a `NetworkInterface{nic-a}` in central; run the `CompiledNICReconciler` (with `Client` = a controller-runtime client on central, `DefaultClusterName:"default"`) once against `nic-a`; assert a `CompiledNIC` `default-nic-a` exists in central with `spec.clusterName == "c1"` and label `workload=vm1`. Then run `broker.SyncOnce{ClusterName:"c1"}` into a downstream envtest (CRD installed, namespace `default` present) and assert it materializes; and a `clusterName:c2` VM's NIC does NOT cross. This chains compiler→binding→broker→downstream in one test.

(If standing up the reconciler in-process against the kit-aggregated server is awkward, split: assert the compiler stamping via the Task-4 reconciler envtest against central, and the broker sync via the Task-5 loopback test — together they cover the chain. Prefer the single chained test; fall back to the split only if the harness fights back, and note it.)

Run: `nix develop --command bash -c 'cd central && go test ./test/ -run Phase1b -v' 2>&1 | tail -30`
Expected: PASS.

- [ ] **Step 2: Full workspace build + tests.**

Run: `nix develop --command bash -c 'for m in api central netplane; do (cd $m && go build ./... && go test ./... 2>&1 | grep -vE "no test files"); done | tail -40'`
Expected: green across api/central/netplane. (Other modules — cni/flowplane — untouched; a quick `go build ./...` in each is a bonus check.)

- [ ] **Step 3: Commit the e2e test.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/test/phase1b_e2e_test.go
git commit -m "test(central): Phase 1b single-cluster compile->bind->sync e2e

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

- [ ] **Step 4: Update memory.** Update `central-apiserver-foundation.md` (or add a `phase1b-net-types-central.md` memory): net.ectobase.dev types served aggregated from central; the codegen recipe from Task 2 (which of a/b/c worked); `CompiledNIC.spec.clusterName` binding + field selector; `VirtualMachine` placement anchor (Phase-1b: placement only, no VMI); compiler repointed to central + stamps clusterName from owning VM (`--cluster-name` default for VM-less NICs); broker now syncs real namespaced CompiledNIC; loopback + compile-e2e gates green. Open: Phase 3 scheduler/failover, ClusterRestriction, container cross-cluster workload type, KubeVirt VMI lifecycle (Phase 4), the local apiserver-kit replace still unmerged. Update `MEMORY.md` index line.

- [ ] **Step 5: Finish the branch** via superpowers:finishing-a-development-branch (merge `feat/phase1b-net-types-central` to main; the local apiserver-kit `replace` caveat carries over — merge is fine per the Phase-1 decision).

---

## Notes for the executor

- **Additive to the running system**: `api/v1alpha1` stays the import path for agent/CNI — those modules do NOT change. Central gains the net group; netplane's compiler retargets its client.
- **The codegen spike (Task 2) is the gate for Tasks 3+** — do not fan out the 8 remaining types until the one-type recipe builds + serves + round-trips. Record the exact recipe in Task 2's commit so Task 3 is mechanical.
- **`WatchListClient=false`** on every aggregated-apiserver informer — now including the compiler's.
- **Declarative set-reconcile, namespaced keying** — derive from live sets each pass; slices ⇒ `equality.Semantic.DeepEqual`, not `==`.
- **Field-mirror discipline**: internal `central/apis/net` structs must match `api/v1alpha1` field-for-field or conversion-gen fails — diff on any conversion error.
- Run git-mutating tasks sequentially; envtest/codegen via the nix devShell.
- The loopback envtest (Task 5) is the standing single-cluster gate; the 2-cluster kind smoke is out of scope this phase (deferred with Phase 2's).
```
