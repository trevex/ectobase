# Phase 4 — KubeVirt VM Lifecycle (containerDisk) via CompiledVM + Downstream Materializer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A scheduled `VirtualMachine` boots a real KubeVirt VM: the compiler emits a `CompiledVM` (denormalized boot intent, `spec.clusterName`-bound like `CompiledNIC`), the broker syncs it downstream, and a new downstream vm-materializer turns it into a `kubevirt.io/v1.VirtualMachine` (containerDisk boot, `runStrategy` for Tier-1). No Ceph.

**Architecture:** `CompiledVM` is a new `net.ectobase.dev` compiled type (Phase-1b recipe: shared versioned in `api/v1alpha1`, central internal mirror + hand-conversion + fuzzer + served aggregated + downstream CRD). A new `CompiledVMReconciler` (netplane, against central) produces it via a pure `CompileVM`. The broker syncs `CompiledVM` alongside `CompiledNIC`. A new downstream binary `netplane/cmd/vm-materializer` reconciles local `CompiledVM` → `kubevirt.io/v1.VirtualMachine` via a pure `buildVM`. `kubevirt.io/api` is added to `netplane` only.

**Tech Stack:** Go 1.26.4 (workspace); `api` + `central` + `netplane` modules; apiserver-kit v0.3.4 (local replace); controller-runtime v0.24.1; `kubevirt.io/api` (NEW, netplane); envtest (kit-aggregated + controller-runtime + KubeVirt CRDs).

**Design doc:** `docs/superpowers/specs/2026-08-02-phase4-kubevirt-vm-lifecycle-design.md`.

**Non-negotiable carry-overs:**
- Net-group types use the Phase-1b recipe: shared versioned struct in `api/v1alpha1`, central internal mirror (`central/apis/net`) + **hand-written conversion** (`central/apis/net/v1alpha1/conversion.go`) + fuzzer entry, guarded by the roundtrip test; register + serve + downstream CRD via `make generate` + `central/hack/update-codegen.sh`. (Memory `[[phase1b-net-types-central]]` documents this; Phase-1b Task 3 did it for 8 types.)
- Every central-aggregated informer runs with `KUBE_FEATURE_WatchListClient=false` (now also the compiler's CompiledVM watch). The vm-materializer runs against a plain downstream cluster (no flag).
- Declarative set-reconcile, no in-memory diff; `equality.Semantic.DeepEqual` for slice-bearing specs.
- go 1.26.4 workspace; run go/codegen via `nix develop --command bash -c '...'`. Ignore stale go-1.26.0 LSP diagnostics.
- Additive only; keep the CompiledNIC/scheduler/broker-NIC paths byte-identical.

**Branch:** `feat/phase4-kubevirt-vm` off main (already created this session; verify `git branch --show-current`).

---

## File structure

**Types (api + central):**
- Modify: `api/v1alpha1/virtualmachine_types.go` — `Spec.Image`, `Spec.RunStrategy`.
- Create: `api/v1alpha1/compiledvm_types.go` — `CompiledVM`/`CompiledVMList`/`CompiledVMSpec`/`CompiledVMInterface`.
- Modify: `api/v1alpha1/register.go` — register CompiledVM.
- Create: `central/apis/net/compiledvm_types.go` + `compiledvm_rest.go` (internal + resource.Object + `spec.clusterName` field-selector hook).
- Modify: `central/apis/net/register.go`, `central/apis/net/v1alpha1/aliases.go`, `central/apis/net/v1alpha1/conversion.go` (hand conversion), `central/apis/net/fuzzer/fuzzer.go`, `central/cmd/apiserver/main.go` (serve).
- Regenerated: api deepcopy/CRDs; central codegen.

**Compiler (netplane):**
- Create: `netplane/controllers/compiledvm.go` (pure `CompileVM` + `CompiledVMReconciler`) + test.
- Modify: `netplane/cmd/controller/main.go` — register the reconciler.

**Broker (central):**
- Modify: `central/internal/broker/broker.go` — `SyncCompiledVMs` + a shared driver; `central/cmd/broker/main.go` — watch + field-select CompiledVM too.
- Modify/Create: `central/internal/broker/broker_test.go` + `central/test/broker_test.go` — CompiledVM sync coverage.

**vm-materializer (netplane):**
- Create: `netplane/controllers/vmmaterializer.go` (pure `buildVM` + `VMMaterializerReconciler`) + test.
- Create: `netplane/cmd/vm-materializer/main.go`.
- Modify: `netplane/go.mod` — add `kubevirt.io/api`.

**Tests:**
- Modify: `central/test/net_envtest_test.go` (CompiledVM CRUD + selector), `central/test/phase4_e2e_test.go` (new chained e2e), `netplane` materializer envtest.

---

## Task 1: Types — VirtualMachine boot fields + CompiledVM (Phase-1b recipe)

**Files:** `api/v1alpha1/{virtualmachine_types.go,compiledvm_types.go,register.go}`; `central/apis/net/{compiledvm_types.go,compiledvm_rest.go,register.go}`; `central/apis/net/v1alpha1/{aliases.go,conversion.go}`; `central/apis/net/fuzzer/fuzzer.go`; `central/cmd/apiserver/main.go`; regenerated codegen.

- [ ] **Step 1: Add VirtualMachine boot fields.** In `api/v1alpha1/virtualmachine_types.go`, add to `VirtualMachineSpec` (after `Resources`):

```go
	// Image is the containerDisk image the VM boots from (e.g. quay.io/containerdisks/fedora:41).
	// +optional
	Image string `json:"image,omitempty"`
	// RunStrategy is the KubeVirt run strategy (Always, RerunOnFailure, Manual, Halted).
	// Empty defaults to RerunOnFailure (Tier-1 local restart on node death).
	// +optional
	RunStrategy string `json:"runStrategy,omitempty"`
```

- [ ] **Step 2: Create the shared CompiledVM versioned type.** Create `api/v1alpha1/compiledvm_types.go` (mirror `compilednic_types.go`'s marker/style):

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledVMSpec is the fully lowered, ready-to-materialize boot intent for a VM:
// the containerDisk image, compute resources, run strategy, the cluster binding,
// and the per-interface MAC + overlay network name. A downstream materializer
// turns this into a kubevirt.io/v1.VirtualMachine.
type CompiledVMSpec struct {
	// ClusterName is the cluster this compiled VM is bound to (the pod->node binding).
	// The per-cluster broker selects on this field.
	// +optional
	ClusterName string `json:"clusterName,omitempty"`
	// Image is the containerDisk image to boot from.
	Image string `json:"image,omitempty"`
	// Resources is the compute request/limit; maps to the KubeVirt domain resources.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// RunStrategy is the KubeVirt run strategy (defaulted upstream by the compiler).
	// +optional
	RunStrategy string `json:"runStrategy,omitempty"`
	// Interfaces are the VM's overlay interfaces (one per owned NetworkInterface).
	// +optional
	Interfaces []CompiledVMInterface `json:"interfaces,omitempty"`
}

// CompiledVMInterface is a resolved overlay interface for a VM: the pinned MAC
// and the multus network (NetworkAttachmentDefinition) name for the flowplane binding.
type CompiledVMInterface struct {
	// MAC is the pinned L2 address (from the NetworkInterface).
	MAC string `json:"mac,omitempty"`
	// NetworkName is the multus NetworkAttachmentDefinition name for the overlay binding.
	NetworkName string `json:"networkName,omitempty"`
}

// CompiledVMStatus is the observed state of a CompiledVM.
type CompiledVMStatus struct {
	// State is the materialization state (e.g. Applied, Pending).
	State string `json:"state,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// CompiledVM is the lowered boot intent for a scheduled VirtualMachine.
type CompiledVM struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CompiledVMSpec   `json:"spec,omitempty"`
	Status CompiledVMStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// CompiledVMList is a list of CompiledVM objects.
type CompiledVMList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CompiledVM `json:"items"`
}
```

- [ ] **Step 3: Register in the api scheme.** In `api/v1alpha1/register.go`, add `&CompiledVM{}, &CompiledVMList{}` to the known-types list (mirror `&CompiledNIC{}, &CompiledNICList{}`).

- [ ] **Step 4: Regenerate api deepcopy + CRD.**

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp && make generate' 2>&1 | tail -12`
Expected: `api/v1alpha1/zz_generated.deepcopy.go` gains CompiledVM/CompiledVMList/CompiledVMSpec/CompiledVMInterface/CompiledVMStatus DeepCopy; `config/crd/bases/net.ectobase.dev_compiledvms.yaml` created (+ chart crd-bases sync); VirtualMachine CRD gains `spec.image`, `spec.runStrategy`.

- [ ] **Step 5: Central internal mirror + rest + register + alias + conversion + fuzzer + serve** — follow the Phase-1b recipe EXACTLY (memory `[[phase1b-net-types-central]]`; the same steps Phase-1b Task 3 did per type):
  - `central/apis/net/compiledvm_types.go` — internal `CompiledVM`/`CompiledVMList`/`CompiledVMSpec`/`CompiledVMInterface`/`CompiledVMStatus` mirroring the versioned fields VERBATIM (no json tags). Reuse the internal net-group's shared types where present.
  - `central/apis/net/compiledvm_rest.go` — mirror `compilednic_rest.go`: `resource.Object` + status subresource, `NamespaceScoped()→true`, `GetGroupResource()→WithResource("compiledvms")`, PLUS the field-selector hook (`SelectableFields`/`SupportedFieldSelectors` returning `spec.clusterName`, exactly like `compilednic_rest.go`).
  - `central/apis/net/register.go` — add `&CompiledVM{}, &CompiledVMList{}`.
  - `central/apis/net/v1alpha1/aliases.go` — add `type CompiledVM = netv1.CompiledVM` + `type CompiledVMList = netv1.CompiledVMList`.
  - `central/apis/net/v1alpha1/conversion.go` — hand-written field-identity `Convert_*` (both directions) for CompiledVM/List/Spec/Interface/Status + register in `RegisterConversions` (follow the CompiledNIC block; slice `Interfaces` looped, `Resources` deep-copied).
  - `central/apis/net/fuzzer/fuzzer.go` — add the CompiledVMSpec entry if the harness needs one.
  - `central/cmd/apiserver/main.go` — add `.With(apiserver.Resource(&netapi.CompiledVM{}, netv1.SchemeGroupVersion))`.

- [ ] **Step 6: Regenerate central codegen + build + fuzz.**

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && bash hack/update-codegen.sh && go build ./... && go test ./apis/... -run "RoundTrip|Roundtrip" 2>&1 | tail -12'`
Expected: codegen clean; build clean; net roundtrip fuzz PASS (proves CompiledVM conversion lossless). If it fails, a field drifted between the internal + versioned CompiledVM — diff them.

- [ ] **Step 7: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add api/v1alpha1 config/crd deploy/charts central/apis central/client-go central/cmd/apiserver/main.go
git commit -m "feat(api,central): VirtualMachine image/runStrategy + CompiledVM type

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: CompileVM + CompiledVMReconciler (TDD)

**Files:** `netplane/controllers/compiledvm.go`, `netplane/controllers/compiledvm_test.go`, `netplane/cmd/controller/main.go`.

Context: `resolvePlacement(nic|vm, vms, default)` and `Placement{ClusterName, WorkloadID}` already exist in `netplane/controllers/compilednic.go` (Phase 1b) — REUSE them. The NIC MAC is `NetworkInterface.Spec.MAC` (`api/v1alpha1/networkinterface_types.go:23`). The compiler runs against central (Phase 1b repointed it).

- [ ] **Step 1: Write the failing unit test** `netplane/controllers/compiledvm_test.go`:

```go
package controllers

import (
	"testing"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

func TestCompileVM(t *testing.T) {
	vm := &netv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1"},
		Spec: netv1.VirtualMachineSpec{
			ClusterName:   "c1",
			Image:         "quay.io/containerdisks/fedora:41",
			InterfaceRefs: []netv1.LocalObjectReference{{Name: "nic-a"}},
			Resources:     corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")}},
		},
	}
	nics := []netv1.NetworkInterface{{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "nic-a"}, Spec: netv1.NetworkInterfaceSpec{MAC: "02:00:00:00:00:01"}}}

	cvm := CompileVM(vm, nics, Placement{ClusterName: "c1", WorkloadID: "vm1"}, "flowplane-overlay")

	if cvm.Name != "ns-vm1" || cvm.Namespace != "ns" { t.Fatalf("name/ns: %s/%s", cvm.Namespace, cvm.Name) }
	if cvm.Spec.ClusterName != "c1" { t.Fatalf("clusterName: %q", cvm.Spec.ClusterName) }
	if cvm.Labels["workload"] != "vm1" { t.Fatalf("workload label: %v", cvm.Labels) }
	if cvm.Spec.Image != "quay.io/containerdisks/fedora:41" { t.Fatalf("image: %q", cvm.Spec.Image) }
	if cvm.Spec.RunStrategy != "RerunOnFailure" { t.Fatalf("runStrategy default: %q", cvm.Spec.RunStrategy) }
	if len(cvm.Spec.Interfaces) != 1 || cvm.Spec.Interfaces[0].MAC != "02:00:00:00:00:01" || cvm.Spec.Interfaces[0].NetworkName != "flowplane-overlay" {
		t.Fatalf("interfaces: %+v", cvm.Spec.Interfaces)
	}
	if cvm.Spec.Resources.Requests.Memory().Cmp(resource.MustParse("1Gi")) != 0 { t.Fatalf("mem: %v", cvm.Spec.Resources.Requests.Memory()) }
}
```
Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/netplane && go test ./controllers/ -run TestCompileVM -v 2>&1 | tail'` → FAIL.

- [ ] **Step 2: Implement `netplane/controllers/compiledvm.go`.**

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"reflect"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// defaultRunStrategy is stamped when a VM leaves RunStrategy empty: KubeVirt
// restarts the VMI on another node on node death (Tier-1 local self-heal).
const defaultRunStrategy = "RerunOnFailure"

// CompileVM lowers a VirtualMachine into a CompiledVM: containerDisk image, compute
// resources, run strategy (defaulted), the cluster binding (from placement), and
// one resolved overlay interface (MAC + networkName) per owned NetworkInterface.
func CompileVM(vm *netv1.VirtualMachine, nics []netv1.NetworkInterface, placement Placement, networkName string) netv1.CompiledVM {
	runStrategy := vm.Spec.RunStrategy
	if runStrategy == "" {
		runStrategy = defaultRunStrategy
	}
	macByNIC := map[string]string{}
	for i := range nics {
		macByNIC[nics[i].Name] = nics[i].Spec.MAC
	}
	var ifaces []netv1.CompiledVMInterface
	for _, ref := range vm.Spec.InterfaceRefs {
		ifaces = append(ifaces, netv1.CompiledVMInterface{MAC: macByNIC[ref.Name], NetworkName: networkName})
	}
	compiled := netv1.CompiledVM{
		TypeMeta:   metav1.TypeMeta{APIVersion: "net.ectobase.dev/v1alpha1", Kind: "CompiledVM"},
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%s", vm.Namespace, vm.Name), Namespace: vm.Namespace},
		Spec: netv1.CompiledVMSpec{
			ClusterName: placement.ClusterName,
			Image:       vm.Spec.Image,
			Resources:   *vm.Spec.Resources.DeepCopy(),
			RunStrategy: runStrategy,
			Interfaces:  ifaces,
		},
	}
	if placement.WorkloadID != "" {
		compiled.Labels = map[string]string{"workload": placement.WorkloadID}
	}
	return compiled
}

// CompiledVMReconciler watches VirtualMachines and upserts their CompiledVM.
type CompiledVMReconciler struct {
	Client      client.Client
	NetworkName string // the multus NAD name for the flowplane overlay binding
}

func (r *CompiledVMReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vm netv1.VirtualMachine
	if err := r.Client.Get(ctx, req.NamespacedName, &vm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Resolve the VM's owned NICs (same namespace) for their MACs.
	var nicList netv1.NetworkInterfaceList
	if err := r.Client.List(ctx, &nicList, client.InNamespace(vm.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list nics: %w", err)
	}
	placement := Placement{ClusterName: vm.Spec.ClusterName, WorkloadID: vm.Name}
	compiled := CompileVM(&vm, nicList.Items, placement, r.NetworkName)
	key := types.NamespacedName{Namespace: compiled.Namespace, Name: compiled.Name}
	var existing netv1.CompiledVM
	err := r.Client.Get(ctx, key, &existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := controllerutil.SetControllerReference(&vm, &compiled, r.Client.Scheme()); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Client.Create(ctx, &compiled); err != nil {
			return ctrl.Result{}, fmt.Errorf("create compiledvm: %w", err)
		}
	case err != nil:
		return ctrl.Result{}, err
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
			return ctrl.Result{}, fmt.Errorf("update compiledvm: %w", err)
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager watches VirtualMachines (Owns their CompiledVMs) and re-enqueues
// a VM when one of its NetworkInterfaces changes (MAC).
func (r *CompiledVMReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.VirtualMachine{}).
		Owns(&netv1.CompiledVM{}).
		Watches(&netv1.NetworkInterface{}, handler.EnqueueRequestsFromMapFunc(r.vmsForNIC)).
		Complete(r)
}

// vmsForNIC maps a NetworkInterface event to reconcile requests for every VM in the
// same namespace that references it.
func (r *CompiledVMReconciler) vmsForNIC(ctx context.Context, obj client.Object) []reconcile.Request {
	nic, ok := obj.(*netv1.NetworkInterface)
	if !ok {
		return nil
	}
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms, client.InNamespace(nic.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range vms.Items {
		for _, ref := range vms.Items[i].Spec.InterfaceRefs {
			if ref.Name == nic.Name {
				reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: vms.Items[i].Namespace, Name: vms.Items[i].Name}})
				break
			}
		}
	}
	return reqs
}
```
Run the unit test → PASS.

- [ ] **Step 3: Register the reconciler.** In `netplane/cmd/controller/main.go`, next to the `CompiledNICReconciler` registration, add:
```go
	if err := (&controllers.CompiledVMReconciler{Client: mgr.GetClient(), NetworkName: networkName}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup compiledvm reconciler: %v", err)
	}
```
Add a `--network-name` flag (default `flowplane-overlay`) → `networkName`, mirroring how `--cluster-name` is wired. (This is the multus NAD name for the overlay binding.)

- [ ] **Step 4: Build + full controllers test.**

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/netplane && go build ./... && go test ./controllers/... 2>&1 | tail -15'`
Expected: build clean; TestCompileVM + existing compiler tests PASS.

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add netplane/controllers/compiledvm.go netplane/controllers/compiledvm_test.go netplane/cmd/controller
git commit -m "feat(netplane): compiler emits CompiledVM from scheduled VirtualMachine

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Broker syncs CompiledVM too (TDD)

**Files:** `central/internal/broker/broker.go`, `central/internal/broker/broker_test.go`, `central/cmd/broker/main.go`, `central/test/broker_test.go`.

Design: keep the existing `SyncOnce` (CompiledNIC) byte-identical; add `SyncCompiledVMs` (an explicit twin for CompiledVM — a namespaced set-reconcile keyed by namespace/name, field-selected by `spec.clusterName`, `equality.Semantic.DeepEqual` on Spec). The broker's reconcile calls BOTH. The broker cmd watches + field-selects both types. (Explicit twin over generics: the Phase-1b "concrete over generic" philosophy; ~35 lines, clear + low-risk.)

- [ ] **Step 1: Write the failing unit test** in `central/internal/broker/broker_test.go` (add alongside the CompiledNIC test):

```go
func TestSyncCompiledVMs_NamespacedCreateUpdateGC(t *testing.T) {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil { t.Fatal(err) }
	vm := func(ns, name, cn, img string) *netv1.CompiledVM {
		return &netv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: netv1.CompiledVMSpec{ClusterName: cn, Image: img}}
	}
	idx := func(o client.Object) []string { return []string{o.(*netv1.CompiledVM).Spec.ClusterName} }
	central := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&netv1.CompiledVM{}, "spec.clusterName", idx).
		WithObjects(vm("ns1", "a", "c1", "fedora"), vm("ns1", "b", "c2", "x")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(vm("ns1", "stale", "c1", "old"), vm("ns1", "a", "c1", "OLD")).Build()

	b := &Broker{Central: central, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncCompiledVMs(context.Background()); err != nil { t.Fatal(err) }

	list := &netv1.CompiledVMList{}
	if err := downstream.List(context.Background(), list); err != nil { t.Fatal(err) }
	if len(list.Items) != 1 { t.Fatalf("want 1 (a), got %d: %+v", len(list.Items), list.Items) }
	if list.Items[0].Name != "a" || list.Items[0].Spec.Image != "fedora" { t.Fatalf("want a(fedora), got %+v", list.Items[0]) }
}
```
Run → FAIL (no SyncCompiledVMs).

- [ ] **Step 2: Implement `SyncCompiledVMs`** in `central/internal/broker/broker.go` (mirror `SyncOnce`, swap the type; add a `keyVM` helper):

```go
// keyVM identifies a namespaced CompiledVM as "namespace/name".
func keyVM(o *netv1.CompiledVM) string { return o.Namespace + "/" + o.Name }

// SyncCompiledVMs is the CompiledVM twin of SyncOnce: declarative set-reconcile of
// CompiledVMs bound to ClusterName, central->downstream (create/update/delete).
func (b *Broker) SyncCompiledVMs(ctx context.Context) error {
	desired := &netv1.CompiledVMList{}
	if err := b.Central.List(ctx, desired, client.MatchingFields{"spec.clusterName": b.ClusterName}); err != nil {
		return fmt.Errorf("list central vms: %w", err)
	}
	want := make(map[string]netv1.CompiledVM, len(desired.Items))
	for _, o := range desired.Items {
		want[keyVM(&o)] = o
	}
	have := &netv1.CompiledVMList{}
	if err := b.Downstream.List(ctx, have); err != nil {
		return fmt.Errorf("list downstream vms: %w", err)
	}
	haveKeys := make(map[string]bool, len(have.Items))
	for i := range have.Items {
		cur := &have.Items[i]
		haveKeys[keyVM(cur)] = true
		w, ok := want[keyVM(cur)]
		if !ok {
			if err := b.Downstream.Delete(ctx, cur); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("gc vm %s: %w", keyVM(cur), err)
			}
			continue
		}
		if !equality.Semantic.DeepEqual(cur.Spec, w.Spec) {
			cur.Spec = w.Spec
			if err := b.Downstream.Update(ctx, cur); err != nil {
				return fmt.Errorf("update vm %s: %w", keyVM(cur), err)
			}
		}
	}
	for k, w := range want {
		if haveKeys[k] {
			continue
		}
		local := &netv1.CompiledVM{}
		local.Namespace = w.Namespace
		local.Name = w.Name
		local.Spec = w.Spec
		if err := b.Downstream.Create(ctx, local); err != nil {
			return fmt.Errorf("create vm %s: %w", k, err)
		}
	}
	return nil
}
```
Run → PASS.

- [ ] **Step 3: Broker cmd watches + field-selects CompiledVM too; reconcile calls both.** In `central/cmd/broker/main.go`:
  - Add `&netv1.CompiledVM{}` to the cache `ByObject` map with the SAME `spec.clusterName` field selector as CompiledNIC.
  - Add a second `.Watches(&netv1.CompiledVM{}, ...)` OR a second controller — simplest: the reconciler already does a full sync on any event; register a second controller `ctrl.NewControllerManagedBy(mgr).For(&netv1.CompiledVM{}).Complete(r)` so a CompiledVM event also triggers the reconciler. (r ignores the request.)
  - In `brokerReconciler.Reconcile`, after `b.SyncOnce(ctx)`, also call `b.SyncCompiledVMs(ctx)` (return on first error):
```go
	if err := b.SyncOnce(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := b.SyncCompiledVMs(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
```

- [ ] **Step 4: Extend the loopback envtest.** In `central/test/broker_test.go`, add CompiledVM alongside the CompiledNIC assertions (the downstream env already installs the net CRDs from `config/crd/bases`; ensure `net.ectobase.dev_compiledvms.yaml` is picked up): create `CompiledVM{ns, clusterName:c1}` + `{clusterName:c2}` in central → after a sync, downstream has exactly the c1 one; the CompiledNIC path still passes. (Either call `b.SyncCompiledVMs` directly or reuse the manager path.)

- [ ] **Step 5: Build + broker tests + loopback.**

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go build ./... && go test ./internal/broker/... && go test ./test/ -run TestBroker_Loopback -v 2>&1 | tail -20'`
Expected: build clean; unit + loopback PASS (CompiledNIC AND CompiledVM synced, bounded, GC'd).

- [ ] **Step 6: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/internal/broker central/cmd/broker central/test/broker_test.go
git commit -m "feat(central): broker syncs CompiledVM alongside CompiledNIC

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: vm-materializer — kubevirt.io/api spike + buildVM + controller (TDD)

**Files:** `netplane/go.mod`; `netplane/controllers/vmmaterializer.go`, `netplane/controllers/vmmaterializer_test.go`; `netplane/cmd/vm-materializer/main.go`; a materializer envtest.

- [ ] **Step 1: SPIKE — add `kubevirt.io/api` + prove CRDs load in envtest.** Add `kubevirt.io/api` to `netplane/go.mod` (pick a stable release compatible with the workspace's k8s v0.36 / apimachinery — check `kubevirt.io/api`'s go.mod for its k8s.io dep floor; if it forces an incompatible k8s bump, pin the newest release whose deps are satisfiable, and record it). Run `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/netplane && go get kubevirt.io/api@<ver> && go mod tidy'`. Write a MINIMAL envtest `netplane/controllers/vmmaterializer_test.go` that (a) registers `kubevirtv1.AddToScheme`, (b) stands up a controller-runtime `envtest.Environment` with the KubeVirt `VirtualMachine` CRD installed (locate the CRD yaml shipped in the `kubevirt.io/api` module — e.g. under its `crds`/`generated` dir — and point `CRDDirectoryPaths` at it; if it doesn't ship a usable CRD, vendor the `virtualmachines.kubevirt.io` CRD yaml into `netplane/test/crds/`), (c) creates a trivial `kubevirtv1.VirtualMachine` and gets it back. This de-risks the dep + CRD-in-envtest before the full mapping.

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/netplane && go build ./... && go test ./controllers/ -run TestKubeVirtCRDLoads -v 2>&1 | tail -20'`
Expected: build clean; the trivial VM create/get PASS. RECORD the kubevirt.io/api version + where the CRD yaml came from in the eventual commit. If the CRD genuinely can't be loaded in envtest after real effort, report NEEDS_CONTEXT with specifics (fallback: assert `buildVM`'s output object purely as a unit test without envtest, and defer the served-CRD assertion).

- [ ] **Step 2: Write the failing `buildVM` unit test** `netplane/controllers/vmmaterializer_test.go` (add to the file):

```go
func TestBuildVM(t *testing.T) {
	cvm := &netv1.CompiledVM{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ns-vm1", Labels: map[string]string{"workload": "vm1"}},
		Spec: netv1.CompiledVMSpec{
			Image:       "quay.io/containerdisks/fedora:41",
			RunStrategy: "RerunOnFailure",
			Resources:   corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")}},
			Interfaces:  []netv1.CompiledVMInterface{{MAC: "02:00:00:00:00:01", NetworkName: "flowplane-overlay"}},
		},
	}
	vm := buildVM(cvm)
	if vm.Name != "ns-vm1" || vm.Namespace != "ns" { t.Fatalf("meta: %s/%s", vm.Namespace, vm.Name) }
	if vm.Spec.RunStrategy == nil || *vm.Spec.RunStrategy != kubevirtv1.RunStrategyRerunOnFailure { t.Fatalf("runStrategy: %v", vm.Spec.RunStrategy) }
	vols := vm.Spec.Template.Spec.Volumes
	if len(vols) != 1 || vols[0].ContainerDisk == nil || vols[0].ContainerDisk.Image != "quay.io/containerdisks/fedora:41" { t.Fatalf("volumes: %+v", vols) }
	ifaces := vm.Spec.Template.Spec.Domain.Devices.Interfaces
	if len(ifaces) != 1 || ifaces[0].MacAddress != "02:00:00:00:00:01" { t.Fatalf("interfaces: %+v", ifaces) }
	nets := vm.Spec.Template.Spec.Networks
	if len(nets) != 1 || nets[0].Multus == nil || nets[0].Multus.NetworkName != "flowplane-overlay" { t.Fatalf("networks: %+v", nets) }
	if vm.Spec.Template.Spec.Domain.Resources.Requests.Memory().Cmp(resource.MustParse("1Gi")) != 0 { t.Fatalf("mem: %v", vm.Spec.Template.Spec.Domain.Resources.Requests.Memory()) }
}
```
Run → FAIL (no buildVM). NOTE: the exact KubeVirt field paths (`ContainerDisk.Image`, `Domain.Devices.Interfaces[].MacAddress`, `Networks[].Multus.NetworkName`, `RunStrategy` enum consts, the interface binding field) must match the pinned `kubevirt.io/api` version — ADJUST field names to the actual API surface (read the pinned package). The interface binding for the flowplane tap: use the appropriate binding (a `Binding: &kubevirtv1.PluginBinding{Name: ...}` if the flowplane binding plugin is registered, or `Bridge`/`Masquerade` as the API provides) — confirm against the kubevirt version + `config/deploy/kubevirt-binding.yaml`; the test asserts MacAddress + the multus network which are stable.

- [ ] **Step 3: Implement `buildVM` + the reconciler** in `netplane/controllers/vmmaterializer.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	kubevirtv1 "kubevirt.io/api/core/v1"
)

// runStrategy maps our string to the KubeVirt enum (unknown -> RerunOnFailure).
func runStrategy(s string) kubevirtv1.VirtualMachineRunStrategy {
	switch kubevirtv1.VirtualMachineRunStrategy(s) {
	case kubevirtv1.RunStrategyAlways, kubevirtv1.RunStrategyManual, kubevirtv1.RunStrategyHalted, kubevirtv1.RunStrategyRerunOnFailure:
		return kubevirtv1.VirtualMachineRunStrategy(s)
	default:
		return kubevirtv1.RunStrategyRerunOnFailure
	}
}

// buildVM turns a CompiledVM into a kubevirt.io/v1.VirtualMachine (containerDisk boot,
// pinned-MAC overlay interfaces on the flowplane multus network). Pure: no I/O.
func buildVM(cvm *netv1.CompiledVM) *kubevirtv1.VirtualMachine {
	rs := runStrategy(cvm.Spec.RunStrategy)
	disks := []kubevirtv1.Disk{{Name: "containerdisk", DiskDevice: kubevirtv1.DiskDevice{Disk: &kubevirtv1.DiskTarget{Bus: kubevirtv1.DiskBusVirtio}}}}
	volumes := []kubevirtv1.Volume{{Name: "containerdisk", VolumeSource: kubevirtv1.VolumeSource{ContainerDisk: &kubevirtv1.ContainerDiskSource{Image: cvm.Spec.Image}}}}
	var ifaces []kubevirtv1.Interface
	var networks []kubevirtv1.Network
	for i, in := range cvm.Spec.Interfaces {
		name := fmt.Sprintf("net%d", i)
		ifaces = append(ifaces, kubevirtv1.Interface{Name: name, MacAddress: in.MAC, Binding: &kubevirtv1.PluginBinding{Name: "flowplane"}})
		networks = append(networks, kubevirtv1.Network{Name: name, NetworkSource: kubevirtv1.NetworkSource{Multus: &kubevirtv1.MultusNetwork{NetworkName: in.NetworkName}}})
	}
	vm := &kubevirtv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: cvm.Namespace, Name: cvm.Name, Labels: map[string]string{"workload": cvm.Labels["workload"]}},
		Spec: kubevirtv1.VirtualMachineSpec{
			RunStrategy: &rs,
			Template: &kubevirtv1.VirtualMachineInstanceTemplateSpec{
				Spec: kubevirtv1.VirtualMachineInstanceSpec{
					Domain: kubevirtv1.DomainSpec{
						Resources: kubevirtv1.ResourceRequirements{Requests: cvm.Spec.Resources.Requests},
						Devices:   kubevirtv1.Devices{Disks: disks, Interfaces: ifaces},
					},
					Volumes:  volumes,
					Networks: networks,
				},
			},
		},
	}
	return vm
}

// VMMaterializerReconciler turns local CompiledVMs into KubeVirt VirtualMachines.
type VMMaterializerReconciler struct{ Client client.Client }

func (r *VMMaterializerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cvm netv1.CompiledVM
	if err := r.Client.Get(ctx, req.NamespacedName, &cvm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	desired := buildVM(&cvm)
	key := types.NamespacedName{Namespace: desired.Namespace, Name: desired.Name}
	var existing kubevirtv1.VirtualMachine
	err := r.Client.Get(ctx, key, &existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := ctrl.SetControllerReference(&cvm, desired, r.Client.Scheme()); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Client.Create(ctx, desired); err != nil {
			return ctrl.Result{}, fmt.Errorf("create vm: %w", err)
		}
	case err != nil:
		return ctrl.Result{}, err
	default:
		if !equality.Semantic.DeepEqual(existing.Spec, desired.Spec) {
			existing.Spec = desired.Spec
			if err := r.Client.Update(ctx, &existing); err != nil {
				return ctrl.Result{}, fmt.Errorf("update vm: %w", err)
			}
		}
	}
	return ctrl.Result{}, nil
}

func (r *VMMaterializerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.CompiledVM{}).
		Owns(&kubevirtv1.VirtualMachine{}).
		Complete(r)
}
```
IMPORTANT: `ctrl.SetControllerReference` here sets a CompiledVM→VirtualMachine owner ref for downstream GC. If the KubeVirt scheme + CompiledVM scheme aren't both registered on the materializer's manager, this fails — Step 4 registers both. ADJUST any field name (`PluginBinding`, `RunStrategyRerunOnFailure`, `ContainerDiskSource`, `DiskBusVirtio`, `ResourceRequirements`) to the pinned kubevirt.io/api surface. Run the `buildVM` test → PASS.

- [ ] **Step 4: Materializer entrypoint** `netplane/cmd/vm-materializer/main.go`: a controller-runtime manager on the DOWNSTREAM config (default in-cluster / `--kubeconfig`). Scheme installs `netv1.AddToScheme` (CompiledVM) + `kubevirtv1.AddToScheme` (VirtualMachine) + `metav1.AddToGroupVersion`. Register `(&controllers.VMMaterializerReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr)`. Metrics BindAddress "0". No `WatchListClient` env needed (downstream is a plain cluster, not the aggregated apiserver). Model the manager wiring on `netplane/cmd/controller/main.go` but WITHOUT `--central-kubeconfig`/`WatchListClient` (it's downstream).

- [ ] **Step 5: Materializer envtest — CompiledVM → KubeVirt VM.** Extend the Task-1 spike envtest (or add `TestMaterializer_CreatesVM`): downstream envtest with BOTH the CompiledVM CRD (`config/crd/bases/net.ectobase.dev_compiledvms.yaml`) AND the KubeVirt VirtualMachine CRD installed; create a `CompiledVM`; run `VMMaterializerReconciler.Reconcile`; assert a `kubevirtv1.VirtualMachine` exists with the right image/runStrategy/interface-MAC/multus-network. (No running virt-controller — just the API object.)

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/netplane && go build ./... && go test ./controllers/ -run "BuildVM|Materializer|KubeVirtCRD" -v 2>&1 | tail -25'`
Expected: PASS.

- [ ] **Step 6: Commit** (record the kubevirt.io/api version + CRD source).

```bash
cd /home/nik/Development/ironcore-net-xdp
git add netplane/controllers/vmmaterializer.go netplane/controllers/vmmaterializer_test.go netplane/cmd/vm-materializer netplane/go.mod netplane/go.sum netplane/test
git commit -m "feat(netplane): vm-materializer CompiledVM -> kubevirt.io/v1.VirtualMachine (containerDisk)

kubevirt.io/api <ver>; CRD for envtest from <source>.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Chained single-cluster e2e + wrap

**Files:** `central/test/net_envtest_test.go`, `central/test/phase4_e2e_test.go`; memory; branch finish.

- [ ] **Step 1: Central CompiledVM CRUD + selector envtest.** In `central/test/net_envtest_test.go`, add (mirror the CompiledNIC selector test): create `CompiledVM{ns, spec.clusterName:c1}` + `{clusterName:c2}`, `List(MatchingFields{"spec.clusterName":"c1"})` → exactly the c1 one; a basic CRUD roundtrip.

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go test ./test/ -run "CompiledVM" -v 2>&1 | tail -15'` → PASS.

- [ ] **Step 2: Chained e2e** `central/test/phase4_e2e_test.go` (extends the Phase-3 chain). Boot central (kit-aggregated) + a downstream envtest with the net CRDs + the KubeVirt VirtualMachine CRD. Sequence: create `ClusterPool{c1}` Ready (status heartbeat sim) → run `clusterpool.Reconciler` (Ready) → create `VirtualMachine{vm1, image, resources, interfaceRefs:[nic-a], runStrategy:""}` + `NetworkInterface{nic-a, MAC}` → run `scheduler.Reconciler` (binds c1) → run `controllers.CompiledNICReconciler` AND `controllers.CompiledVMReconciler` (produce CompiledNIC + CompiledVM, both clusterName c1) → run `broker.Broker{ClusterName:c1}.SyncOnce` + `.SyncCompiledVMs` (materialize both downstream) → run `controllers.VMMaterializerReconciler` on the downstream CompiledVM → assert a `kubevirtv1.VirtualMachine` exists downstream with the fedora image + runStrategy RerunOnFailure + the nic-a MAC on the flowplane-overlay multus net. This chains schedule→compile(NIC+VM)→sync→materialize end to end. (The e2e imports netplane controllers + kubevirtv1; central/go.mod already replaces netplane — confirm kubevirt is reachable transitively for the test, else add the require.)

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go test ./test/ -run Phase4 -v 2>&1 | tail -30'` → PASS.

- [ ] **Step 3: Full workspace build + tests + commit.**

Run: `nix develop --command bash -c 'for m in api central netplane; do echo "== $m =="; (cd /home/nik/Development/ironcore-net-xdp/$m && go build ./... && go test ./... 2>&1 | grep -vE "no test files"); done 2>&1 | tail -50'`
Expected: green (kine durability test skips; benign SSA managedFields log non-fatal).

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/test
git commit -m "test(central): Phase 4 CompiledVM envtest + chained schedule->compile->sync->materialize e2e

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

- [ ] **Step 4: Wrap (controller-run).** Update memory (`phase4-kubevirt-vm-lifecycle.md` + MEMORY.md index): CompiledVM (net type, Phase-1b recipe) + compiler emits it + broker syncs it (SyncCompiledVMs) + downstream vm-materializer → kubevirt.io/v1.VirtualMachine (containerDisk boot, runStrategy Tier-1); kubevirt.io/api in netplane only (record version); envtest-gated (materializer builds correct VM against installed KubeVirt CRDs); chained e2e green. Open: Ceph storage-mobility (Volume + CompiledVolumeAttachment), cross-cluster sticky-IP, real KubeVirt boot on the fabric, full Tier-1 (medik8s) + Tier-2 actuators, cloud-init. Then finish the branch via superpowers:finishing-a-development-branch.

---

## Notes for the executor

- **CompiledVM = the Phase-1b recipe for ONE net type** (Task 1 Step 5). Memory `[[phase1b-net-types-central]]` + `central/apis/net/compilednic_*` are the exact template; the roundtrip fuzz is the guard.
- **Keep the CompiledNIC/scheduler/broker-NIC paths byte-identical** — Phase 4 is additive.
- **The kubevirt.io/api dep + CRD-in-envtest is the one real unknown** (Task 4 Step 1 spike) — resolve it before the full `buildVM` mapping; adjust field names to the pinned version.
- **`kubevirt.io/api` in `netplane` only** — central stays KubeVirt-free (it serves CompiledVM, a net type).
- **`WatchListClient=false`** on the compiler's CompiledVM watch (central-aggregated); NOT on the materializer (downstream plain cluster).
- **Both compiled objects carry the same `spec.clusterName`** (same `resolvePlacement`/placement) so they co-locate — the e2e asserts it.
- Sequential git; per-task spec + quality review; envtest/codegen via the nix devShell.
```
