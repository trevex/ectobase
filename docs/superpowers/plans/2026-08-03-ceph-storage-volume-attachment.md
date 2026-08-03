# Ceph Storage — Volume + CompiledVolumeAttachment + Rook Backend — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A VM boots from a persistent RBD-backed disk: a first-class `Volume` → compiler emits a `CompiledVolumeAttachment` (spec.clusterName-bound) → broker syncs it → a downstream VolumeMaterializer creates a CDI `DataVolume` (RBD PVC) → the VMMaterializer boots the VM from it. A minimal Rook Ceph provides the RBD StorageClass.

**Architecture:** `Volume` + `CompiledVolumeAttachment` are new `net.ectobase.dev` types (Phase-1b recipe: shared versioned in `api/v1alpha1` + central internal mirror + hand-conversion + fuzzer + served aggregated + downstream CRD). A `CompiledVolumeAttachmentReconciler` (netplane, against central) emits attachments; the broker syncs them (3rd type); a `VolumeMaterializerReconciler` builds `cdiv1.DataVolume`s; `buildVM` gains an `attachments` param and boots from the DataVolume PVCs (joining by the `workload` label). containerDisk stays the ephemeral fallback. `kubevirt.io/containerized-data-importer-api v1.64.0` is already transitively present in netplane.

**Tech Stack:** Go 1.26.4 (workspace); `api` + `central` + `netplane` modules; apiserver-kit v0.3.4 (local replace); controller-runtime v0.24.1; `kubevirt.io/api v1.6.6` + `kubevirt.io/containerized-data-importer-api v1.64.0` (netplane); Rook Ceph (infra); envtest (kit-aggregated + controller-runtime + KubeVirt/CDI CRD fixtures).

**Design doc:** `docs/superpowers/specs/2026-08-03-ceph-storage-volume-attachment-design.md`.

**Non-negotiable carry-overs:**
- Net-group types use the Phase-1b recipe (memory `[[phase1b-net-types-central]]`; `CompiledVM` in Phase 4 is the exact template): shared versioned `api/v1alpha1` + central internal mirror + hand-written conversion (`central/apis/net/v1alpha1/conversion.go`) + fuzzer + register + serve + downstream CRD; guarded by the roundtrip fuzz test.
- Every central-aggregated informer runs `KUBE_FEATURE_WatchListClient=false` (now also the compiler's CompiledVolumeAttachment watch). Downstream materializers run against a plain cluster (no flag).
- Declarative set-reconcile, no in-memory diff; `equality.Semantic.DeepEqual` for slice/quantity-bearing specs.
- **Additive**: keep CompiledNIC / CompiledVM / scheduler / broker-NIC-VM paths byte-identical. `buildVM` gains a param; Phase-4 callers pass `nil` ⇒ unchanged output.
- Server-side apply for the DataVolume + VM (Phase-4 pattern; CDI/KubeVirt webhooks default fields). TypeMeta set on applied objects.
- go 1.26.4 workspace; run go/codegen via `nix develop --command bash -c '...'`. Ignore stale go-1.26.0 LSP diagnostics.
- The netplane `replace google.golang.org/genproto` (Phase-4) stays; making CDI a direct dep doesn't remove it.

**Branch:** `feat/ceph-storage-volume-attachment` off main (already created this session; verify `git branch --show-current`).

---

## File structure

**Types (api + central):**
- Create: `api/v1alpha1/volume_types.go` (`Volume`), `api/v1alpha1/compiledvolumeattachment_types.go` (`CompiledVolumeAttachment`); Modify `api/v1alpha1/virtualmachine_types.go` (`VolumeRefs`), `register.go`.
- Create: `central/apis/net/{volume,compiledvolumeattachment}_types.go` + `_rest.go`; Modify `central/apis/net/register.go`, `.../v1alpha1/aliases.go`, `.../v1alpha1/conversion.go`, `fuzzer/fuzzer.go`, `central/cmd/apiserver/main.go`.

**Compiler (netplane):** Create `netplane/controllers/compiledvolumeattachment.go` + test; Modify `netplane/cmd/controller/main.go`.

**Broker (central):** Modify `central/internal/broker/broker.go` (`SyncCompiledVolumeAttachments`), `broker_test.go`, `central/cmd/broker/main.go`, `central/test/broker_test.go`.

**Materializer (netplane):** Create `netplane/controllers/volumematerializer.go` + test; Modify `netplane/controllers/vmmaterializer.go` (buildVM param + join), `netplane/cmd/vm-materializer/main.go` (register VolumeMaterializer + CDI scheme); Create `netplane/test/crds/cdi-datavolume-crd.yaml`; Modify `netplane/go.mod` (CDI direct).

**Infra + e2e:** Create `hack/rook-ceph-up.sh`; Modify `hack/install-stack.sh`; `central/test/net_envtest_test.go` (Volume/attachment CRUD+selector), `central/test/ceph_e2e_test.go` (chained e2e).

---

## Task 1: Types — Volume + CompiledVolumeAttachment + VirtualMachine.VolumeRefs (Phase-1b recipe)

**Files:** `api/v1alpha1/{volume_types.go,compiledvolumeattachment_types.go,virtualmachine_types.go,register.go}`; `central/apis/net/{volume_types.go,volume_rest.go,compiledvolumeattachment_types.go,compiledvolumeattachment_rest.go,register.go}`; `central/apis/net/v1alpha1/{aliases.go,conversion.go}`; `central/apis/net/fuzzer/fuzzer.go`; `central/cmd/apiserver/main.go`; regenerated codegen.

- [ ] **Step 1: Add `VirtualMachine.Spec.VolumeRefs`.** In `api/v1alpha1/virtualmachine_types.go`, add to `VirtualMachineSpec` (after `InterfaceRefs`):

```go
	// VolumeRefs names the Volumes (same namespace) this VM attaches. A referenced
	// Volume with a BootImage is the boot disk; others are data disks. When empty the
	// VM boots ephemerally from Image (containerDisk).
	// +optional
	VolumeRefs []LocalObjectReference `json:"volumeRefs,omitempty"`
```

- [ ] **Step 2: Create `api/v1alpha1/volume_types.go`** (shared versioned; mirror `compiledvm_types.go` markers):

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VolumeSpec defines a persistent RBD-backed disk for a VM.
type VolumeSpec struct {
	// Size is the requested disk size (e.g. 10Gi).
	Size resource.Quantity `json:"size,omitempty"`
	// StorageClass is the ceph-csi RBD StorageClass; empty uses the cluster default.
	// +optional
	StorageClass string `json:"storageClass,omitempty"`
	// BootImage, if set, is a containerDisk/registry image imported into the disk
	// (making it bootable). Empty leaves a blank data disk of Size.
	// +optional
	BootImage string `json:"bootImage,omitempty"`
}

// VolumeStatus is the observed state of a Volume.
type VolumeStatus struct {
	// Phase is the current lifecycle phase of the Volume.
	// +optional
	Phase string `json:"phase,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Volume is a persistent RBD-backed disk referenced by a VirtualMachine.
type Volume struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VolumeSpec   `json:"spec,omitempty"`
	Status VolumeStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// VolumeList is a list of Volume objects.
type VolumeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Volume `json:"items"`
}
```

- [ ] **Step 3: Create `api/v1alpha1/compiledvolumeattachment_types.go`** (shared versioned):

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledVolumeAttachmentSpec is the lowered, cluster-bound attachment of one
// Volume to one VM: the RBD disk parameters a downstream materializer turns into a
// CDI DataVolume (RBD PVC).
type CompiledVolumeAttachmentSpec struct {
	// ClusterName is the cluster this attachment is bound to (the pod->node binding);
	// the per-cluster broker selects on this field.
	// +optional
	ClusterName string `json:"clusterName,omitempty"`
	// Size is the RBD disk size.
	Size resource.Quantity `json:"size,omitempty"`
	// StorageClass is the ceph-csi RBD StorageClass (empty = cluster default).
	// +optional
	StorageClass string `json:"storageClass,omitempty"`
	// BootImage, if set, is imported into the disk (bootable); empty = blank disk.
	// +optional
	BootImage string `json:"bootImage,omitempty"`
	// Boot marks this attachment as the VM's boot disk.
	// +optional
	Boot bool `json:"boot,omitempty"`
}

// CompiledVolumeAttachmentStatus is the observed state.
type CompiledVolumeAttachmentStatus struct {
	// State is the materialization state.
	// +optional
	State string `json:"state,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// CompiledVolumeAttachment binds one Volume to one VM on a cluster.
type CompiledVolumeAttachment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CompiledVolumeAttachmentSpec   `json:"spec,omitempty"`
	Status CompiledVolumeAttachmentStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// CompiledVolumeAttachmentList is a list of CompiledVolumeAttachment objects.
type CompiledVolumeAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CompiledVolumeAttachment `json:"items"`
}
```

- [ ] **Step 4: Register + regen api.** In `api/v1alpha1/register.go` add `&Volume{}, &VolumeList{}, &CompiledVolumeAttachment{}, &CompiledVolumeAttachmentList{}` to the known-types list. Run:

`nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp && make generate' 2>&1 | tail -12`
Expected: `api/v1alpha1/zz_generated.deepcopy.go` gains the 4 types' DeepCopy; `config/crd/bases/net.ectobase.dev_{volumes,compiledvolumeattachments}.yaml` created (+ chart sync); VirtualMachine CRD gains `spec.volumeRefs`.

- [ ] **Step 5: Central internal mirror + rest + register + alias + conversion + fuzzer + serve — Phase-1b recipe (the `CompiledVM` files in `central/apis/net` are the EXACT template).** For BOTH `Volume` and `CompiledVolumeAttachment`:
  - `central/apis/net/{volume,compiledvolumeattachment}_types.go` — internal mirrors (verbatim fields, no tags).
  - `central/apis/net/{volume,compiledvolumeattachment}_rest.go` — `resource.Object` + status subresource; `NamespaceScoped()→true`; plurals `volumes` / `compiledvolumeattachments`. **`CompiledVolumeAttachment` ADDITIONALLY** implements the field-selector hook (`SelectableFields`/`SupportedFieldSelectors` → `spec.clusterName`, mirror `compiledvm_rest.go`). `Volume` does NOT (no clusterName).
  - `central/apis/net/register.go` — add all 4 types. `central/apis/net/v1alpha1/aliases.go` — add aliases for all 4 + their Spec/Status. `central/apis/net/v1alpha1/conversion.go` — hand-written field-identity `Convert_*` (both directions) for Volume/List/Spec/Status + CompiledVolumeAttachment/List/Spec/Status + register in `RegisterConversions` (follow the CompiledVM block; `Size resource.Quantity` is a value type — direct assign via `out.Size = in.Size` is fine, or `in.Size.DeepCopy()` for independence — match how the codebase converts Quantity elsewhere).
  - `central/apis/net/fuzzer/fuzzer.go` — add `VolumeSpec` + `CompiledVolumeAttachmentSpec` fuzz funcs if the harness registers per-Spec funcs.
  - `central/cmd/apiserver/main.go` — add `.With(apiserver.Resource(&netapi.Volume{}, ...))` + `.With(apiserver.Resource(&netapi.CompiledVolumeAttachment{}, ...))`.

- [ ] **Step 6: Regen central + build + fuzz.**

`nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && bash hack/update-codegen.sh && go build ./... && go test ./apis/... -run "RoundTrip|Roundtrip" 2>&1 | tail -12'`
Expected: codegen clean; build clean; net roundtrip fuzz PASS (Volume + CompiledVolumeAttachment lossless). If it fails, a field drifted internal-vs-versioned — diff.

- [ ] **Step 7: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add api/v1alpha1 config/crd deploy/charts central/apis central/client-go central/cmd/apiserver/main.go
git commit -m "feat(api,central): Volume + CompiledVolumeAttachment types + VirtualMachine.volumeRefs

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: CompileVolumeAttachments + reconciler (TDD)

**Files:** `netplane/controllers/compiledvolumeattachment.go`, `..._test.go`, `netplane/cmd/controller/main.go`.

Context: `Placement{ClusterName, WorkloadID}` + `resolvePlacement` exist in `compilednic.go`. The VM's own `spec.clusterName` is the binding (set by the scheduler), like CompiledVM.

- [ ] **Step 1: Write the failing unit test** `netplane/controllers/compiledvolumeattachment_test.go`:

```go
package controllers

import (
	"testing"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

func TestCompileVolumeAttachments(t *testing.T) {
	vm := &netv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1"},
		Spec:       netv1.VirtualMachineSpec{ClusterName: "c1", VolumeRefs: []netv1.LocalObjectReference{{Name: "boot"}, {Name: "data"}}},
	}
	volumes := []netv1.Volume{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "boot"}, Spec: netv1.VolumeSpec{Size: resource.MustParse("10Gi"), BootImage: "quay.io/containerdisks/fedora:41", StorageClass: "ceph-rbd"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "data"}, Spec: netv1.VolumeSpec{Size: resource.MustParse("5Gi")}},
	}
	atts := CompileVolumeAttachments(vm, volumes, Placement{ClusterName: "c1", WorkloadID: "vm1"})
	if len(atts) != 2 {
		t.Fatalf("want 2 attachments, got %d", len(atts))
	}
	byName := map[string]netv1.CompiledVolumeAttachment{}
	for _, a := range atts {
		byName[a.Name] = a
	}
	boot := byName["vm1-boot"]
	if boot.Namespace != "ns" || boot.Labels["workload"] != "vm1" || boot.Spec.ClusterName != "c1" {
		t.Fatalf("boot meta: %+v", boot)
	}
	if !boot.Spec.Boot || boot.Spec.BootImage != "quay.io/containerdisks/fedora:41" || boot.Spec.StorageClass != "ceph-rbd" || boot.Spec.Size.Cmp(resource.MustParse("10Gi")) != 0 {
		t.Fatalf("boot spec: %+v", boot.Spec)
	}
	data := byName["vm1-data"]
	if data.Spec.Boot || data.Spec.BootImage != "" || data.Spec.Size.Cmp(resource.MustParse("5Gi")) != 0 {
		t.Fatalf("data spec: %+v", data.Spec)
	}
}
```
Run → FAIL.

- [ ] **Step 2: Implement `netplane/controllers/compiledvolumeattachment.go`.**

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

// CompileVolumeAttachments lowers a VirtualMachine + its referenced Volumes into one
// CompiledVolumeAttachment per VolumeRef, each cluster-bound (from placement) and
// workload-labelled. A Volume with a BootImage yields Boot=true. Pure.
func CompileVolumeAttachments(vm *netv1.VirtualMachine, volumes []netv1.Volume, placement Placement) []netv1.CompiledVolumeAttachment {
	byName := map[string]*netv1.Volume{}
	for i := range volumes {
		byName[volumes[i].Name] = &volumes[i]
	}
	var out []netv1.CompiledVolumeAttachment
	for _, ref := range vm.Spec.VolumeRefs {
		vol, ok := byName[ref.Name]
		if !ok {
			continue // volume not found yet; the Volume watch re-triggers
		}
		att := netv1.CompiledVolumeAttachment{
			TypeMeta:   metav1.TypeMeta{APIVersion: "net.ectobase.dev/v1alpha1", Kind: "CompiledVolumeAttachment"},
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%s", vm.Name, ref.Name), Namespace: vm.Namespace},
			Spec: netv1.CompiledVolumeAttachmentSpec{
				ClusterName:  placement.ClusterName,
				Size:         vol.Spec.Size,
				StorageClass: vol.Spec.StorageClass,
				BootImage:    vol.Spec.BootImage,
				Boot:         vol.Spec.BootImage != "",
			},
		}
		if placement.WorkloadID != "" {
			att.Labels = map[string]string{"workload": placement.WorkloadID}
		}
		out = append(out, att)
	}
	return out
}

// CompiledVolumeAttachmentReconciler upserts a VM's CompiledVolumeAttachments (one per
// VolumeRef) and GCs attachments for VolumeRefs that were removed.
type CompiledVolumeAttachmentReconciler struct{ Client client.Client }

func (r *CompiledVolumeAttachmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vm netv1.VirtualMachine
	if err := r.Client.Get(ctx, req.NamespacedName, &vm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	var volList netv1.VolumeList
	if err := r.Client.List(ctx, &volList, client.InNamespace(vm.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list volumes: %w", err)
	}
	placement := Placement{ClusterName: vm.Spec.ClusterName, WorkloadID: vm.Name}
	desired := CompileVolumeAttachments(&vm, volList.Items, placement)
	want := map[string]netv1.CompiledVolumeAttachment{}
	for _, a := range desired {
		want[a.Name] = a
	}
	// Existing attachments owned by this VM (workload label).
	var have netv1.CompiledVolumeAttachmentList
	if err := r.Client.List(ctx, &have, client.InNamespace(vm.Namespace), client.MatchingLabels{"workload": vm.Name}); err != nil {
		return ctrl.Result{}, fmt.Errorf("list attachments: %w", err)
	}
	haveNames := map[string]bool{}
	for i := range have.Items {
		cur := &have.Items[i]
		haveNames[cur.Name] = true
		w, ok := want[cur.Name]
		if !ok {
			if err := r.Client.Delete(ctx, cur); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("gc attachment %s: %w", cur.Name, err)
			}
			continue
		}
		if !reflect.DeepEqual(cur.Spec, w.Spec) {
			cur.Spec = w.Spec
			if err := r.Client.Update(ctx, cur); err != nil {
				return ctrl.Result{}, fmt.Errorf("update attachment %s: %w", cur.Name, err)
			}
		}
	}
	for name, w := range want {
		if haveNames[name] {
			continue
		}
		att := w
		if err := controllerutil.SetControllerReference(&vm, &att, r.Client.Scheme()); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Client.Create(ctx, &att); err != nil {
			return ctrl.Result{}, fmt.Errorf("create attachment %s: %w", name, err)
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager watches VirtualMachines (Owns their attachments) + re-enqueues a VM
// when a referenced Volume changes.
func (r *CompiledVolumeAttachmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.VirtualMachine{}).
		Owns(&netv1.CompiledVolumeAttachment{}).
		Watches(&netv1.Volume{}, handler.EnqueueRequestsFromMapFunc(r.vmsForVolume)).
		Complete(r)
}

// vmsForVolume maps a Volume event to reconcile requests for VMs (same namespace) that reference it.
func (r *CompiledVolumeAttachmentReconciler) vmsForVolume(ctx context.Context, obj client.Object) []reconcile.Request {
	vol, ok := obj.(*netv1.Volume)
	if !ok {
		return nil
	}
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms, client.InNamespace(vol.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range vms.Items {
		for _, ref := range vms.Items[i].Spec.VolumeRefs {
			if ref.Name == vol.Name {
				reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: vms.Items[i].Namespace, Name: vms.Items[i].Name}})
				break
			}
		}
	}
	return reqs
}
```
Run → PASS.

- [ ] **Step 3: Register.** In `netplane/cmd/controller/main.go`, next to `CompiledVMReconciler`, add:
```go
	if err := (&controllers.CompiledVolumeAttachmentReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup compiledvolumeattachment controller: %v", err)
	}
```

- [ ] **Step 4: Build + test.**

`nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/netplane && go build ./... && go test ./controllers/... 2>&1 | tail -15'`
Expected: build clean; TestCompileVolumeAttachments + existing tests PASS.

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add netplane/controllers/compiledvolumeattachment.go netplane/controllers/compiledvolumeattachment_test.go netplane/cmd/controller
git commit -m "feat(netplane): compiler emits CompiledVolumeAttachment per VM VolumeRef

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Broker syncs CompiledVolumeAttachment (TDD)

**Files:** `central/internal/broker/broker.go`, `broker_test.go`, `central/cmd/broker/main.go`, `central/test/broker_test.go`.

Design: `SyncCompiledVolumeAttachments` — a 3rd explicit twin of `SyncOnce`/`SyncCompiledVMs` (concrete-over-generic; note the refactor trigger). Keep `SyncOnce`/`SyncCompiledVMs` byte-identical.

- [ ] **Step 1: Failing unit test** in `central/internal/broker/broker_test.go` (mirror `TestSyncCompiledVMs_NamespacedCreateUpdateGC`):

```go
func TestSyncCompiledVolumeAttachments_NamespacedCreateUpdateGC(t *testing.T) {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil { t.Fatal(err) }
	att := func(ns, name, cn, img string) *netv1.CompiledVolumeAttachment {
		return &netv1.CompiledVolumeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: netv1.CompiledVolumeAttachmentSpec{ClusterName: cn, BootImage: img}}
	}
	idx := func(o client.Object) []string { return []string{o.(*netv1.CompiledVolumeAttachment).Spec.ClusterName} }
	central := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&netv1.CompiledVolumeAttachment{}, "spec.clusterName", idx).
		WithObjects(att("ns1", "a", "c1", "fedora"), att("ns1", "b", "c2", "x")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(att("ns1", "stale", "c1", "old"), att("ns1", "a", "c1", "OLD")).Build()

	b := &Broker{Central: central, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncCompiledVolumeAttachments(context.Background()); err != nil { t.Fatal(err) }

	list := &netv1.CompiledVolumeAttachmentList{}
	if err := downstream.List(context.Background(), list); err != nil { t.Fatal(err) }
	if len(list.Items) != 1 || list.Items[0].Name != "a" || list.Items[0].Spec.BootImage != "fedora" {
		t.Fatalf("want [a(fedora)], got %+v", list.Items)
	}
	if err := b.SyncCompiledVolumeAttachments(context.Background()); err != nil { t.Fatalf("second sync: %v", err) }
}
```
Run → FAIL.

- [ ] **Step 2: Implement `SyncCompiledVolumeAttachments`** in `central/internal/broker/broker.go` (mirror `SyncCompiledVMs`, swap type; add `keyAtt`):

```go
// keyAtt identifies a namespaced CompiledVolumeAttachment as "namespace/name".
func keyAtt(o *netv1.CompiledVolumeAttachment) string { return o.Namespace + "/" + o.Name }

// SyncCompiledVolumeAttachments is the CompiledVolumeAttachment twin of SyncOnce.
func (b *Broker) SyncCompiledVolumeAttachments(ctx context.Context) error {
	desired := &netv1.CompiledVolumeAttachmentList{}
	if err := b.Central.List(ctx, desired, client.MatchingFields{"spec.clusterName": b.ClusterName}); err != nil {
		return fmt.Errorf("list central attachments: %w", err)
	}
	want := make(map[string]netv1.CompiledVolumeAttachment, len(desired.Items))
	for _, o := range desired.Items {
		want[keyAtt(&o)] = o
	}
	have := &netv1.CompiledVolumeAttachmentList{}
	if err := b.Downstream.List(ctx, have); err != nil {
		return fmt.Errorf("list downstream attachments: %w", err)
	}
	haveKeys := make(map[string]bool, len(have.Items))
	for i := range have.Items {
		cur := &have.Items[i]
		haveKeys[keyAtt(cur)] = true
		w, ok := want[keyAtt(cur)]
		if !ok {
			if err := b.Downstream.Delete(ctx, cur); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("gc attachment %s: %w", keyAtt(cur), err)
			}
			continue
		}
		if !equality.Semantic.DeepEqual(cur.Spec, w.Spec) {
			cur.Spec = w.Spec
			if err := b.Downstream.Update(ctx, cur); err != nil {
				return fmt.Errorf("update attachment %s: %w", keyAtt(cur), err)
			}
		}
	}
	for k, w := range want {
		if haveKeys[k] {
			continue
		}
		local := &netv1.CompiledVolumeAttachment{}
		local.Namespace = w.Namespace
		local.Name = w.Name
		local.Spec = w.Spec
		if err := b.Downstream.Create(ctx, local); err != nil {
			return fmt.Errorf("create attachment %s: %w", k, err)
		}
	}
	return nil
}
```
Run → PASS.

- [ ] **Step 3: cmd/broker wiring.** In `central/cmd/broker/main.go`: add `&netv1.CompiledVolumeAttachment{}` to the cache `ByObject` map with the `spec.clusterName` field selector; add a 3rd controller `ctrl.NewControllerManagedBy(mgr).Named("compiledvolumeattachment").For(&netv1.CompiledVolumeAttachment{}).Complete(r)`; in `brokerReconciler.Reconcile`, after `SyncCompiledVMs`, call `b.SyncCompiledVolumeAttachments(ctx)` (return on first error). Update the package/struct doc comments to mention the 3 synced types.

- [ ] **Step 4: Loopback envtest.** In `central/test/broker_test.go`, add a CompiledVolumeAttachment section (mirror the CompiledVM one): create `{ns,clusterName:c1}` + `{c2}` in central → sync → downstream has exactly the c1 one; existing NIC/VM sections intact.

- [ ] **Step 5: Build + broker tests + loopback.**

`nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go build ./... && go test ./internal/broker/... && go test ./test/ -run TestBroker_Loopback -v 2>&1 | tail -20'`
Expected: green (all 3 types synced).

- [ ] **Step 6: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/internal/broker central/cmd/broker central/test/broker_test.go
git commit -m "feat(central): broker syncs CompiledVolumeAttachment (3rd synced type)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: VolumeMaterializer — CDI DataVolume (spike + build, TDD)

**Files:** `netplane/go.mod`; `netplane/test/crds/cdi-datavolume-crd.yaml`; `netplane/controllers/volumematerializer.go`, `..._test.go`; `netplane/cmd/vm-materializer/main.go`.

CDI surface (verified, v1.64.0, `cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"`): `DataVolume{TypeMeta,ObjectMeta,Spec DataVolumeSpec}`; `DataVolumeSpec{Source *DataVolumeSource, Storage *StorageSpec}`; `StorageSpec{AccessModes []corev1.PersistentVolumeAccessMode, Resources corev1.VolumeResourceRequirements, StorageClassName *string}`; `DataVolumeSource{Registry *DataVolumeSourceRegistry{URL *string}, Blank *DataVolumeBlankImage{}}`; `cdiv1.SchemeGroupVersion` (group `cdi.kubevirt.io`, v1beta1); `cdiv1.AddToScheme`.

- [ ] **Step 1: Make CDI a direct dep + write the CRD fixture.** `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/netplane && go get kubevirt.io/containerized-data-importer-api@v1.64.0 && go mod tidy 2>&1 | tail'` (moves it indirect→direct; the genproto replace stays; if tidy re-breaks the build, keep the replace). Create `netplane/test/crds/cdi-datavolume-crd.yaml` — a minimal structural preserve-unknown-fields CRD for `datavolumes.cdi.kubevirt.io` (group `cdi.kubevirt.io`, version `v1beta1`, scope Namespaced, `spec`/`status` `x-kubernetes-preserve-unknown-fields: true`), headered exactly like `netplane/test/crds/kubevirt-vm-crd.yaml` (a TEST FIXTURE, not the real CRD). Mirror that file's shape.

- [ ] **Step 2: Failing `buildDataVolume` unit test** `netplane/controllers/volumematerializer_test.go`:

```go
package controllers

import (
	"testing"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
)

func TestBuildDataVolume_Boot(t *testing.T) {
	cva := &netv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1-boot", Labels: map[string]string{"workload": "vm1"}},
		Spec:       netv1.CompiledVolumeAttachmentSpec{Size: resource.MustParse("10Gi"), StorageClass: "ceph-rbd", BootImage: "quay.io/containerdisks/fedora:41", Boot: true},
	}
	dv := buildDataVolume(cva)
	if dv.Name != "vm1-boot" || dv.Namespace != "ns" { t.Fatalf("meta: %s/%s", dv.Namespace, dv.Name) }
	if dv.Spec.Source == nil || dv.Spec.Source.Registry == nil || dv.Spec.Source.Registry.URL == nil || *dv.Spec.Source.Registry.URL != "docker://quay.io/containerdisks/fedora:41" {
		t.Fatalf("source: %+v", dv.Spec.Source)
	}
	if dv.Spec.Storage == nil || dv.Spec.Storage.StorageClassName == nil || *dv.Spec.Storage.StorageClassName != "ceph-rbd" { t.Fatalf("storageClass: %+v", dv.Spec.Storage) }
	if dv.Spec.Storage.Resources.Requests.Storage().Cmp(resource.MustParse("10Gi")) != 0 { t.Fatalf("size: %v", dv.Spec.Storage.Resources.Requests.Storage()) }
	if len(dv.Spec.Storage.AccessModes) != 1 || dv.Spec.Storage.AccessModes[0] != corev1.ReadWriteOnce { t.Fatalf("access: %+v", dv.Spec.Storage.AccessModes) }
}

func TestBuildDataVolume_Blank(t *testing.T) {
	cva := &netv1.CompiledVolumeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1-data"}, Spec: netv1.CompiledVolumeAttachmentSpec{Size: resource.MustParse("5Gi")}}
	dv := buildDataVolume(cva)
	if dv.Spec.Source == nil || dv.Spec.Source.Blank == nil { t.Fatalf("expected blank source, got %+v", dv.Spec.Source) }
	if dv.Spec.Storage.StorageClassName != nil { t.Fatalf("expected default storageClass (nil), got %v", *dv.Spec.Storage.StorageClassName) }
}
```
Run → FAIL.

- [ ] **Step 3: Implement `netplane/controllers/volumematerializer.go`.**

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
)

// dvFieldOwner is the VolumeMaterializer's server-side-apply field manager.
const dvFieldOwner = "volume-materializer"

// buildDataVolume turns a CompiledVolumeAttachment into a CDI DataVolume: an RBD PVC
// (via the ceph-csi StorageClass) whose source is a registry import of BootImage
// (bootable) or a blank disk of Size. Pure; TypeMeta set for server-side apply.
func buildDataVolume(cva *netv1.CompiledVolumeAttachment) *cdiv1.DataVolume {
	storage := &cdiv1.StorageSpec{
		AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: cva.Spec.Size}},
	}
	if cva.Spec.StorageClass != "" {
		sc := cva.Spec.StorageClass
		storage.StorageClassName = &sc
	}
	var source *cdiv1.DataVolumeSource
	if cva.Spec.BootImage != "" {
		url := "docker://" + cva.Spec.BootImage
		source = &cdiv1.DataVolumeSource{Registry: &cdiv1.DataVolumeSourceRegistry{URL: &url}}
	} else {
		source = &cdiv1.DataVolumeSource{Blank: &cdiv1.DataVolumeBlankImage{}}
	}
	labels := map[string]string{}
	if w := cva.Labels["workload"]; w != "" {
		labels["workload"] = w
	}
	return &cdiv1.DataVolume{
		TypeMeta:   metav1.TypeMeta{APIVersion: cdiv1.SchemeGroupVersion.String(), Kind: "DataVolume"},
		ObjectMeta: metav1.ObjectMeta{Namespace: cva.Namespace, Name: cva.Name, Labels: labels},
		Spec:       cdiv1.DataVolumeSpec{Source: source, Storage: storage},
	}
}

// VolumeMaterializerReconciler turns CompiledVolumeAttachments into CDI DataVolumes.
type VolumeMaterializerReconciler struct{ Client client.Client }

func (r *VolumeMaterializerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cva netv1.CompiledVolumeAttachment
	if err := r.Client.Get(ctx, req.NamespacedName, &cva); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	desired := buildDataVolume(&cva)
	if err := ctrl.SetControllerReference(&cva, desired, r.Client.Scheme()); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.Client.Patch(ctx, desired, client.Apply, client.FieldOwner(dvFieldOwner), client.ForceOwnership); err != nil {
		return ctrl.Result{}, fmt.Errorf("apply datavolume: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *VolumeMaterializerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.CompiledVolumeAttachment{}).
		Owns(&cdiv1.DataVolume{}).
		Complete(r)
}
```
Run the buildDataVolume tests → PASS. (Adjust any CDI field name to the pinned v1.64.0 if the build flags a mismatch — the types were verified but double-check `VolumeResourceRequirements` vs `ResourceRequirements`.)

- [ ] **Step 4: Wire into cmd/vm-materializer + envtest.** In `netplane/cmd/vm-materializer/main.go`: register `cdiv1.AddToScheme` on the scheme; register `(&controllers.VolumeMaterializerReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr)` alongside the VM materializer. Add `TestVolumeMaterializer_CreatesDataVolume` (in volumematerializer_test.go): a downstream envtest with the CDI DataVolume CRD fixture + KubeVirt VM CRD fixture (CRDDirectoryPaths lists `netplane/test/crds`); scheme = netv1 + kubevirtv1 + cdiv1; create a `CompiledVolumeAttachment`; run `VolumeMaterializerReconciler.Reconcile`; assert a `cdiv1.DataVolume` exists with the right source/storageClass/size.

`nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/netplane && go build ./... && go test ./controllers/ -run "BuildDataVolume|VolumeMaterializer" -v 2>&1 | tail -25'`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add netplane/controllers/volumematerializer.go netplane/controllers/volumematerializer_test.go netplane/cmd/vm-materializer netplane/test/crds/cdi-datavolume-crd.yaml netplane/go.mod netplane/go.sum go.work.sum
git commit -m "feat(netplane): VolumeMaterializer CompiledVolumeAttachment -> CDI DataVolume (RBD)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: VMMaterializer boots from DataVolumes (TDD)

**Files:** `netplane/controllers/vmmaterializer.go`, `vmmaterializer_test.go`.

- [ ] **Step 1: Extend the failing test.** In `vmmaterializer_test.go`, add:

```go
func TestBuildVM_FromDataVolumes(t *testing.T) {
	cvm := &netv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ns-vm1", Labels: map[string]string{"workload": "vm1"}},
		Spec: netv1.CompiledVMSpec{Image: "ignored-when-volumes", RunStrategy: "RerunOnFailure"}}
	atts := []netv1.CompiledVolumeAttachment{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1-data"}, Spec: netv1.CompiledVolumeAttachmentSpec{Boot: false}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1-boot"}, Spec: netv1.CompiledVolumeAttachmentSpec{Boot: true}},
	}
	vm := buildVM(cvm, atts)
	vols := vm.Spec.Template.Spec.Volumes
	if len(vols) != 2 { t.Fatalf("want 2 volumes, got %+v", vols) }
	// boot disk first, referencing its DataVolume; no containerDisk.
	if vols[0].DataVolume == nil || vols[0].DataVolume.Name != "vm1-boot" { t.Fatalf("boot vol first: %+v", vols) }
	if vols[1].DataVolume == nil || vols[1].DataVolume.Name != "vm1-data" { t.Fatalf("data vol: %+v", vols) }
	for _, v := range vols { if v.ContainerDisk != nil { t.Fatalf("no containerDisk when volumes present: %+v", vols) } }
}
```
Also confirm the existing `TestBuildVM` still compiles — its `buildVM(cvm)` call must become `buildVM(cvm, nil)` (containerDisk fallback). Run → FAIL (arity + logic).

- [ ] **Step 2: Extend `buildVM`.** In `netplane/controllers/vmmaterializer.go`, change the signature to `buildVM(cvm *netv1.CompiledVM, attachments []netv1.CompiledVolumeAttachment)` and replace the disks/volumes construction:

```go
	var disks []kubevirtv1.Disk
	var volumes []kubevirtv1.Volume
	if len(attachments) > 0 {
		// Persistent RBD disks: boot attachment first, then the rest by name (deterministic).
		ordered := append([]netv1.CompiledVolumeAttachment(nil), attachments...)
		sort.SliceStable(ordered, func(i, j int) bool {
			if ordered[i].Spec.Boot != ordered[j].Spec.Boot {
				return ordered[i].Spec.Boot // boot first
			}
			return ordered[i].Name < ordered[j].Name
		})
		for _, a := range ordered {
			disks = append(disks, kubevirtv1.Disk{Name: a.Name, DiskDevice: kubevirtv1.DiskDevice{Disk: &kubevirtv1.DiskTarget{Bus: kubevirtv1.DiskBusVirtio}}})
			volumes = append(volumes, kubevirtv1.Volume{Name: a.Name, VolumeSource: kubevirtv1.VolumeSource{DataVolume: &kubevirtv1.DataVolumeSource{Name: a.Name}}})
		}
	} else {
		// Ephemeral fallback: containerDisk from Image (Phase-4 behavior).
		disks = []kubevirtv1.Disk{{Name: containerDiskName, DiskDevice: kubevirtv1.DiskDevice{Disk: &kubevirtv1.DiskTarget{Bus: kubevirtv1.DiskBusVirtio}}}}
		volumes = []kubevirtv1.Volume{{Name: containerDiskName, VolumeSource: kubevirtv1.VolumeSource{ContainerDisk: &kubevirtv1.ContainerDiskSource{Image: cvm.Spec.Image}}}}
	}
```
(Delete the old unconditional `disks`/`volumes` literals; keep the interface/network/runStrategy code. Add `"sort"` to imports.)

- [ ] **Step 3: Reconcile joins attachments by workload label.** In `VMMaterializerReconciler.Reconcile`, after `Get(&cvm)` and before `buildVM`, list the attachments:

```go
	var atts netv1.CompiledVolumeAttachmentList
	if w := cvm.Labels["workload"]; w != "" {
		if err := r.Client.List(ctx, &atts, client.InNamespace(cvm.Namespace), client.MatchingLabels{"workload": w}); err != nil {
			return ctrl.Result{}, fmt.Errorf("list attachments: %w", err)
		}
	}
	desired := buildVM(&cvm, atts.Items)
```
(Replace the existing `desired := buildVM(&cvm)`.) Add a `.Watches(&netv1.CompiledVolumeAttachment{}, handler.EnqueueRequestsFromMapFunc(r.cvmsForAttachment))` to `SetupWithManager` so a new/changed attachment re-triggers its VM, and add the mapper (the CompiledVM name is `{ns}-{vm}` and the attachment's `workload` label is `{vm}`, so the owning CompiledVM is `{cva.Namespace}-{workload}` in `cva.Namespace`):

```go
// cvmsForAttachment maps a CompiledVolumeAttachment event to its owning CompiledVM
// (named "{namespace}-{workload}"), so a new/changed DataVolume-backing attachment
// re-materializes the VM's disk list.
func (r *VMMaterializerReconciler) cvmsForAttachment(ctx context.Context, obj client.Object) []reconcile.Request {
	cva, ok := obj.(*netv1.CompiledVolumeAttachment)
	if !ok {
		return nil
	}
	w := cva.Labels["workload"]
	if w == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: cva.Namespace, Name: cva.Namespace + "-" + w}}}
}
```
Add the imports `"sigs.k8s.io/controller-runtime/pkg/handler"`, `"sigs.k8s.io/controller-runtime/pkg/reconcile"`, and `"k8s.io/apimachinery/pkg/types"` to `vmmaterializer.go` if not already present.

- [ ] **Step 4: Fix the existing buildVM call sites + build + test.** Update `TestBuildVM` (Phase-4) to `buildVM(cvm, nil)`. Run:

`nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/netplane && go build ./... && go vet ./controllers/... && go test ./controllers/ -run "BuildVM|Materializer|VolumeMaterializer|BuildDataVolume" -v 2>&1 | tail -30'`
Expected: build+vet clean; `TestBuildVM` (containerDisk fallback), `TestBuildVM_FromDataVolumes`, and the materializer envtests PASS.

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add netplane/controllers/vmmaterializer.go netplane/controllers/vmmaterializer_test.go
git commit -m "feat(netplane): VM boots from CompiledVolumeAttachment DataVolumes (containerDisk fallback)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Rook backend + chained e2e + wrap

**Files:** `hack/rook-ceph-up.sh`, `hack/install-stack.sh`; `central/test/net_envtest_test.go`, `central/test/ceph_e2e_test.go`; memory; branch finish.

- [ ] **Step 1: Central Volume + CompiledVolumeAttachment CRUD + selector envtest.** In `central/test/net_envtest_test.go`, add: a `Volume` create/get roundtrip (Size/BootImage survive) + a `CompiledVolumeAttachment` `spec.clusterName` selector test (c1 vs c2 → List MatchingFields returns exactly c1). Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go test ./test/ -run "Volume|CompiledVolumeAttachment" -v 2>&1 | tail -15'` → PASS.

- [ ] **Step 2: Chained e2e** `central/test/ceph_e2e_test.go` (extends the Phase-4 chain). Boot central + a downstream envtest with the net CRDs + the KubeVirt VM CRD + the CDI DataVolume CRD fixtures; scheme netv1 + kubevirtv1 + cdiv1. Sequence: ClusterPool c1 Ready → create `Volume{boot, BootImage:fedora, Size:10Gi, StorageClass:ceph-rbd}` + `VirtualMachine{vm1, VolumeRefs:[boot]}` + `NetworkInterface{nic-a}` → scheduler binds c1 → run `CompiledNICReconciler` + `CompiledVMReconciler` + `CompiledVolumeAttachmentReconciler` → assert central has `CompiledVolumeAttachment vm1-boot` (clusterName c1, Boot, BootImage) → run `broker.SyncOnce` + `SyncCompiledVMs` + `SyncCompiledVolumeAttachments` → assert all downstream → run `VolumeMaterializerReconciler` on the attachment → assert a `cdiv1.DataVolume vm1-boot` (RBD, registry source) → run `VMMaterializerReconciler` on the CompiledVM → assert the `kubevirtv1.VirtualMachine default-vm1` boots from the `vm1-boot` DataVolume (a dataVolume volume, no containerDisk). Name it `TestCeph_ScheduleCompileSyncMaterializeVolume_E2E`.

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go test ./test/ -run TestCeph -v 2>&1 | tail -30'` → PASS.

- [ ] **Step 3: Rook manifest/script (best-effort infra).** Create `hack/rook-ceph-up.sh`: apply the Rook operator (`rook-ceph` from the upstream release manifests — `kubectl apply -f https://raw.githubusercontent.com/rook/rook/<ver>/deploy/examples/{crds,common,operator}.yaml`), then apply an inline minimal `CephCluster` (`spec.mon.count: 1`, `spec.mgr.count: 1`, `spec.storage.useAllDevices: false` + a directory/host-based OSD so it runs on kind without a raw device, `spec.cephVersion.allowUnsupported: true`) + a `CephBlockPool{spec.replicated.size: 1, requireSafeReplicaSize: false}` + a `ceph-rbd` `StorageClass` (provisioner `rook-ceph.rbd.csi.ceph.com`, `pool: <blockpool>`, `imageFormat: "2"`, `imageFeatures: layering`, `csi.storage.k8s.io/*` secret refs to the rook operator namespace). Add a `--dry-run` guard + a clear "single-mon replica-1, NO redundancy, dev only" header. Wire an optional call into `hack/install-stack.sh` (behind a flag/env, after CDI). This is INFRA — do NOT block on a live Rook bring-up in this task; the script + manifests are the deliverable. If you attempt a live apply on a kind cluster and it doesn't converge within a reasonable budget, leave the script committed + note it.

- [ ] **Step 4: Full workspace build + tests + commit.**

`nix develop --command bash -c 'for m in api central netplane; do echo "== $m =="; (cd /home/nik/Development/ironcore-net-xdp/$m && go build ./... && go test ./... 2>&1 | grep -vE "no test files"); done 2>&1 | tail -50'`
Expected: green (kine durability skips; benign SSA managedFields log non-fatal).

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/test hack/rook-ceph-up.sh hack/install-stack.sh
git commit -m "feat: Rook Ceph dev backend + Ceph storage chained e2e (schedule->compile->sync->DataVolume->VM)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

- [ ] **Step 5: Wrap (controller-run).** Update memory (`ceph-storage-volume-attachment.md` + MEMORY.md index): Volume + CompiledVolumeAttachment net types (Phase-1b recipe) + compiler emits attachments + broker syncs (3rd type) + VolumeMaterializer → CDI DataVolume (RBD) + VM boots from the DataVolume PVCs (workload-join, containerDisk fallback); CDI direct dep + a hand CDI CRD fixture; Rook single-mon replica-1 dev backend (`hack/rook-ceph-up.sh`, best-effort live). Open: cross-cluster shared-RBD mobility, NetworkFence, live Rook boot, storage.ectobase.dev split, broker generic refactor (3rd type). Then finish the branch via superpowers:finishing-a-development-branch.

---

## Notes for the executor

- **Two new net types via the Phase-1b recipe** (Task 1) — `central/apis/net/compiledvm_*` + the CompiledVM conversion block are the exact template; roundtrip fuzz is the guard.
- **Keep CompiledNIC/CompiledVM/scheduler/broker-NIC-VM byte-identical** — this phase is additive. `buildVM` gains a param; pass `nil` for the ephemeral path.
- **CDI types verified for v1.64.0** (Task 4) — if a field name mismatches at build, adjust to the pinned package; the CRD-in-envtest is a hand-written fixture like the KubeVirt one.
- **SSA for the DataVolume + VM** (CDI/KubeVirt webhooks default fields); TypeMeta set.
- **`WatchListClient=false`** on the compiler's CompiledVolumeAttachment watch (central-aggregated); NOT on the downstream materializers.
- **All three compiled objects carry the same `spec.clusterName` + `workload` label** (same VM placement) — the e2e asserts co-location; the VM↔attachment join is by the `workload` label.
- **Rook is best-effort/infra** — the control-plane envtest gate does not depend on it.
- Sequential git; per-task spec + quality review; envtest/codegen via the nix devShell.
```
