# Phase 5b — Tier-2 Fence-Gated Cross-Cluster Failover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Phase-3 `Fencer` seam real (whole-pool /64 storage + network fences) and add the recovery half, so a lost compute pool's VMs safely fail over to a healthy pool with an at-most-one-live-writer guarantee.

**Architecture:** Central holds each pool's fence coordinates (its node /64 underlay prefixes, broker-reported before partition). On `poolLost`, the failover reconciler fences **every** /64 (csi-addons `NetworkFence` at Ceph + a reflector route-blocklist), waits for all to confirm active (barrier), then sticky-re-binds each VM with capacity + anti-affinity. Recovery clears each /64's fence only after the returning broker GC-confirms the node drained. Fail-safe: any unconfirmed step leaves the VM in place, no `Spec` write.

**Tech Stack:** Go (controller-runtime, apiserver-kit aggregated apiserver + envtest, client-go), gRPC (routebus.v1), csi-addons `NetworkFence` (unstructured), the netplane reflector RIB.

**Spec:** `docs/superpowers/specs/2026-08-05-tier2-failover-fencing-design.md`
**Branch:** `feat/tier2-failover-fencing` (exists).

---

## Conventions for every task

- Run Go tooling in the nix devShell: `nix develop --command bash -c '...'` (provides `KUBEBUILDER_ASSETS` for envtest, `controller-gen`, `protoc`).
- Central module: `github.com/trevex/ectobase/central` (dir `central/`). Netplane: `github.com/trevex/ectobase/netplane`. Shared API: `github.com/trevex/ectobase/api` (dir `api/`).
- **The net API is two-layer:** external versioned `api/v1alpha1/*` + internal hub `central/apis/net/*` + **hand-written** conversions `central/apis/net/v1alpha1/conversion.go` (conversion-gen can't handle the alias). A new net field must be added in BOTH type files AND both conversion directions, then deepcopy regenerated. Platform group (`central/apis/platform/*`) uses generated conversions.
- Codegen commands: `make generate` (api deepcopy + CRD + chart CRD sync); `cd central && ./hack/update-codegen.sh` (central deepcopy/conversions/client-go); `make proto-routebus` (routebus gRPC stubs).
- Commit after each task with the shown message. Pre-commit skips rust for Go-only changes.

---

## File Structure

**API types (shared + central hub + conversions):**
- `api/v1alpha1/virtualmachine_types.go` (modify) — add `Status.Placement` + `Spec.AntiAffinity`.
- `central/apis/net/virtualmachine_types.go` (modify) — mirror.
- `central/apis/net/v1alpha1/conversion.go` (modify) — mirror both directions for the new fields.
- `central/apis/platform/v1alpha1/clusterpool_types.go` + `central/apis/platform/clusterpool_types.go` (modify) — add `Status.NodePrefixes`, `Status.NodeDrain`, `Status.FencedPrefixes`.

**Central logic:**
- `central/internal/scheduler/schedule.go` (modify) — anti-affinity predicate + `ScheduleBatch` capacity accumulation.
- `central/internal/failover/failover.go` (modify) — `PrefixFencer` seam, whole-pool fence barrier, recovery release.
- `central/internal/fence/storage.go` (create) — `StorageFencer` (csi-addons NetworkFence).
- `central/internal/fence/network.go` (create) — `NetworkFencer` (reflector admin gRPC client).
- `central/internal/broker/report.go` (create) — upward NodePrefixes/Placement stamping + drain-confirm.
- `central/cmd/controller/main.go`, `central/cmd/broker/main.go` (modify) — wiring.

**Reflector / route bus:**
- `api/proto/routebus/v1/routebus.proto` (modify) — `RouteBusAdmin` service (`SetFence`/`ClearFence`).
- `netplane/reflector/rib.go` (modify) — /64 blocklist (gate Announce, filter Subscribe, withdraw matching).
- `netplane/reflector/admin.go` (create) — `AdminServer` implementing the admin RPCs over the RIB.
- `netplane/cmd/reflector/main.go` (modify) — register the admin service.

**Tests:** unit alongside each package; integration in `central/test/`.

---

## Task 1: ClusterPool status fence-coordinate fields

Adds the pool's fence coordinates + drain/fenced tracking to `ClusterPoolStatus` (platform group; generated conversions).

**Files:**
- Modify: `central/apis/platform/v1alpha1/clusterpool_types.go`
- Modify: `central/apis/platform/clusterpool_types.go`
- Test: `central/apis/platform/v1alpha1/clusterpool_fence_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `central/apis/platform/v1alpha1/clusterpool_fence_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import "testing"

func TestClusterPoolStatus_FenceFields(t *testing.T) {
	s := ClusterPoolStatus{
		NodePrefixes:   []string{"2001:db8:0:1::/64"},
		FencedPrefixes: []string{"2001:db8:0:1::/64"},
		NodeDrain:      []NodeDrainStatus{{Prefix: "2001:db8:0:1::/64", Drained: true}},
	}
	if s.NodePrefixes[0] != "2001:db8:0:1::/64" || !s.NodeDrain[0].Drained {
		t.Fatalf("fence fields not wired: %+v", s)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd central && go test ./apis/platform/v1alpha1/ -run TestClusterPoolStatus_FenceFields'`
Expected: FAIL — `NodePrefixes`/`NodeDrain`/`FencedPrefixes`/`NodeDrainStatus` undefined (compile error).

- [ ] **Step 3: Add the fields to the versioned type**

In `central/apis/platform/v1alpha1/clusterpool_types.go`, add to `ClusterPoolStatus` (after the `Lease` field) and add the `NodeDrainStatus` type:

```go
	// NodePrefixes is the set of node /64 underlay prefixes composing this cluster,
	// reported by the broker. Central fences these (Ceph NetworkFence + route
	// blocklist) to evacuate a lost pool without reaching it.
	// +optional
	NodePrefixes []string `json:"nodePrefixes,omitempty" protobuf:"bytes,5,rep,name=nodePrefixes"`
	// FencedPrefixes is the subset of NodePrefixes central has fenced (evacuation).
	// +optional
	FencedPrefixes []string `json:"fencedPrefixes,omitempty" protobuf:"bytes,6,rep,name=fencedPrefixes"`
	// NodeDrain reports, per fenced /64, whether the returning broker has confirmed
	// its stale VMIs are terminated (safe to release the fence).
	// +optional
	// +listType=map
	// +listMapKey=prefix
	NodeDrain []NodeDrainStatus `json:"nodeDrain,omitempty" protobuf:"bytes,7,rep,name=nodeDrain"`
}

// NodeDrainStatus is the per-/64 drain confirmation used to gate fence release.
type NodeDrainStatus struct {
	// Prefix is the node /64 underlay prefix.
	Prefix string `json:"prefix" protobuf:"bytes,1,opt,name=prefix"`
	// Drained is true once the broker confirms the /64's stale VMIs are gone.
	Drained bool `json:"drained,omitempty" protobuf:"varint,2,opt,name=drained"`
}
```

(Delete the original closing `}` of `ClusterPoolStatus` that the snippet replaces — the block above ends the struct then declares `NodeDrainStatus`.)

- [ ] **Step 4: Mirror the fields in the internal hub type**

In `central/apis/platform/clusterpool_types.go`, add to `ClusterPoolStatus` (after `Lease`) and add the hub `NodeDrainStatus` (no json/protobuf tags — internal types omit them, matching the existing hub style):

```go
	// NodePrefixes is the set of node /64 underlay prefixes composing this cluster.
	NodePrefixes []string
	// FencedPrefixes is the subset of NodePrefixes central has fenced.
	FencedPrefixes []string
	// NodeDrain reports per-/64 drain confirmation gating fence release.
	NodeDrain []NodeDrainStatus
}

// NodeDrainStatus is the per-/64 drain confirmation used to gate fence release.
type NodeDrainStatus struct {
	Prefix  string
	Drained bool
}
```

- [ ] **Step 5: Regenerate deepcopy + conversions**

Run: `nix develop --command bash -c 'cd central && ./hack/update-codegen.sh'`
Expected: regenerates `zz_generated.deepcopy.go` (both dirs) + `zz_generated.conversion.go` for platform; exits 0. If it reports a conversion gap, re-run — platform uses conversion-gen which handles same-shaped fields automatically.

- [ ] **Step 6: Run the test + full build**

Run: `nix develop --command bash -c 'cd central && go test ./apis/platform/... && go build ./...'`
Expected: PASS + build clean.

- [ ] **Step 7: Commit**

```bash
git add central/apis/platform/ central/client-go/
git commit -m "feat(central): ClusterPool status fence coordinates (NodePrefixes/FencedPrefixes/NodeDrain)"
```

---

## Task 2: VirtualMachine Placement status + anti-affinity spec

Adds `Status.Placement` (broker-reported running location) and a minimal `Spec.AntiAffinity` (group key for failover-time spread) to the net VirtualMachine — external type + hub + hand-written conversions.

**Files:**
- Modify: `api/v1alpha1/virtualmachine_types.go`
- Modify: `central/apis/net/virtualmachine_types.go`
- Modify: `central/apis/net/v1alpha1/conversion.go`
- Test: `central/apis/net/v1alpha1/vm_placement_conversion_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `central/apis/net/v1alpha1/vm_placement_conversion_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	net "github.com/trevex/ectobase/central/apis/net"
)

func TestVirtualMachine_PlacementAndAntiAffinity_Roundtrip(t *testing.T) {
	in := &netv1.VirtualMachine{}
	in.Spec.AntiAffinity = &netv1.VMAntiAffinity{Group: "web"}
	in.Status.Placement = &netv1.VMPlacement{ClusterName: "poolA", NodeName: "n1", NodePrefix: "2001:db8:0:1::/64"}

	var hub net.VirtualMachine
	if err := Convert_v1alpha1_VirtualMachine_To_net_VirtualMachine(in, &hub, nil); err != nil {
		t.Fatalf("to hub: %v", err)
	}
	if hub.Spec.AntiAffinity == nil || hub.Spec.AntiAffinity.Group != "web" {
		t.Fatalf("anti-affinity lost to hub: %+v", hub.Spec.AntiAffinity)
	}
	if hub.Status.Placement == nil || hub.Status.Placement.NodePrefix != "2001:db8:0:1::/64" {
		t.Fatalf("placement lost to hub: %+v", hub.Status.Placement)
	}

	var out netv1.VirtualMachine
	if err := Convert_net_VirtualMachine_To_v1alpha1_VirtualMachine(&hub, &out, nil); err != nil {
		t.Fatalf("to versioned: %v", err)
	}
	if out.Spec.AntiAffinity.Group != "web" || out.Status.Placement.ClusterName != "poolA" {
		t.Fatalf("roundtrip mismatch: %+v %+v", out.Spec.AntiAffinity, out.Status.Placement)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd central && go test ./apis/net/v1alpha1/ -run TestVirtualMachine_PlacementAndAntiAffinity_Roundtrip'`
Expected: FAIL — `VMAntiAffinity`/`VMPlacement` undefined (compile error).

- [ ] **Step 3: Add the types to the external versioned API**

In `api/v1alpha1/virtualmachine_types.go`, add to `VirtualMachineSpec` (after `PoolSelector`):

```go
	// AntiAffinity, if set, spreads VMs sharing a Group across ClusterPools during
	// scheduling and failover (best-effort: availability wins if no non-violating pool).
	// +optional
	AntiAffinity *VMAntiAffinity `json:"antiAffinity,omitempty"`
```

Add to `VirtualMachineStatus` (after `Conditions`):

```go
	// Placement is the VM's actual running location, stamped by the broker. Central
	// uses NodePrefix as the fence coordinate and to gate recovery drain.
	// +optional
	Placement *VMPlacement `json:"placement,omitempty"`
```

Add these types at the end of the file:

```go
// VMAntiAffinity is a minimal anti-affinity: VMs sharing Group should land on
// different ClusterPools. Best-effort — a failover with no non-violating pool
// places anyway and records the violation.
type VMAntiAffinity struct {
	// Group is the anti-affinity key; VMs with the same Group repel each other.
	Group string `json:"group,omitempty"`
}

// VMPlacement is the VM's actual running location, reported upward by the broker.
type VMPlacement struct {
	// ClusterName is the pool the VM is running on.
	ClusterName string `json:"clusterName,omitempty"`
	// NodeName is the node running the VM.
	NodeName string `json:"nodeName,omitempty"`
	// NodePrefix is that node's /64 underlay prefix (the fence coordinate).
	NodePrefix string `json:"nodePrefix,omitempty"`
}
```

- [ ] **Step 4: Mirror the types in the internal hub**

In `central/apis/net/virtualmachine_types.go`, add to `VirtualMachineSpec` (after `PoolSelector`):

```go
	// AntiAffinity spreads VMs sharing a Group across pools during scheduling/failover.
	AntiAffinity *VMAntiAffinity
```

Add to `VirtualMachineStatus` (after `Conditions`):

```go
	// Placement is the VM's actual running location (broker-reported).
	Placement *VMPlacement
```

Add at the end of the file:

```go
// VMAntiAffinity is the hub mirror of the anti-affinity group key.
type VMAntiAffinity struct {
	Group string
}

// VMPlacement is the hub mirror of the VM's actual running location.
type VMPlacement struct {
	ClusterName string
	NodeName    string
	NodePrefix  string
}
```

- [ ] **Step 5: Extend the hand-written conversions**

In `central/apis/net/v1alpha1/conversion.go`, find `Convert_v1alpha1_VirtualMachineSpec_To_net_VirtualMachineSpec` and its reverse, and `Convert_v1alpha1_VirtualMachineStatus_To_net_VirtualMachineStatus` and its reverse. Add the field copies. In the **Spec → net** direction add:

```go
	if in.AntiAffinity != nil {
		out.AntiAffinity = &net.VMAntiAffinity{Group: in.AntiAffinity.Group}
	} else {
		out.AntiAffinity = nil
	}
```

In the **Spec net → versioned** direction add:

```go
	if in.AntiAffinity != nil {
		out.AntiAffinity = &netv1.VMAntiAffinity{Group: in.AntiAffinity.Group}
	} else {
		out.AntiAffinity = nil
	}
```

In the **Status → net** direction add:

```go
	if in.Placement != nil {
		out.Placement = &net.VMPlacement{ClusterName: in.Placement.ClusterName, NodeName: in.Placement.NodeName, NodePrefix: in.Placement.NodePrefix}
	} else {
		out.Placement = nil
	}
```

In the **Status net → versioned** direction add:

```go
	if in.Placement != nil {
		out.Placement = &netv1.VMPlacement{ClusterName: in.Placement.ClusterName, NodeName: in.Placement.NodeName, NodePrefix: in.Placement.NodePrefix}
	} else {
		out.Placement = nil
	}
```

(The exact receiver/param names `in`/`out` and the `net`/`netv1` import aliases already exist in that file — match them. If the conversion functions use a helper for pointers, follow the local style; the explicit nil-guarded copy above is always safe.)

- [ ] **Step 6: Regenerate deepcopy + CRD**

Run: `nix develop --command bash -c 'make generate && cd central && ./hack/update-codegen.sh'`
Expected: regenerates `api/v1alpha1/zz_generated.deepcopy.go`, the CRD `config/crd/bases/net.ectobase.dev_virtualmachines.yaml` (+ chart sync), and central deepcopy; exits 0.

- [ ] **Step 7: Run the test + build**

Run: `nix develop --command bash -c 'cd central && go test ./apis/net/... && go build ./... && cd ../api && go build ./...'`
Expected: PASS + build clean (roundtrip conversion holds).

- [ ] **Step 8: Commit**

```bash
git add api/ central/apis/ central/client-go/ config/crd/ deploy/charts/
git commit -m "feat(api): VirtualMachine Status.Placement + Spec.AntiAffinity (net conversions)"
```

---

## Task 3: Scheduler — anti-affinity predicate + batch capacity accounting

Adds an anti-affinity filter and a `ScheduleBatch` that accumulates committed resources across a failover burst so N VMs don't over-commit one target.

**Files:**
- Modify: `central/internal/scheduler/schedule.go`
- Test: `central/internal/scheduler/schedule_antiaffinity_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `central/internal/scheduler/schedule_antiaffinity_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package scheduler

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	"github.com/trevex/ectobase/central/internal/clusterpool"
)

func readyPool(name string, cpu int64) platformv1.ClusterPool {
	return platformv1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: platformv1.ClusterPoolStatus{
			Phase:       clusterpool.PhaseReady,
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: *resource.NewQuantity(cpu, resource.DecimalSI)},
		},
	}
}

func vmWith(group string, cpu int64) *netv1.VirtualMachine {
	vm := &netv1.VirtualMachine{}
	vm.Spec.Resources.Requests = corev1.ResourceList{corev1.ResourceCPU: *resource.NewQuantity(cpu, resource.DecimalSI)}
	if group != "" {
		vm.Spec.AntiAffinity = &netv1.VMAntiAffinity{Group: group}
	}
	return vm
}

// occupancy: pool -> set of anti-affinity groups already placed there.
func TestSchedule_AntiAffinity_AvoidsCoLocation(t *testing.T) {
	pools := []platformv1.ClusterPool{readyPool("A", 8), readyPool("B", 8)}
	occ := map[string]map[string]bool{"A": {"web": true}}
	name, _, violated, ok := ScheduleAntiAffine(vmWith("web", 1), pools, nil, occ)
	if !ok || name != "B" || violated {
		t.Fatalf("want B non-violating, got name=%q violated=%v ok=%v", name, violated, ok)
	}
}

func TestSchedule_AntiAffinity_AvailabilityWinsWithViolation(t *testing.T) {
	pools := []platformv1.ClusterPool{readyPool("A", 8)} // only A, already holds web
	occ := map[string]map[string]bool{"A": {"web": true}}
	name, _, violated, ok := ScheduleAntiAffine(vmWith("web", 1), pools, nil, occ)
	if !ok || name != "A" || !violated {
		t.Fatalf("want A placed with violation, got name=%q violated=%v ok=%v", name, violated, ok)
	}
}

func TestScheduleBatch_NoOverCommit(t *testing.T) {
	pools := []platformv1.ClusterPool{readyPool("A", 2)} // fits exactly two 1-CPU VMs
	vms := []*netv1.VirtualMachine{vmWith("", 1), vmWith("", 1), vmWith("", 1)}
	res := ScheduleBatch(vms, pools)
	if res[0].Pool != "A" || res[1].Pool != "A" {
		t.Fatalf("first two should fit A: %+v", res)
	}
	if res[2].OK {
		t.Fatalf("third must not fit (capacity 2): %+v", res[2])
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd central && go test ./internal/scheduler/ -run "AntiAffin|Batch"'`
Expected: FAIL — `ScheduleAntiAffine`/`ScheduleBatch` undefined.

- [ ] **Step 3: Implement the anti-affinity scheduler + batch**

Append to `central/internal/scheduler/schedule.go`:

```go
// ScheduleAntiAffine is Schedule plus anti-affinity: pools already holding the vm's
// AntiAffinity.Group (per occupancy: poolName -> set of groups) are avoided. It first
// tries non-violating fitting pools; if none, it falls back to any fitting pool and
// reports violated=true (availability wins). occupancy may be nil.
func ScheduleAntiAffine(vm *netv1.VirtualMachine, pools []platformv1.ClusterPool, allocated map[string]corev1.ResourceList, occupancy map[string]map[string]bool) (string, string, bool, bool) {
	group := ""
	if vm.Spec.AntiAffinity != nil {
		group = vm.Spec.AntiAffinity.Group
	}
	if group == "" {
		name, reason, ok := Schedule(vm, pools, allocated)
		return name, reason, false, ok
	}
	// First pass: pools NOT already holding the group.
	var clean []platformv1.ClusterPool
	for i := range pools {
		if occupancy[pools[i].Name][group] {
			continue
		}
		clean = append(clean, pools[i])
	}
	if name, reason, ok := Schedule(vm, clean, allocated); ok {
		return name, reason, false, true
	}
	// Fallback: any fitting pool, accept the violation.
	name, reason, ok := Schedule(vm, pools, allocated)
	return name, reason, ok, ok // violated == ok (a placement here is a violation)
}

// Placement is one VM's ScheduleBatch outcome.
type Placement struct {
	Pool     string
	Violated bool
	OK       bool
	Reason   string
}

// ScheduleBatch places a batch of VMs against the pools, accumulating committed
// resources (so N VMs don't over-commit one target) and anti-affinity occupancy
// (so a batch doesn't co-locate a Group it just placed). Order follows the input.
func ScheduleBatch(vms []*netv1.VirtualMachine, pools []platformv1.ClusterPool) []Placement {
	allocated := map[string]corev1.ResourceList{}
	occupancy := map[string]map[string]bool{}
	out := make([]Placement, len(vms))
	for i, vm := range vms {
		name, reason, violated, ok := ScheduleAntiAffine(vm, pools, allocated, occupancy)
		out[i] = Placement{Pool: name, Violated: violated, OK: ok, Reason: reason}
		if !ok {
			continue
		}
		// Commit this VM's requests against the chosen pool.
		cur := allocated[name]
		if cur == nil {
			cur = corev1.ResourceList{}
		}
		for r, q := range vm.Spec.Resources.Requests {
			c := cur[r]
			c.Add(q)
			cur[r] = c
		}
		allocated[name] = cur
		// Record anti-affinity occupancy.
		if vm.Spec.AntiAffinity != nil && vm.Spec.AntiAffinity.Group != "" {
			if occupancy[name] == nil {
				occupancy[name] = map[string]bool{}
			}
			occupancy[name][vm.Spec.AntiAffinity.Group] = true
		}
	}
	return out
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command bash -c 'cd central && go test ./internal/scheduler/'`
Expected: PASS (all scheduler tests, old + new).

- [ ] **Step 5: Commit**

```bash
git add central/internal/scheduler/
git commit -m "feat(scheduler): anti-affinity ScheduleAntiAffine + ScheduleBatch capacity accounting"
```

---

## Task 4: PrefixFencer seam + whole-pool fence barrier

Redefines the `Fencer` seam from per-VM to per-/64 storage+network fencers, and reworks the failover reconciler to fence the whole pool (barrier) before any re-bind, then sticky-re-bind via `ScheduleBatch`.

**Files:**
- Modify: `central/internal/failover/failover.go`
- Modify: `central/internal/failover/failover_test.go`
- Modify: `central/test/failover_test.go` (update the fake fencer to the new seam)

- [ ] **Step 1: Write the failing test**

Replace the body of `central/internal/failover/failover_test.go` with (keeps the package + helpers, swaps to the new seam):

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package failover

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	"github.com/trevex/ectobase/central/internal/clusterpool"
)

type okFencer struct{}

func (okFencer) Fence(context.Context, string) error   { return nil }
func (okFencer) Release(context.Context, string) error { return nil }

type denyFencer struct{ err error }

func (d denyFencer) Fence(context.Context, string) error   { return d.err }
func (denyFencer) Release(context.Context, string) error   { return nil }

func lostPoolObj(name string, prefixes ...string) *platformv1.ClusterPool {
	old := metav1.NewMicroTime(time.Now().Add(-10 * time.Minute))
	return &platformv1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: platformv1.ClusterPoolStatus{
			Phase:        clusterpool.PhaseUnknown,
			Lease:        &platformv1.ClusterPoolLease{RenewTime: &old},
			NodePrefixes: prefixes,
		},
	}
}

func vmOn(name, pool string) *netv1.VirtualMachine {
	return &netv1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: netv1.VirtualMachineSpec{ClusterName: pool}}
}

func TestFailover_WholePoolFence_ThenRebind(t *testing.T) {
	scheme := testScheme(t)
	lost := lostPoolObj("A", "2001:db8:0:1::/64", "2001:db8:0:2::/64")
	healthy := readyPoolObj("B")
	vm := vmOn("vm1", "A")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lost, healthy, vm).WithStatusSubresource(vm, lost).Build()
	r := &Reconciler{Client: c, StorageFencer: okFencer{}, NetworkFencer: okFencer{}, FailoverThreshold: time.Minute}

	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &netv1.VirtualMachine{}
	_ = c.Get(context.Background(), key("vm1"), got)
	if got.Spec.ClusterName != "B" {
		t.Fatalf("want rebind to B, got %q", got.Spec.ClusterName)
	}
}

func TestFailover_PartialFence_Blocks(t *testing.T) {
	scheme := testScheme(t)
	lost := lostPoolObj("A", "2001:db8:0:1::/64")
	vm := vmOn("vm1", "A")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lost, readyPoolObj("B"), vm).WithStatusSubresource(vm, lost).Build()
	r := &Reconciler{Client: c, StorageFencer: denyFencer{errors.New("no ceph")}, NetworkFencer: okFencer{}, FailoverThreshold: time.Minute}

	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &netv1.VirtualMachine{}
	_ = c.Get(context.Background(), key("vm1"), got)
	if got.Spec.ClusterName != "A" {
		t.Fatalf("must NOT rebind when a fence is unconfirmed, got %q", got.Spec.ClusterName)
	}
}
```

Then create shared helpers `central/internal/failover/helpers_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package failover

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	"github.com/trevex/ectobase/central/internal/clusterpool"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := platformv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func readyPoolObj(name string) *platformv1.ClusterPool {
	return &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: platformv1.ClusterPoolStatus{Phase: clusterpool.PhaseReady}}
}

func req(name string) ctrl.Request { return ctrl.Request{NamespacedName: types.NamespacedName{Name: name}} }
func key(name string) client.ObjectKey { return types.NamespacedName{Name: name} }

var _ = metav1.Now
```

(If `netv1.AddToScheme`/`platformv1.AddToScheme` are named differently, grep `func AddToScheme` in `api/v1alpha1/` and `central/apis/platform/v1alpha1/` and use the real names.)

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd central && go test ./internal/failover/'`
Expected: FAIL — `Reconciler` has no `StorageFencer`/`NetworkFencer` fields; `PrefixFencer` seam not defined (compile error).

- [ ] **Step 3: Rework `failover.go` to the new seam + whole-pool barrier**

Replace the `Fencer`/`DenyFencer`/`Reconciler`/`failoverVM` region of `central/internal/failover/failover.go` (lines ~26–110) with:

```go
// PrefixFencer applies/releases ONE fence backend (storage or network) for a single
// node /64. Fence must be idempotent and return nil ONLY when the fence is confirmed
// ACTIVE; Release returns nil only when the fence is confirmed removed.
type PrefixFencer interface {
	Fence(ctx context.Context, prefix string) error
	Release(ctx context.Context, prefix string) error
}

// DenyFencer refuses to confirm any fence; wiring it means Tier-2 always fails safe.
type DenyFencer struct{}

func (DenyFencer) Fence(context.Context, string) error   { return fmt.Errorf("no fence actuator configured") }
func (DenyFencer) Release(context.Context, string) error { return fmt.Errorf("no fence actuator configured") }

// Reconciler runs Tier-2 fence-gated failover for VMs bound to a lost pool.
type Reconciler struct {
	Client            client.Client
	StorageFencer     PrefixFencer
	NetworkFencer     PrefixFencer
	FailoverThreshold time.Duration
}

func (r *Reconciler) Reconcile(ctx context.Context, rq ctrl.Request) (ctrl.Result, error) {
	var pool platformv1.ClusterPool
	if err := r.Client.Get(ctx, rq.NamespacedName, &pool); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Recovery path: release fences for /64s the broker has confirmed drained.
	if err := r.releaseDrained(ctx, &pool); err != nil {
		return ctrl.Result{}, err
	}
	if !poolLost(&pool, time.Now(), r.FailoverThreshold) {
		return ctrl.Result{RequeueAfter: r.FailoverThreshold}, nil
	}
	// Whole-pool fence: every /64 must confirm BOTH fences active (barrier) before
	// any re-bind. A pool with no reported /64s cannot be safely fenced -> block.
	if len(pool.Status.NodePrefixes) == 0 {
		return ctrl.Result{RequeueAfter: r.FailoverThreshold}, r.blockPoolVMs(ctx, pool.Name, "no NodePrefixes reported; cannot fence")
	}
	var fenced []string
	for _, p := range pool.Status.NodePrefixes {
		if err := r.StorageFencer.Fence(ctx, p); err != nil {
			return ctrl.Result{RequeueAfter: r.FailoverThreshold}, r.blockPoolVMs(ctx, pool.Name, "storage fence unconfirmed for "+p+": "+err.Error())
		}
		if err := r.NetworkFencer.Fence(ctx, p); err != nil {
			return ctrl.Result{RequeueAfter: r.FailoverThreshold}, r.blockPoolVMs(ctx, pool.Name, "network fence unconfirmed for "+p+": "+err.Error())
		}
		fenced = append(fenced, p)
	}
	if err := r.setFencedPrefixes(ctx, &pool, fenced); err != nil {
		return ctrl.Result{}, err
	}
	// All /64s fenced active -> schedule + sticky re-bind the whole batch.
	return ctrl.Result{RequeueAfter: r.FailoverThreshold}, r.rebindPoolVMs(ctx, pool.Name)
}
```

- [ ] **Step 4: Add the batch re-bind + block + fenced-tracking helpers**

Append to `central/internal/failover/failover.go` (imports needed: add `"github.com/trevex/ectobase/central/internal/scheduler"`, `"k8s.io/apimachinery/pkg/api/meta"`, `metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"` — some already imported):

```go
// rebindPoolVMs schedules ALL VMs on lostPool as a batch (capacity + anti-affinity
// accounted) and sticky-re-binds each that placed; VMs with no target get FailoverBlocked.
func (r *Reconciler) rebindPoolVMs(ctx context.Context, lostPool string) error {
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms); err != nil {
		return fmt.Errorf("list vms: %w", err)
	}
	var pools platformv1.ClusterPoolList
	if err := r.Client.List(ctx, &pools); err != nil {
		return fmt.Errorf("list pools: %w", err)
	}
	var candidates []platformv1.ClusterPool
	for _, p := range pools.Items {
		if p.Name != lostPool {
			candidates = append(candidates, p)
		}
	}
	var batch []*netv1.VirtualMachine
	for i := range vms.Items {
		if vms.Items[i].Spec.ClusterName == lostPool {
			batch = append(batch, &vms.Items[i])
		}
	}
	placements := scheduler.ScheduleBatch(batch, candidates)
	for i, vm := range batch {
		pl := placements[i]
		if !pl.OK {
			if err := r.block(ctx, vm, "no pool to fail over to: "+pl.Reason); err != nil {
				return err
			}
			continue
		}
		vm.Spec.ClusterName = pl.Pool
		if err := r.Client.Update(ctx, vm); err != nil {
			return fmt.Errorf("rebind vm %s: %w", vm.Name, err)
		}
		msg := "failed over to " + pl.Pool
		if pl.Violated {
			msg += " (anti-affinity violated: no non-violating pool)"
		}
		meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "FailoverBlocked", Status: metav1.ConditionFalse, Reason: "FailedOver", Message: msg, ObservedGeneration: vm.Generation})
		meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "Scheduled", Status: metav1.ConditionTrue, Reason: "FailedOver", Message: "bound to " + pl.Pool, ObservedGeneration: vm.Generation})
		if err := r.Client.Status().Update(ctx, vm); err != nil {
			return fmt.Errorf("status vm %s: %w", vm.Name, err)
		}
	}
	return nil
}

// blockPoolVMs marks every VM on lostPool FailoverBlocked (used when the pool-wide
// fence barrier is not satisfied). Writes only status, never Spec.
func (r *Reconciler) blockPoolVMs(ctx context.Context, lostPool, msg string) error {
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms); err != nil {
		return fmt.Errorf("list vms: %w", err)
	}
	for i := range vms.Items {
		if vms.Items[i].Spec.ClusterName != lostPool {
			continue
		}
		if err := r.block(ctx, &vms.Items[i], msg); err != nil {
			return err
		}
	}
	return nil
}

// setFencedPrefixes records which /64s central has fenced (drives recovery release).
func (r *Reconciler) setFencedPrefixes(ctx context.Context, pool *platformv1.ClusterPool, fenced []string) error {
	pool.Status.FencedPrefixes = fenced
	return r.Client.Status().Update(ctx, pool)
}

// releaseDrained clears the fence (both backends) for every FencedPrefix the broker
// has reported Drained, then trims it from FencedPrefixes. Fail-safe: an un-drained
// /64 stays fenced. Returns nil when there's nothing to release.
func (r *Reconciler) releaseDrained(ctx context.Context, pool *platformv1.ClusterPool) error {
	if len(pool.Status.FencedPrefixes) == 0 {
		return nil
	}
	drained := map[string]bool{}
	for _, d := range pool.Status.NodeDrain {
		if d.Drained {
			drained[d.Prefix] = true
		}
	}
	var remain []string
	changed := false
	for _, p := range pool.Status.FencedPrefixes {
		if !drained[p] {
			remain = append(remain, p)
			continue
		}
		if err := r.StorageFencer.Release(ctx, p); err != nil {
			remain = append(remain, p) // hold the fence if release unconfirmed
			continue
		}
		if err := r.NetworkFencer.Release(ctx, p); err != nil {
			remain = append(remain, p)
			continue
		}
		changed = true
	}
	if !changed {
		return nil
	}
	pool.Status.FencedPrefixes = remain
	return r.Client.Status().Update(ctx, pool)
}
```

Keep the existing `block`, `poolLost`, and `SetupWithManager` functions. Delete the old `failoverVM` function (replaced by `rebindPoolVMs`).

- [ ] **Step 5: Update the envtest fake fencer to the new seam**

In `central/test/failover_test.go`, replace the `confirmingFencer` (and any `splitFencer`) type with the new seam and update the `Reconciler{...}` construction. The fencer becomes:

```go
type confirmingFencer struct{}

func (confirmingFencer) Fence(context.Context, string) error   { return nil }
func (confirmingFencer) Release(context.Context, string) error { return nil }
```

And the reconciler construction becomes `&failover.Reconciler{Client: c, StorageFencer: confirmingFencer{}, NetworkFencer: confirmingFencer{}, FailoverThreshold: time.Minute}`. Any lost `ClusterPool` fixture in this file must now set `Status.NodePrefixes: []string{"2001:db8:0:1::/64"}` (else the barrier blocks). Update accordingly.

- [ ] **Step 6: Run to verify it passes**

Run: `nix develop --command bash -c 'cd central && go test ./internal/failover/ && go build ./...'`
Expected: PASS (unit tests) + build clean. (The envtest `central/test/failover_test.go` runs in Task 13's suite pass; ensure it at least compiles here via `go build ./...` / `go vet ./test/...`.)

- [ ] **Step 7: Commit**

```bash
git add central/internal/failover/ central/test/failover_test.go
git commit -m "feat(failover): PrefixFencer seam + whole-pool fence barrier + batch sticky re-bind + recovery release"
```

---

## Task 5: Update the controller wiring for the new seam

The controller `main.go` still constructs `failover.Reconciler{Fencer: DenyFencer{}}`. Update it to the two-fencer seam (defaulting to `DenyFencer` until Tasks 8–9 provide real actuators, so prod stays fail-safe).

**Files:**
- Modify: `central/cmd/controller/main.go`

- [ ] **Step 1: Update the construction**

In `central/cmd/controller/main.go`, change the `failover.Reconciler{...}` literal (around line 81) from `Fencer: failover.DenyFencer{}` to:

```go
	if err := (&failover.Reconciler{
		Client:            mgr.GetClient(),
		StorageFencer:     failover.DenyFencer{},
		NetworkFencer:     failover.DenyFencer{},
		FailoverThreshold: 2 * time.Minute,
	}).SetupWithManager(mgr); err != nil {
```

(Match the surrounding error-handling style already in the file.)

- [ ] **Step 2: Build to verify**

Run: `nix develop --command bash -c 'cd central && go build ./...'`
Expected: clean build, exit 0.

- [ ] **Step 3: Commit**

```bash
git add central/cmd/controller/main.go
git commit -m "chore(central): wire controller to the two-fencer PrefixFencer seam (DenyFencer default)"
```

---

## Task 6: Reflector RIB /64 blocklist

Adds a per-/64 blocklist to the RIB: reject `Announce` whose nexthop ∈ a fenced /64, filter fenced routes out of `Subscribe` snapshots, and on `SetFence` withdraw already-stored matching routes. `ClearFence` removes the block.

**Files:**
- Modify: `netplane/reflector/rib.go`
- Test: `netplane/reflector/rib_fence_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `netplane/reflector/rib_fence_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import "testing"

type capSink struct {
	id      string
	updates []string // prefixes seen in RouteUpdate ADD
}

func (c *capSink) ID() string { return c.id }
func (c *capSink) Send(m interface{ GetRoute() interface{} }) {}

func TestRIB_Fence_RejectsAnnounceFromFencedNexthop(t *testing.T) {
	r := NewRIB()
	r.SetFence("2001:db8:0:1::/64")
	// Announce a route whose nexthop is inside the fenced /64 -> must be dropped.
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	if r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("fenced-nexthop route must not be stored")
	}
	// A route from an unfenced nexthop is accepted.
	r.Announce("nodeB", 100, "10.0.0.6/32", []string{"2001:db8:0:2::b"}, false)
	if !r.HasRoute(100, "10.0.0.6/32") {
		t.Fatalf("unfenced route must be stored")
	}
}

func TestRIB_SetFence_WithdrawsExistingMatching(t *testing.T) {
	r := NewRIB()
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	if !r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("precondition: route stored")
	}
	r.SetFence("2001:db8:0:1::/64")
	if r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("SetFence must withdraw existing routes with a fenced nexthop")
	}
	r.ClearFence("2001:db8:0:1::/64")
	// After clear, a re-announce is accepted again.
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	if !r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("ClearFence must re-allow announces")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd netplane && go test ./reflector/ -run "RIB_Fence|SetFence"'`
Expected: FAIL — `SetFence`/`ClearFence`/`HasRoute`/nexthop-fencing undefined.

- [ ] **Step 3: Add the blocklist to the RIB**

In `netplane/reflector/rib.go`, add a `fenced` field to the `RIB` struct (in the struct literal in `NewRIB` too), a helper, and the public methods. Add to the struct:

```go
	fenced map[string]*net.IPNet // /64 CIDR string -> parsed net; nexthops inside are blocked
```

Add `"net"` to the imports. In `NewRIB()`'s returned literal add: `fenced: map[string]*net.IPNet{},`.

Add these methods:

```go
// SetFence blocks a node /64: rejects future announces whose nexthop is inside it and
// withdraws already-stored matching routes. Idempotent.
func (r *RIB) SetFence(prefix string) {
	_, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return
	}
	r.mu.Lock()
	r.fenced[prefix] = ipnet
	// Withdraw existing routes any of whose nexthops fall in the fenced /64.
	var victims []routeKey
	for k, e := range r.routes {
		for _, nhs := range e.origins {
			if anyNexthopFenced(nhs, r.fenced) {
				victims = append(victims, k)
				break
			}
		}
	}
	r.mu.Unlock()
	for _, k := range victims {
		r.dropRouteAllOrigins(k)
	}
}

// ClearFence removes a /64 block. Routes are restored by the owning agents' next resync.
func (r *RIB) ClearFence(prefix string) {
	r.mu.Lock()
	delete(r.fenced, prefix)
	r.mu.Unlock()
}

// HasRoute reports whether (vni, prefix) is currently stored. Test/inspection helper.
func (r *RIB) HasRoute(vni uint32, prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.routes[routeKey{vni, prefix}]
	return ok
}

func anyNexthopFenced(nexthops []string, fenced map[string]*net.IPNet) bool {
	for _, nh := range nexthops {
		ip := net.ParseIP(nh)
		if ip == nil {
			continue
		}
		for _, ipnet := range fenced {
			if ipnet.Contains(ip) {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Gate `Announce` and add the withdraw-all helper**

In `netplane/reflector/rib.go`, at the top of `Announce` (after it takes the lock — inspect the existing body; it locks `r.mu`), add a fenced-nexthop rejection. Because `SetFence` above locks `r.mu` itself, do the check inside `Announce` while it holds the lock:

```go
	// (inside Announce, after r.mu.Lock(), before storing)
	if anyNexthopFenced(nexthops, r.fenced) {
		return // drop: this nexthop is fenced
	}
```

Add the helper used by `SetFence` (drops a route from all origins + fans out withdraw). If an equivalent already exists (`withdrawRouteOrigin`/`DropOrigin`), compose it; otherwise add:

```go
// dropRouteAllOrigins removes a route entirely and fans out a WITHDRAW to subscribers.
func (r *RIB) dropRouteAllOrigins(k routeKey) {
	r.mu.Lock()
	e, ok := r.routes[k]
	if !ok {
		r.mu.Unlock()
		return
	}
	for origin := range e.origins {
		if s, ok := r.byOrigin[origin]; ok {
			delete(s, k)
		}
	}
	delete(r.routes, k)
	r.mu.Unlock()
	r.fanout(k, nil, pb.RouteOp_ROUTE_WITHDRAW, "", e.external)
}
```

(Verify the withdraw op enum name via `grep RouteOp_ netplane/gen/routebusv1/*.go`; use the real withdraw constant. `fanout`'s signature is `fanout(k routeKey, nexthops []string, op pb.RouteOp, origin string, external bool)` per `rib.go:214`.)

- [ ] **Step 5: Simplify the test's sink (compile fix)**

The `capSink` in Step 1 referenced an interface that won't match `Sink`. Replace `rib_fence_test.go`'s `capSink` type with a minimal real `Sink` (grep `type Sink interface` in `rib.go:14` for the exact method set — likely `ID() string` + `Send(*pb.ServerMsg)`):

```go
type capSink struct{ id string }

func (c *capSink) ID() string             { return c.id }
func (c *capSink) Send(*pb.ServerMsg)      {}
```

Add the import `pb "github.com/trevex/ectobase/netplane/gen/routebusv1"`. (If `Sink.Send` takes a different type, match it.)

- [ ] **Step 6: Run to verify it passes**

Run: `nix develop --command bash -c 'cd netplane && go test ./reflector/'`
Expected: PASS (all reflector tests, old + new).

- [ ] **Step 7: Commit**

```bash
git add netplane/reflector/rib.go netplane/reflector/rib_fence_test.go
git commit -m "feat(reflector): per-/64 RIB blocklist (reject fenced nexthops, withdraw existing)"
```

---

## Task 7: routebus admin RPC + reflector admin server

Adds a `RouteBusAdmin` gRPC service (`SetFence`/`ClearFence`) to the proto, regenerates stubs, and implements it over the RIB.

**Files:**
- Modify: `api/proto/routebus/v1/routebus.proto`
- Create: `netplane/reflector/admin.go`
- Modify: `netplane/cmd/reflector/main.go`
- Test: `netplane/reflector/admin_test.go` (create)

- [ ] **Step 1: Add the admin service to the proto**

In `api/proto/routebus/v1/routebus.proto`, add (after the existing `RouteBus` service):

```protobuf
// RouteBusAdmin lets central set/clear per-/64 route fences on the reflector.
service RouteBusAdmin {
  rpc SetFence(FenceRequest) returns (FenceReply);
  rpc ClearFence(FenceRequest) returns (FenceReply);
}

message FenceRequest {
  string prefix = 1; // node /64, e.g. "2001:db8:0:1::/64"
}

message FenceReply {}
```

- [ ] **Step 2: Regenerate the stubs**

Run: `nix develop --command bash -c 'make proto-routebus'`
Expected: regenerates `netplane/gen/routebusv1/*.go` with `RouteBusAdminServer`, `FenceRequest`, `FenceReply`; exits 0.

- [ ] **Step 3: Write the failing test**

Create `netplane/reflector/admin_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"context"
	"testing"

	pb "github.com/trevex/ectobase/netplane/gen/routebusv1"
)

func TestAdminServer_SetClearFence(t *testing.T) {
	rib := NewRIB()
	rib.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	a := NewAdminServer(rib)

	if _, err := a.SetFence(context.Background(), &pb.FenceRequest{Prefix: "2001:db8:0:1::/64"}); err != nil {
		t.Fatalf("SetFence: %v", err)
	}
	if rib.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("SetFence must withdraw the fenced route")
	}
	if _, err := a.ClearFence(context.Background(), &pb.FenceRequest{Prefix: "2001:db8:0:1::/64"}); err != nil {
		t.Fatalf("ClearFence: %v", err)
	}
	rib.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	if !rib.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("ClearFence must re-allow the route")
	}
}
```

- [ ] **Step 4: Run to verify it fails**

Run: `nix develop --command bash -c 'cd netplane && go test ./reflector/ -run TestAdminServer'`
Expected: FAIL — `NewAdminServer` undefined.

- [ ] **Step 5: Implement the admin server**

Create `netplane/reflector/admin.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"context"

	pb "github.com/trevex/ectobase/netplane/gen/routebusv1"
)

// AdminServer implements RouteBusAdmin over a RIB: central sets/clears per-/64 route
// fences to suppress a lost pool's overlay routes (the network half of Tier-2 fencing).
type AdminServer struct {
	pb.UnimplementedRouteBusAdminServer
	rib *RIB
}

// NewAdminServer wraps the RIB with the admin fence API.
func NewAdminServer(rib *RIB) *AdminServer { return &AdminServer{rib: rib} }

// SetFence blocks a node /64: rejects future announces from and withdraws existing
// routes whose nexthop is inside it.
func (a *AdminServer) SetFence(_ context.Context, req *pb.FenceRequest) (*pb.FenceReply, error) {
	a.rib.SetFence(req.GetPrefix())
	return &pb.FenceReply{}, nil
}

// ClearFence removes a /64 block; owning agents restore their routes on next resync.
func (a *AdminServer) ClearFence(_ context.Context, req *pb.FenceRequest) (*pb.FenceReply, error) {
	a.rib.ClearFence(req.GetPrefix())
	return &pb.FenceReply{}, nil
}
```

- [ ] **Step 6: Register the admin service in the reflector**

In `netplane/cmd/reflector/main.go`, right after `routebusv1.RegisterRouteBusServer(srv, reflector.NewServer(rib))`, capture the RIB and register the admin service. Change the construction so the RIB is shared:

```go
	rib := reflector.NewRIB()
	routebusv1.RegisterRouteBusServer(srv, reflector.NewServer(rib))
	routebusv1.RegisterRouteBusAdminServer(srv, reflector.NewAdminServer(rib))
```

(Replace the inline `reflector.NewServer(reflector.NewRIB())` so both servers share one RIB.)

- [ ] **Step 7: Run to verify it passes + build**

Run: `nix develop --command bash -c 'cd netplane && go test ./reflector/ && go build ./...'`
Expected: PASS + build clean.

- [ ] **Step 8: Commit**

```bash
git add api/proto/routebus/ netplane/gen/routebusv1/ netplane/reflector/admin.go netplane/reflector/admin_test.go netplane/cmd/reflector/main.go
git commit -m "feat(reflector): RouteBusAdmin SetFence/ClearFence over the RIB blocklist"
```

---

## Task 8: NetworkFencer — reflector admin gRPC client

The central-side `PrefixFencer` whose `Fence`/`Release` dial the reflector's `RouteBusAdmin`.

**Files:**
- Create: `central/internal/fence/network.go`
- Test: `central/internal/fence/network_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `central/internal/fence/network_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package fence

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/trevex/ectobase/netplane/gen/routebusv1"
	"github.com/trevex/ectobase/netplane/reflector"
)

func TestNetworkFencer_FenceCallsAdmin(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	rib := reflector.NewRIB()
	rib.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	pb.RegisterRouteBusAdminServer(srv, reflector.NewAdminServer(rib))
	go srv.Serve(lis)
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	f := NewNetworkFencer(pb.NewRouteBusAdminClient(conn))
	if err := f.Fence(context.Background(), "2001:db8:0:1::/64"); err != nil {
		t.Fatalf("Fence: %v", err)
	}
	if rib.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("Fence should have withdrawn the route via admin RPC")
	}
	if err := f.Release(context.Background(), "2001:db8:0:1::/64"); err != nil {
		t.Fatalf("Release: %v", err)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd central && go test ./internal/fence/ -run TestNetworkFencer'`
Expected: FAIL — package/`NewNetworkFencer` undefined. (Note: this test imports `netplane/reflector`; the central module must be able to resolve it — check `central/go.mod` for a `require`/`replace` on `github.com/trevex/ectobase/netplane`. If absent, add it in Step 3.)

- [ ] **Step 3: Implement the NetworkFencer**

Create `central/internal/fence/network.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package fence provides the central-side storage + network fence actuators that back
// the failover PrefixFencer seam.
package fence

import (
	"context"
	"fmt"

	pb "github.com/trevex/ectobase/netplane/gen/routebusv1"
)

// NetworkFencer is the network half of Tier-2 fencing: it withdraws a lost pool's
// overlay routes by calling the reflector's RouteBusAdmin SetFence/ClearFence.
type NetworkFencer struct {
	admin pb.RouteBusAdminClient
}

// NewNetworkFencer wraps a RouteBusAdmin client.
func NewNetworkFencer(admin pb.RouteBusAdminClient) *NetworkFencer {
	return &NetworkFencer{admin: admin}
}

// Fence blocks the /64 at the reflector (idempotent). nil == the fence is set.
func (f *NetworkFencer) Fence(ctx context.Context, prefix string) error {
	if _, err := f.admin.SetFence(ctx, &pb.FenceRequest{Prefix: prefix}); err != nil {
		return fmt.Errorf("reflector SetFence %s: %w", prefix, err)
	}
	return nil
}

// Release clears the /64 block at the reflector.
func (f *NetworkFencer) Release(ctx context.Context, prefix string) error {
	if _, err := f.admin.ClearFence(ctx, &pb.FenceRequest{Prefix: prefix}); err != nil {
		return fmt.Errorf("reflector ClearFence %s: %w", prefix, err)
	}
	return nil
}
```

If Step 2 showed the netplane module isn't required, run `nix develop --command bash -c 'cd central && go get github.com/trevex/ectobase/netplane && go mod tidy'` (and, if the repo uses a `go.work`, confirm netplane is a workspace member so the local copy resolves).

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command bash -c 'cd central && go test ./internal/fence/'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add central/internal/fence/network.go central/internal/fence/network_test.go central/go.mod central/go.sum
git commit -m "feat(fence): NetworkFencer (reflector RouteBusAdmin client)"
```

---

## Task 9: StorageFencer — csi-addons NetworkFence

The storage half: create/delete a csi-addons `NetworkFence` (unstructured, no new dep) per /64 against an injected client, confirming `active` via the CR's `status.result`.

**Files:**
- Create: `central/internal/fence/storage.go`
- Test: `central/internal/fence/storage_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `central/internal/fence/storage_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package fence

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func nfScheme() *fake.ClientBuilder {
	// Unstructured objects need the GVK registered on the fake client's rest mapper.
	return fake.NewClientBuilder()
}

// A NetworkFence whose status the fake pre-populates as Succeeded confirms active.
func TestStorageFencer_FenceCreatesAndConfirms(t *testing.T) {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(schema.GroupVersionKind{Group: NetworkFenceGVR.Group, Version: NetworkFenceGVR.Version, Kind: "NetworkFence"})
	existing.SetName("ectobase-2001-db8-0-1--64")
	_ = unstructured.SetNestedField(existing.Object, "Succeeded", "status", "result")

	c := fake.NewClientBuilder().WithObjects(existing).Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})

	// Fence on an already-Succeeded CR returns nil (active).
	if err := f.Fence(context.Background(), "2001:db8:0:1::/64"); err != nil {
		t.Fatalf("Fence: %v", err)
	}
}

func TestStorageFencer_FencePendingReturnsError(t *testing.T) {
	c := fake.NewClientBuilder().Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
	// No CR yet: Fence creates it, but status isn't Succeeded -> not active -> error (fail-safe).
	if err := f.Fence(context.Background(), "2001:db8:0:1::/64"); err == nil {
		t.Fatalf("Fence must error until the NetworkFence reports Succeeded")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd central && go test ./internal/fence/ -run TestStorageFencer'`
Expected: FAIL — `NewStorageFencer`/`NetworkFenceGVR` undefined.

- [ ] **Step 3: Implement the StorageFencer**

Create `central/internal/fence/storage.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package fence

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NetworkFenceGVR is the csi-addons NetworkFence group/version (cluster-scoped CR).
var NetworkFenceGVR = schema.GroupVersion{Group: "csiaddons.openshift.io", Version: "v1alpha1"}

// StorageFencer is the storage half of Tier-2 fencing: it blocklists a node /64 at
// Ceph via a csi-addons NetworkFence CR (fenceState=Fenced), confirming active via
// status.result==Succeeded. It writes to an injected client (the Ceph-management
// cluster; the same cluster in the single-cluster lab).
type StorageFencer struct {
	c      client.Client
	driver string
	secret client.ObjectKey
}

// NewStorageFencer wraps the management-cluster client + the CSI driver + provisioner secret.
func NewStorageFencer(c client.Client, driver string, secret client.ObjectKey) *StorageFencer {
	return &StorageFencer{c: c, driver: driver, secret: secret}
}

func fenceName(prefix string) string {
	r := strings.NewReplacer(":", "-", "/", "--", ".", "-")
	return "ectobase-" + r.Replace(prefix)
}

func (f *StorageFencer) obj(prefix, state string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: NetworkFenceGVR.Group, Version: NetworkFenceGVR.Version, Kind: "NetworkFence"})
	u.SetName(fenceName(prefix))
	_ = unstructured.SetNestedField(u.Object, state, "spec", "fenceState")
	_ = unstructured.SetNestedField(u.Object, f.driver, "spec", "driver")
	_ = unstructured.SetNestedStringSlice(u.Object, []string{prefix}, "spec", "cidrs")
	_ = unstructured.SetNestedField(u.Object, f.secret.Name, "spec", "secret", "name")
	_ = unstructured.SetNestedField(u.Object, f.secret.Namespace, "spec", "secret", "namespace")
	return u
}

// Fence ensures a Fenced NetworkFence exists for the /64 and returns nil ONLY when its
// status.result == Succeeded (fail-safe: a Pending/absent-status fence returns an error).
func (f *StorageFencer) Fence(ctx context.Context, prefix string) error {
	want := f.obj(prefix, "Fenced")
	cur := &unstructured.Unstructured{}
	cur.SetGroupVersionKind(want.GroupVersionKind())
	err := f.c.Get(ctx, client.ObjectKey{Name: want.GetName()}, cur)
	if apierrors.IsNotFound(err) {
		if cerr := f.c.Create(ctx, want); cerr != nil {
			return fmt.Errorf("create NetworkFence %s: %w", want.GetName(), cerr)
		}
		return fmt.Errorf("NetworkFence %s created; awaiting Succeeded", want.GetName())
	}
	if err != nil {
		return fmt.Errorf("get NetworkFence %s: %w", want.GetName(), err)
	}
	result, _, _ := unstructured.NestedString(cur.Object, "status", "result")
	if result != "Succeeded" {
		return fmt.Errorf("NetworkFence %s not active (result=%q)", want.GetName(), result)
	}
	return nil
}

// Release flips the CR to Unfenced and deletes it; nil once removed/not-found.
func (f *StorageFencer) Release(ctx context.Context, prefix string) error {
	u := f.obj(prefix, "Unfenced")
	if err := f.c.Delete(ctx, u); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete NetworkFence %s: %w", u.GetName(), err)
	}
	return nil
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command bash -c 'cd central && go test ./internal/fence/'`
Expected: PASS. (If the fake client rejects unstructured without a registered scheme, the test uses the default builder; if it errors on GVK mapping, add `WithScheme` using a scheme where the GVK is registered via `scheme.AddKnownTypeWithName` — but the default fake client tracks unstructured by GVK and should work.)

- [ ] **Step 5: Commit**

```bash
git add central/internal/fence/storage.go central/internal/fence/storage_test.go
git commit -m "feat(fence): StorageFencer (csi-addons NetworkFence, status-confirmed)"
```

---

## Task 10: Broker — stamp NodePrefixes + VM Placement upward

The broker reports each pool's node /64s and each VM's actual placement into central status, so central holds fence coordinates before partition.

**Files:**
- Create: `central/internal/broker/report.go`
- Test: `central/internal/broker/report_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `central/internal/broker/report_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import "testing"

func TestNodePrefixesFromNodes(t *testing.T) {
	nodes := []NodeFact{
		{Name: "n1", Prefix: "2001:db8:0:1::/64"},
		{Name: "n2", Prefix: "2001:db8:0:2::/64"},
		{Name: "n3", Prefix: ""}, // no prefix yet -> skipped
	}
	got := NodePrefixesFromNodes(nodes)
	if len(got) != 2 || got[0] != "2001:db8:0:1::/64" || got[1] != "2001:db8:0:2::/64" {
		t.Fatalf("unexpected prefixes: %v", got)
	}
}

func TestPlacementForVM(t *testing.T) {
	nodes := []NodeFact{{Name: "n1", Prefix: "2001:db8:0:1::/64"}}
	pl := PlacementForVM("poolA", "n1", nodes)
	if pl == nil || pl.NodePrefix != "2001:db8:0:1::/64" || pl.ClusterName != "poolA" {
		t.Fatalf("unexpected placement: %+v", pl)
	}
	if PlacementForVM("poolA", "unknown", nodes) != nil {
		t.Fatalf("unknown node must yield nil placement")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd central && go test ./internal/broker/ -run "NodePrefixes|Placement"'`
Expected: FAIL — `NodeFact`/`NodePrefixesFromNodes`/`PlacementForVM` undefined.

- [ ] **Step 3: Implement the pure reporting helpers**

Create `central/internal/broker/report.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import netv1 "github.com/trevex/ectobase/api/v1alpha1"

// NodeFact is a node's fence-relevant identity: its name and its /64 underlay prefix.
type NodeFact struct {
	Name   string
	Prefix string
}

// NodePrefixesFromNodes returns the /64 underlay prefixes of the given nodes (skipping
// nodes with no assigned prefix), preserving order. This is the pool fence coordinate
// the broker stamps into ClusterPool.Status.NodePrefixes.
func NodePrefixesFromNodes(nodes []NodeFact) []string {
	var out []string
	for _, n := range nodes {
		if n.Prefix == "" {
			continue
		}
		out = append(out, n.Prefix)
	}
	return out
}

// PlacementForVM builds a VMPlacement for a VM running on nodeName in pool, resolving
// the node's /64 from nodes. Returns nil if the node is unknown (nothing to report yet).
func PlacementForVM(pool, nodeName string, nodes []NodeFact) *netv1.VMPlacement {
	for _, n := range nodes {
		if n.Name == nodeName {
			return &netv1.VMPlacement{ClusterName: pool, NodeName: nodeName, NodePrefix: n.Prefix}
		}
	}
	return nil
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command bash -c 'cd central && go test ./internal/broker/'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add central/internal/broker/report.go central/internal/broker/report_test.go
git commit -m "feat(broker): pure helpers for NodePrefixes + VM Placement upward reporting"
```

---

## Task 11: Broker — recovery drain confirmation

The broker, on recovery, confirms a fenced /64's stale VMIs are gone (GC'd) and computes the `NodeDrain` status central uses to release the fence.

**Files:**
- Modify: `central/internal/broker/report.go`
- Test: `central/internal/broker/drain_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `central/internal/broker/drain_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"testing"

	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

func TestDrainStatus_MarksEmptyNodesDrained(t *testing.T) {
	fenced := []string{"2001:db8:0:1::/64", "2001:db8:0:2::/64"}
	// Nodes still running a stale VMI keyed by /64. Node 1 is empty, node 2 still busy.
	busy := map[string]bool{"2001:db8:0:2::/64": true}
	got := DrainStatus(fenced, busy)
	m := map[string]bool{}
	for _, d := range got {
		m[d.Prefix] = d.Drained
	}
	if !m["2001:db8:0:1::/64"] {
		t.Fatalf("empty /64 must be drained")
	}
	if m["2001:db8:0:2::/64"] {
		t.Fatalf("busy /64 must NOT be drained")
	}
	_ = platformv1.NodeDrainStatus{}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd central && go test ./internal/broker/ -run TestDrainStatus'`
Expected: FAIL — `DrainStatus` undefined.

- [ ] **Step 3: Implement DrainStatus**

Append to `central/internal/broker/report.go`:

```go
import (
	// (add to the existing import block)
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

// DrainStatus computes per-/64 drain confirmation for the fenced prefixes: a /64 is
// Drained unless it still hosts a stale VMI (busy[prefix]==true). The broker reports
// this upward after GC-reconciling the rebound CompiledVMs; central releases a fence
// only for Drained /64s.
func DrainStatus(fenced []string, busy map[string]bool) []platformv1.NodeDrainStatus {
	out := make([]platformv1.NodeDrainStatus, 0, len(fenced))
	for _, p := range fenced {
		out = append(out, platformv1.NodeDrainStatus{Prefix: p, Drained: !busy[p]})
	}
	return out
}
```

(Merge the `import` into the file's existing import block rather than adding a second one.)

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command bash -c 'cd central && go test ./internal/broker/'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add central/internal/broker/report.go central/internal/broker/drain_test.go
git commit -m "feat(broker): DrainStatus — per-/64 drain confirmation for fence release"
```

---

## Task 12: Multi-cluster failover integration test (multiple envtest)

An in-process cross-cluster failover test: central + two downstream clusters (envtest apiservers), a lost pool fenced with fake actuators, VMs re-bound to the healthy pool, then recovery drain → release. Follows the existing `central/test/phase4_e2e_test.go` multi-env pattern.

**Files:**
- Test: `central/test/tier2_failover_e2e_test.go` (create)

- [ ] **Step 1: Read the existing multi-env harness**

Run: `nix develop --command bash -c 'sed -n "1,90p" central/test/phase4_e2e_test.go'`
Note how it builds a `kitenvtest.NewEnvironment`, the scheme it installs (platform + net), and how it constructs `client.Client`s. Reuse these helpers/patterns.

- [ ] **Step 2: Write the failing integration test**

Create `central/test/tier2_failover_e2e_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	"github.com/trevex/ectobase/central/internal/clusterpool"
	"github.com/trevex/ectobase/central/internal/failover"
)

type confirmingPrefixFencer struct{}

func (confirmingPrefixFencer) Fence(context.Context, string) error   { return nil }
func (confirmingPrefixFencer) Release(context.Context, string) error { return nil }

func TestTier2_Failover_FenceRebindRelease(t *testing.T) {
	c, ctx := startNetEnv(t) // reuse the harness from net_envtest_test.go (central+net+platform scheme)

	staleLease := metav1.NewMicroTime(time.Now().Add(-10 * time.Minute))
	lost := &platformv1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{Name: "poolA"},
	}
	if err := c.Create(ctx, lost); err != nil {
		t.Fatal(err)
	}
	lost.Status = platformv1.ClusterPoolStatus{
		Phase:        clusterpool.PhaseUnknown,
		Lease:        &platformv1.ClusterPoolLease{RenewTime: &staleLease},
		NodePrefixes: []string{"2001:db8:0:1::/64"},
	}
	if err := c.Status().Update(ctx, lost); err != nil {
		t.Fatal(err)
	}
	healthy := &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "poolB"}}
	if err := c.Create(ctx, healthy); err != nil {
		t.Fatal(err)
	}
	healthy.Status = platformv1.ClusterPoolStatus{Phase: clusterpool.PhaseReady}
	if err := c.Status().Update(ctx, healthy); err != nil {
		t.Fatal(err)
	}
	vm := &netv1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: "vm1", Namespace: "default"}, Spec: netv1.VirtualMachineSpec{ClusterName: "poolA"}}
	if err := c.Create(ctx, vm); err != nil {
		t.Fatal(err)
	}

	r := &failover.Reconciler{Client: c, StorageFencer: confirmingPrefixFencer{}, NetworkFencer: confirmingPrefixFencer{}, FailoverThreshold: time.Minute}
	if _, err := r.Reconcile(ctx, req("poolA")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	got := &netv1.VirtualMachine{}
	if err := c.Get(ctx, client.ObjectKey{Name: "vm1", Namespace: "default"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.ClusterName != "poolB" {
		t.Fatalf("want re-bind to poolB, got %q", got.Spec.ClusterName)
	}

	// FencedPrefixes recorded.
	gp := &platformv1.ClusterPool{}
	_ = c.Get(ctx, client.ObjectKey{Name: "poolA"}, gp)
	if len(gp.Status.FencedPrefixes) != 1 {
		t.Fatalf("want 1 fenced prefix, got %v", gp.Status.FencedPrefixes)
	}

	// Recovery: broker reports the /64 drained -> next reconcile releases it.
	gp.Status.NodeDrain = []platformv1.NodeDrainStatus{{Prefix: "2001:db8:0:1::/64", Drained: true}}
	if err := c.Status().Update(ctx, gp); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req("poolA")); err != nil {
		t.Fatalf("reconcile recovery: %v", err)
	}
	_ = c.Get(ctx, client.ObjectKey{Name: "poolA"}, gp)
	if len(gp.Status.FencedPrefixes) != 0 {
		t.Fatalf("drained /64 fence must be released, still: %v", gp.Status.FencedPrefixes)
	}
}

func req(name string) reconcileRequest { return reconcileRequest{name} }
```

**Symbol-collision note:** the `central/test` package already contains `failover_test.go` (edited in Task 4). Do NOT define a `req` helper here if one already exists in that package — `grep -n 'func req(' central/test/*.go` first. Prefer inlining `ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}` (import `ctrl "sigs.k8s.io/controller-runtime"` + `"k8s.io/apimachinery/pkg/types"`) and delete the `req`/`reconcileRequest` shim entirely. Likewise adapt `startNetEnv`/scheme registration to the real harness signatures found in Step 1 and `net_envtest_test.go`.

- [ ] **Step 3: Run to verify it fails, then passes**

Run: `nix develop --command bash -c 'cd central && go test ./test/ -run TestTier2_Failover_FenceRebindRelease -v'`
Expected: initially FAIL if harness names need adapting; after adapting to the real `startNetEnv`/request types, PASS (VM re-bound to poolB; fence recorded then released on drain).

- [ ] **Step 4: Commit**

```bash
git add central/test/tier2_failover_e2e_test.go
git commit -m "test(central): Tier-2 fence->rebind->recovery-release envtest integration"
```

---

## Task 13: Wire real fencers into the controller + full-suite pass

Replace the controller's `DenyFencer` defaults with the real `StorageFencer`/`NetworkFencer` (constructed from flags), and run the full test suites.

**Files:**
- Modify: `central/cmd/controller/main.go`

- [ ] **Step 1: Construct and inject the real fencers**

In `central/cmd/controller/main.go`, add flags for the reflector admin address, the CSI driver, and the Ceph provisioner secret; dial the reflector; build the fencers; inject them. Add near the other flags:

```go
	reflectorAdmin := flag.String("reflector-admin", "", "reflector RouteBusAdmin gRPC address (network fence); empty => DenyFencer")
	csiDriver := flag.String("csi-driver", "rbd.csi.ceph.com", "CSI driver for NetworkFence")
	csiSecretName := flag.String("csi-secret-name", "rook-csi-rbd-provisioner", "NetworkFence provisioner secret name")
	csiSecretNS := flag.String("csi-secret-namespace", "rook-ceph", "NetworkFence provisioner secret namespace")
```

After the manager is built, construct the fencers (default to `DenyFencer` when unconfigured — fail-safe):

```go
	var storageF, networkF failover.PrefixFencer = failover.DenyFencer{}, failover.DenyFencer{}
	storageF = fence.NewStorageFencer(mgr.GetClient(), *csiDriver, client.ObjectKey{Name: *csiSecretName, Namespace: *csiSecretNS})
	if *reflectorAdmin != "" {
		conn, derr := grpc.NewClient(*reflectorAdmin, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if derr != nil {
			setupLog.Error(derr, "dial reflector admin")
			os.Exit(1)
		}
		networkF = fence.NewNetworkFencer(routebusv1.NewRouteBusAdminClient(conn))
	}
```

Then set `StorageFencer: storageF, NetworkFencer: networkF` in the `failover.Reconciler{...}` literal. Add imports: `"github.com/trevex/ectobase/central/internal/fence"`, `routebusv1 "github.com/trevex/ectobase/netplane/gen/routebusv1"`, `"google.golang.org/grpc"`, `"google.golang.org/grpc/credentials/insecure"`, `"sigs.k8s.io/controller-runtime/pkg/client"`. (Use the file's existing logger var name instead of `setupLog` if different.)

- [ ] **Step 2: Build + run all affected suites**

Run:
```bash
nix develop --command bash -c 'cd central && go build ./... && go test ./internal/... ./apis/... ./test/... && cd ../netplane && go test ./reflector/...'
```
Expected: build clean; all unit + envtest suites PASS.

- [ ] **Step 3: Commit**

```bash
git add central/cmd/controller/main.go central/go.mod central/go.sum
git commit -m "feat(central): wire real StorageFencer + NetworkFencer into the failover controller"
```

---

## Task 14: Broker wiring — stamp placement + drain in the sync loop

Call the Task 10–11 helpers from the broker's periodic sync so `NodePrefixes`/`Placement`/`NodeDrain` are actually written upward.

**Files:**
- Modify: `central/cmd/broker/main.go` (and/or `central/internal/broker/broker.go`)

- [ ] **Step 1: Read the broker sync loop**

Run: `nix develop --command bash -c 'sed -n "1,200p" central/cmd/broker/main.go; echo ---; sed -n "1,120p" central/internal/broker/broker.go'`
Identify the periodic tick where `SyncOnce`/`SyncCompiledVMs` run and where the ClusterPool lease heartbeat is written.

- [ ] **Step 2: Add a status-report step to the broker**

In `central/internal/broker/broker.go`, add a method that gathers node facts from the downstream cluster (list `corev1.Node`, derive each node's /64 from its addresses — reuse whatever the agent uses to learn a node's underlay /64; grep `underlay` in `netplane/agent`) and the VMI→node placements, then writes `ClusterPool.Status.NodePrefixes` + each VM's `Status.Placement` + `NodeDrain` (via `DrainStatus`, using `FencedPrefixes` and which /64s still host a stale VMI):

```go
// ReportStatus stamps this pool's fence coordinates + per-VM placement + drain status
// into central. Called each sync tick alongside the lease heartbeat.
func (b *Broker) ReportStatus(ctx context.Context, nodes []NodeFact, vmNode map[string]string) error {
	// 1) Pool NodePrefixes.
	var pool platformv1.ClusterPool
	if err := b.Central.Get(ctx, client.ObjectKey{Name: b.ClusterName}, &pool); err != nil {
		return err
	}
	pool.Status.NodePrefixes = NodePrefixesFromNodes(nodes)
	// Drain: a fenced /64 is busy if any VM still runs on a node in it.
	busy := map[string]bool{}
	nodePrefix := map[string]string{}
	for _, n := range nodes {
		nodePrefix[n.Name] = n.Prefix
	}
	for _, nodeName := range vmNode {
		if p := nodePrefix[nodeName]; p != "" {
			busy[p] = true
		}
	}
	pool.Status.NodeDrain = DrainStatus(pool.Status.FencedPrefixes, busy)
	if err := b.Central.Status().Update(ctx, &pool); err != nil {
		return err
	}
	// 2) Per-VM placement.
	for vmName, nodeName := range vmNode {
		var vm netv1.VirtualMachine
		if err := b.Central.Get(ctx, client.ObjectKey{Name: vmName, Namespace: "default"}, &vm); err != nil {
			continue
		}
		vm.Status.Placement = PlacementForVM(b.ClusterName, nodeName, nodes)
		_ = b.Central.Status().Update(ctx, &vm)
	}
	return nil
}
```

(Adapt the VM namespace/listing to how the broker already enumerates its VMs; the exact node→/64 derivation should reuse the agent's existing underlay logic — if none is exposed, read the node's `corev1.Node` annotation/address the CNI sets. Grep first; do not invent a new /64 source.)

- [ ] **Step 3: Call it from the sync tick**

In `central/cmd/broker/main.go`, in the periodic loop where `SyncOnce`/heartbeat run, gather `nodes []broker.NodeFact` + `vmNode map[string]string` (VMI name → node) from the downstream cluster and call `b.ReportStatus(ctx, nodes, vmNode)`, logging errors (best-effort, like the other sync steps).

- [ ] **Step 4: Build + vet**

Run: `nix develop --command bash -c 'cd central && go build ./... && go vet ./...'`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add central/cmd/broker/main.go central/internal/broker/broker.go
git commit -m "feat(broker): report NodePrefixes + VM Placement + NodeDrain upward each sync tick"
```

---

## Task 15: Explicit partition dual-writer scenario test

The spec's headline safety property (§8): a local Tier-1 reschedule onto a node that then gets pool-fenced must be cut off on **both** backends — its overlay route suppressed and its storage blocklisted — so no second live writer survives. This composes the RIB blocklist + the StorageFencer into one named test.

**Files:**
- Test: `central/internal/fence/partition_scenario_test.go` (create)

- [ ] **Step 1: Write the scenario test**

Create `central/internal/fence/partition_scenario_test.go`:

```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package fence

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/trevex/ectobase/netplane/reflector"
)

// A partitioned pool's node keeps a live route + holds the RBD; central fences the
// whole /64. Assert BOTH cuts land: the route is suppressed AND storage confirms fenced.
func TestPartition_WholePoolFence_CutsBothBackends(t *testing.T) {
	const prefix = "2001:db8:0:1::/64"

	// Network: the partitioned node re-announced a sticky route (local Tier-1). Fence it.
	rib := reflector.NewRIB()
	rib.Announce("stale-node", 100, "10.0.0.9/32", []string{"2001:db8:0:1::9"}, false)
	rib.SetFence(prefix)
	if rib.HasRoute(100, "10.0.0.9/32") {
		t.Fatalf("network fence must suppress the partitioned node's route")
	}
	// A further re-announce from the fenced /64 is rejected (no dual-IP).
	rib.Announce("stale-node", 100, "10.0.0.9/32", []string{"2001:db8:0:1::9"}, false)
	if rib.HasRoute(100, "10.0.0.9/32") {
		t.Fatalf("network fence must reject re-announces from the fenced /64")
	}

	// Storage: the NetworkFence CR reports Succeeded -> storage cut confirmed.
	nf := &unstructured.Unstructured{}
	nf.SetGroupVersionKind(schema.GroupVersionKind{Group: NetworkFenceGVR.Group, Version: NetworkFenceGVR.Version, Kind: "NetworkFence"})
	nf.SetName(fenceName(prefix))
	_ = unstructured.SetNestedField(nf.Object, "Succeeded", "status", "result")
	c := fake.NewClientBuilder().WithObjects(nf).Build()
	sf := NewStorageFencer(c, "rbd.csi.ceph.com", client.ObjectKey{Name: "s", Namespace: "ceph"})
	if err := sf.Fence(context.Background(), prefix); err != nil {
		t.Fatalf("storage fence must confirm active: %v", err)
	}
}
```

- [ ] **Step 2: Run to verify it passes**

Run: `nix develop --command bash -c 'cd central && go test ./internal/fence/ -run TestPartition_WholePoolFence_CutsBothBackends'`
Expected: PASS (both backends cut). This is the executable form of the spec's at-most-one-live-writer guarantee.

- [ ] **Step 3: Commit**

```bash
git add central/internal/fence/partition_scenario_test.go
git commit -m "test(fence): explicit partition dual-writer scenario (route suppressed + storage fenced)"
```

---

## Final verification (after all tasks)

- [ ] Full central + netplane suites: `nix develop --command bash -c 'cd central && go build ./... && go test ./... && cd ../netplane && go build ./... && go test ./reflector/...'` — all PASS.
- [ ] Confirm no dataplane (eBPF/Rust) changes: `git diff --name-only main...HEAD | grep -E '^flowplane/|\.rs$'` — expect **no output**.
- [ ] Re-read the spec §6 fail-safe invariants and confirm every `Reconcile` exit that skips a re-bind writes only status (grep `Spec.ClusterName =` in `failover.go` — it must appear only inside `rebindPoolVMs` after the fence barrier).
- [ ] Dispatch a final holistic review across `git diff main...HEAD`, then use `superpowers:finishing-a-development-branch`.

**Deferred manual gate (not automated here):** the spec §8 single-cluster kind lab (central + one broker + reflector + real csi-addons, fault-inject a stale lease → real NetworkFence + reflector fence → re-bind → recovery release) is a live integration gate requiring kind + csi-addons + KubeVirt. It is validated manually on a dev fabric, mirroring how Phase 5a's `hack/tier1-failover-e2e.sh` is best-effort/not-CI-wired. The in-process multi-envtest (Task 12) + the explicit partition scenario (Task 15) are the automated gates; the kind lab is a follow-up.
