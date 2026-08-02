# Phase 3 — Scheduler, Lease/Health, Tier-2 Failover Skeleton, ClusterRestriction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Central binds `VirtualMachine.spec.clusterName` to a healthy, capacity-fitting `ClusterPool` (scheduler), kept honest by a broker-heartbeated lease + capacity report, with a fence-gated Tier-2 failover state machine (injected actuators, fail-safe) and a thin ClusterRestriction admission bounding broker writes.

**Architecture:** New central controllers on the existing manager: a **scheduler** (pure `Schedule` + VM controller) writes `spec.clusterName`; the **broker** gains a heartbeat Runnable writing `ClusterPool.Status.Lease` + `Allocatable` (via an injected `CapacityReporter`); the **pool-health** reconciler turns lease freshness into `Ready`/`Unknown`; a **failover** controller re-binds VMs off lost pools through an injected `Fencer` (fail-safe); a **thin admission** plugin bounds `ectobase:cluster:<name>` identities. Capacity uses native `corev1.ResourceList`. Phase 1b's VM→CompiledNIC→broker chain propagates placement unchanged.

**Tech Stack:** Go 1.26.4 (workspace); `api` + `central` modules; apiserver-kit v0.3.4 (local `replace`); controller-runtime v0.24.1; `k8s.io/api/core/v1` (`corev1`); envtest (kit-aggregated + controller-runtime).

**Design doc:** `docs/superpowers/specs/2026-08-02-phase3-scheduler-failover-design.md`.

**Non-negotiable carry-overs:**
- Every central-aggregated informer runs with `KUBE_FEATURE_WatchListClient=false` — now also the scheduler/failover/pool-health controllers and the broker heartbeat.
- Declarative, no in-memory diff (the `appliedFw` lesson).
- envtest/codegen via the nix devShell (`nix develop --command bash -c '...'`); `KUBEBUILDER_ASSETS` provided there. Ignore stale go-1.26.0 LSP diagnostics (real toolchain is 1.26.4).
- Net-group types (`VirtualMachine`) use the Phase-1b pattern: shared versioned struct in `api/v1alpha1`, central internal mirror + **hand-written conversion** (`central/apis/net/v1alpha1/conversion.go`) + fuzzer, guarded by the roundtrip test. Platform-group types (`ClusterPool`) use the real conversion-gen (`update-codegen.sh`).
- `central/go.mod` keeps the local replaces (kit, api, netplane). openapi codegen already includes `--extra-pkgs "k8s.io/api/core/v1"`.

**Branch:** `feat/phase3-scheduler-failover` off main (already created this session; verify `git branch --show-current`).

---

## File structure

**Types (api + central):**
- Modify: `api/v1alpha1/virtualmachine_types.go` — `Spec.Resources` (corev1.ResourceRequirements), `Spec.PoolSelector`, `Status.Conditions`.
- Modify: `central/apis/net/virtualmachine_types.go` (internal mirror) + `central/apis/net/v1alpha1/conversion.go` (hand conversion).
- Modify: `central/apis/platform/clusterpool_types.go` + `.../v1alpha1/clusterpool_types.go` — `Status.Allocatable`, `Status.Lease` (+ `ClusterPoolLease` type) + phase constants.
- Regenerated: api deepcopy/CRDs; central codegen (deepcopy/conversion/openapi).

**Controllers/engines (central):**
- Create: `central/internal/scheduler/schedule.go` (pure) + `controller.go` + tests.
- Create: `central/internal/failover/failover.go` (Fencer seam + controller) + tests.
- Modify: `central/internal/clusterpool/controller.go` — pool-health from lease freshness (+ `health.go` pure helper).
- Create: `central/internal/broker/heartbeat.go` (`heartbeatOnce` + `CapacityReporter`) + test; Modify `central/cmd/broker/main.go` (wire the Runnable + real node-sum reporter).
- Modify: `central/cmd/controller/main.go` — register scheduler + failover.
- Create: `central/internal/clusterrestriction/admission.go` (pure `Review` + plugin) + test; Modify `central/cmd/apiserver/main.go` (wire the plugin).
- Create: `central/test/scheduler_test.go`, `central/test/failover_test.go`, `central/test/clusterrestriction_test.go`, `central/test/phase3_e2e_test.go`.

---

## Task 1: Types — ClusterPool lease/capacity + VirtualMachine resources/selector/conditions

**Files:** `api/v1alpha1/virtualmachine_types.go`; `central/apis/net/virtualmachine_types.go`; `central/apis/net/v1alpha1/conversion.go`; `central/apis/platform/clusterpool_types.go`; `central/apis/platform/v1alpha1/clusterpool_types.go`; regenerated codegen.

- [ ] **Step 1: Extend the shared VirtualMachine versioned type.** In `api/v1alpha1/virtualmachine_types.go`, add imports `corev1 "k8s.io/api/core/v1"` and (already present) `metav1`. Extend `VirtualMachineSpec` (after `InterfaceRefs`):

```go
	// Resources is the compute resource request/limit for this workload. Only
	// Requests is used for scheduling capacity fit; Limits is carried for parity.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// PoolSelector, if set, restricts scheduling to ClusterPools whose labels match.
	// +optional
	PoolSelector *metav1.LabelSelector `json:"poolSelector,omitempty"`
```

And extend `VirtualMachineStatus`:

```go
	// Conditions capture scheduling/failover observations (Scheduled, Unschedulable, FailoverBlocked).
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
```

- [ ] **Step 2: Mirror into the central internal net type.** In `central/apis/net/virtualmachine_types.go`, add the same three fields in internal style (no json tags), importing `corev1` + `metav1`:

```go
	Resources    corev1.ResourceRequirements
	PoolSelector *metav1.LabelSelector
```
(in `VirtualMachineSpec`) and in `VirtualMachineStatus`:
```go
	Conditions []metav1.Condition
```

- [ ] **Step 3: Extend the hand-written VM conversion.** In `central/apis/net/v1alpha1/conversion.go`, find `Convert_v1alpha1_VirtualMachineSpec_To_net_VirtualMachineSpec` and its reverse (and the Status pair). Add field copies both directions. Because `corev1.ResourceRequirements`, `*metav1.LabelSelector`, and `[]metav1.Condition` are shared apimachinery/corev1 types (same on both sides), copy via deepcopy to preserve pointer independence:

```go
	// spec (both directions):
	out.Resources = *in.Resources.DeepCopy()
	if in.PoolSelector != nil { out.PoolSelector = in.PoolSelector.DeepCopy() } else { out.PoolSelector = nil }
	// status (both directions):
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		copy(out.Conditions, in.Conditions)
	} else { out.Conditions = nil }
```
Add `corev1 "k8s.io/api/core/v1"` / `metav1` imports to conversion.go if missing.

- [ ] **Step 4: Extend ClusterPool status (platform group, both internal + versioned).** In `central/apis/platform/v1alpha1/clusterpool_types.go`, add `corev1 "k8s.io/api/core/v1"` import and a lease type + status fields:

```go
// ClusterPoolLease is the broker's heartbeat on a ClusterPool: the identity
// holding it and when it was last renewed. Stale RenewTime => the pool is Unknown.
type ClusterPoolLease struct {
	// HolderIdentity is the broker instance currently reporting for this pool.
	// +optional
	HolderIdentity string `json:"holderIdentity,omitempty" protobuf:"bytes,1,opt,name=holderIdentity"`
	// RenewTime is when the holder last renewed the lease.
	// +optional
	RenewTime *metav1.MicroTime `json:"renewTime,omitempty" protobuf:"bytes,2,opt,name=renewTime"`
}
```
Extend `ClusterPoolStatus` (after `Conditions`):
```go
	// Allocatable is the schedulable capacity the broker reports for this pool.
	// +optional
	Allocatable corev1.ResourceList `json:"allocatable,omitempty" protobuf:"bytes,3,rep,name=allocatable,casttype=k8s.io/api/core/v1.ResourceList,castkey=k8s.io/api/core/v1.ResourceName"`
	// Lease is the broker heartbeat; a stale RenewTime drives Phase to Unknown.
	// +optional
	Lease *ClusterPoolLease `json:"lease,omitempty" protobuf:"bytes,4,opt,name=lease"`
```

- [ ] **Step 5: Mirror into the internal platform type.** In `central/apis/platform/clusterpool_types.go`, add `corev1` import, the `ClusterPoolLease` struct (internal style, no tags), and the two `ClusterPoolStatus` fields (`Allocatable corev1.ResourceList`, `Lease *ClusterPoolLease`).

- [ ] **Step 6: Regenerate all codegen.**

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp && make generate && cd central && bash hack/update-codegen.sh' 2>&1 | tail -25`
Expected: api deepcopy + CRDs regenerate (VirtualMachine CRD gains `spec.resources`, `spec.poolSelector`, `status.conditions`); central deepcopy/conversion/openapi regenerate; platform conversion-gen emits `ClusterPool` `Allocatable`/`Lease` conversions; no error. If platform conversion-gen errors on `corev1.ResourceList`, ensure `corev1` is a recognized peer (it is via the openapi extra-pkgs + the k8s scheme) — the generated conversion should be a direct `out.Allocatable = in.Allocatable`.

- [ ] **Step 7: Build + roundtrip fuzz + api tests.**

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/api && go build ./... && cd ../central && go build ./... && go test ./apis/... -run "RoundTrip|Roundtrip" 2>&1 | tail -15'`
Expected: build clean; net + platform roundtrip fuzz PASS (proves the hand VM conversion + platform gen conversion are lossless with the new fields).

- [ ] **Step 8: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add api/v1alpha1 config/crd deploy/charts central/apis central/client-go
git commit -m "feat(api,central): ClusterPool lease+allocatable, VirtualMachine resources+poolSelector+conditions

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Broker heartbeat + CapacityReporter (TDD)

**Files:** `central/internal/broker/heartbeat.go`, `central/internal/broker/heartbeat_test.go`, `central/cmd/broker/main.go`.

- [ ] **Step 1: Write the failing unit test.** `central/internal/broker/heartbeat_test.go`: a fake central client holding a `ClusterPool`; `heartbeatOnce` sets `Status.Lease.RenewTime` (non-nil), `HolderIdentity`, and `Status.Allocatable` from a static `CapacityReporter`.

```go
package broker

import (
	"context"; "testing"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	platforminstall "github.com/trevex/ectobase/central/apis/platform/install"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

type staticReporter struct{ rl corev1.ResourceList }
func (s staticReporter) Report(context.Context) (corev1.ResourceList, error) { return s.rl, nil }

func TestHeartbeatOnce(t *testing.T) {
	s := runtime.NewScheme()
	if err := platforminstall.AddToScheme(s); err != nil { t.Fatal(err) }
	pool := &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c1"}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pool).WithStatusSubresource(pool).Build()

	rl := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("8")}
	h := &Heartbeater{Central: c, PoolName: "c1", HolderIdentity: "broker-1", Reporter: staticReporter{rl}}
	if err := h.heartbeatOnce(context.Background()); err != nil { t.Fatal(err) }

	got := &platformv1.ClusterPool{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "c1"}, got); err != nil { t.Fatal(err) }
	if got.Status.Lease == nil || got.Status.Lease.RenewTime == nil { t.Fatalf("lease not set: %+v", got.Status) }
	if got.Status.Lease.HolderIdentity != "broker-1" { t.Fatalf("holder: %q", got.Status.Lease.HolderIdentity) }
	if got.Status.Allocatable.Cpu().Cmp(resource.MustParse("8")) != 0 { t.Fatalf("cpu: %v", got.Status.Allocatable.Cpu()) }
}
```
(Add the `client` import.) Run → FAIL (no `Heartbeater`/`CapacityReporter`).

- [ ] **Step 2: Implement `heartbeat.go`.**

```go
package broker

import (
	"context"; "fmt"; "time"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

// CapacityReporter yields the schedulable capacity to advertise for this cluster.
type CapacityReporter interface{ Report(ctx context.Context) (corev1.ResourceList, error) }

// Heartbeater renews the broker's ClusterPool lease + reports capacity upward.
type Heartbeater struct {
	Central        client.Client
	PoolName       string
	HolderIdentity string
	Reporter       CapacityReporter
	Interval       time.Duration
}

// heartbeatOnce renews the lease RenewTime + Allocatable on the broker's own ClusterPool.
func (h *Heartbeater) heartbeatOnce(ctx context.Context) error {
	pool := &platformv1.ClusterPool{}
	if err := h.Central.Get(ctx, client.ObjectKey{Name: h.PoolName}, pool); err != nil {
		return fmt.Errorf("get clusterpool %s: %w", h.PoolName, err)
	}
	rl, err := h.Reporter.Report(ctx)
	if err != nil { return fmt.Errorf("report capacity: %w", err) }
	now := metav1.NewMicroTime(time.Now())
	pool.Status.Lease = &platformv1.ClusterPoolLease{HolderIdentity: h.HolderIdentity, RenewTime: &now}
	pool.Status.Allocatable = rl
	if err := h.Central.Status().Update(ctx, pool); err != nil {
		return fmt.Errorf("update clusterpool status: %w", err)
	}
	return nil
}

// Start runs heartbeatOnce every Interval until ctx is done (controller-runtime manager.Runnable).
func (h *Heartbeater) Start(ctx context.Context) error {
	t := time.NewTicker(h.Interval)
	defer t.Stop()
	_ = h.heartbeatOnce(ctx) // best-effort immediate beat; errors are retried next tick
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := h.heartbeatOnce(ctx); err != nil {
				// log-and-continue: a transient central outage must not kill the broker
				ctrllog.FromContext(ctx).Error(err, "heartbeat")
			}
		}
	}
}
```
Add `ctrllog "sigs.k8s.io/controller-runtime/pkg/log"`. NOTE: `metav1.NewMicroTime(time.Now())` uses the wall clock — this is the ONLY place time is read; acceptable in production code (not a workflow script). Run the unit test → PASS.

- [ ] **Step 3: Real node-sum CapacityReporter + wire the Runnable.** In `central/cmd/broker/main.go`: add a `nodeCapacityReporter{downstream client.Client}` whose `Report` lists downstream `corev1.Node`s and sums `Status.Allocatable` over `Ready` nodes (a node is Ready if it has a `NodeReady` condition == True). Register it: `mgr.Add(&broker.Heartbeater{Central: mgr.GetClient(), PoolName: clusterName, HolderIdentity: <hostname-or-clusterName>, Reporter: r, Interval: 10*time.Second})`. The downstream scheme must include `corev1` (add `corev1.AddToScheme(scheme)` for the downstream client if it isn't there). Keep `KUBE_FEATURE_WatchListClient=false`.

- [ ] **Step 4: Build + test.**

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go build ./... && go test ./internal/broker/... 2>&1 | tail'`
Expected: build clean; broker unit tests (heartbeat + existing sync) PASS.

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/internal/broker central/cmd/broker
git commit -m "feat(central): broker heartbeats ClusterPool lease + capacity (CapacityReporter)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Pool-health from lease freshness (TDD)

**Files:** `central/internal/clusterpool/health.go`, `central/internal/clusterpool/health_test.go`, `central/internal/clusterpool/controller.go`.

- [ ] **Step 1: Write the failing unit test** for a pure `phaseFromLease`. `central/internal/clusterpool/health_test.go`:

```go
package clusterpool

import (
	"testing"; "time"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

func TestPhaseFromLease(t *testing.T) {
	now := time.Unix(1000, 0)
	stale := 30 * time.Second
	mt := func(sec int64) *metav1.MicroTime { m := metav1.NewMicroTime(time.Unix(sec, 0)); return &m }
	cases := []struct{ name string; lease *platformv1.ClusterPoolLease; want string }{
		{"never", nil, PhasePending},
		{"fresh", &platformv1.ClusterPoolLease{RenewTime: mt(990)}, PhaseReady},   // 10s old < 30s
		{"stale", &platformv1.ClusterPoolLease{RenewTime: mt(900)}, PhaseUnknown}, // 100s old > 30s
		{"nil-renew", &platformv1.ClusterPoolLease{}, PhasePending},
	}
	for _, tc := range cases {
		if got := phaseFromLease(now, tc.lease, stale); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}
```
Run → FAIL (no `phaseFromLease`/`PhaseReady`/`PhaseUnknown`).

- [ ] **Step 2: Implement `health.go`.**

```go
package clusterpool

import (
	"time"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

const (
	PhaseReady   = "Ready"
	PhaseUnknown = "Unknown"
)

// phaseFromLease derives the pool phase from lease freshness: no lease/renew =>
// Pending (never reported); renewed within healthStale => Ready; older => Unknown.
func phaseFromLease(now time.Time, lease *platformv1.ClusterPoolLease, healthStale time.Duration) string {
	if lease == nil || lease.RenewTime == nil {
		return PhasePending
	}
	if now.Sub(lease.RenewTime.Time) <= healthStale {
		return PhaseReady
	}
	return PhaseUnknown
}
```
(`PhasePending` already exists in controller.go.) Run → PASS.

- [ ] **Step 3: Wire into the reconciler.** Replace `controller.go`'s Reconcile body: compute `phase := phaseFromLease(time.Now(), pool.Status.Lease, r.HealthStale)`; if it differs from `pool.Status.Phase`, set it + set a `Ready` condition (`metav1.Condition{Type:"Ready", Status: ConditionTrue if Ready else False, Reason: "LeaseFresh"/"LeaseExpired"/"NoLease", ObservedGeneration: pool.Generation}` via `meta.SetStatusCondition`), `Status().Update`. Add fields `HealthStale time.Duration` to `Reconciler`. In `SetupWithManager`, keep `For(&ClusterPool{})` and return `RequeueAfter: r.HealthStale` from Reconcile so staleness is detected without an event. Imports: `time`, `k8s.io/apimachinery/pkg/api/meta`, `metav1`.

```go
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pool v1alpha1.ClusterPool
	if err := r.Client.Get(ctx, req.NamespacedName, &pool); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	phase := phaseFromLease(time.Now(), pool.Status.Lease, r.HealthStale)
	cond := metav1.Condition{Type: "Ready", ObservedGeneration: pool.Generation}
	switch phase {
	case PhaseReady:
		cond.Status, cond.Reason = metav1.ConditionTrue, "LeaseFresh"
	case PhaseUnknown:
		cond.Status, cond.Reason = metav1.ConditionFalse, "LeaseExpired"
	default:
		cond.Status, cond.Reason = metav1.ConditionFalse, "NoLease"
	}
	changed := pool.Status.Phase != phase
	if changed { pool.Status.Phase = phase }
	if meta.SetStatusCondition(&pool.Status.Conditions, cond) { changed = true }
	if changed {
		if err := r.Client.Status().Update(ctx, &pool); err != nil {
			return ctrl.Result{}, fmt.Errorf("update clusterpool status: %w", err)
		}
	}
	return ctrl.Result{RequeueAfter: r.HealthStale}, nil
}
```
Update `central/cmd/controller/main.go` to set `HealthStale` (e.g. `30 * time.Second`) on the Reconciler.

- [ ] **Step 4: Build + test.**

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go build ./... && go test ./internal/clusterpool/... 2>&1 | tail'`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/internal/clusterpool central/cmd/controller
git commit -m "feat(central): pool-health derives ClusterPool phase from lease freshness

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Scheduler — pure Schedule + VM controller (TDD)

**Files:** `central/internal/scheduler/schedule.go`, `central/internal/scheduler/schedule_test.go`, `central/internal/scheduler/controller.go`, `central/cmd/controller/main.go`.

- [ ] **Step 1: Write the failing unit test** for the pure `Schedule`. `central/internal/scheduler/schedule_test.go`:

```go
package scheduler

import (
	"testing"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	"github.com/trevex/ectobase/central/internal/clusterpool"
)

func pool(name string, phase string, cpu string, labels map[string]string) platformv1.ClusterPool {
	return platformv1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Status: platformv1.ClusterPoolStatus{Phase: phase, Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(cpu)}},
	}
}
func vmReq(cpu string) *netv1.VirtualMachine {
	return &netv1.VirtualMachine{Spec: netv1.VirtualMachineSpec{Resources: corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(cpu)}}}}
}

func TestSchedule(t *testing.T) {
	ready := clusterpool.PhaseReady
	pools := []platformv1.ClusterPool{pool("a", ready, "4", nil), pool("b", ready, "8", nil), pool("c", "Unknown", "16", nil)}

	// fits both a,b; b has more free -> b wins (spread by most-free).
	got, _, ok := Schedule(vmReq("2"), pools, map[string]corev1.ResourceList{})
	if !ok || got != "b" { t.Fatalf("want b, got %q ok=%v", got, ok) }

	// b already loaded to 7/8 -> a (free 4) beats b (free 1).
	got, _, ok = Schedule(vmReq("2"), pools, map[string]corev1.ResourceList{"b": {corev1.ResourceCPU: resource.MustParse("7")}})
	if !ok || got != "a" { t.Fatalf("want a, got %q", got) }

	// request exceeds all Ready capacity -> unschedulable.
	if _, _, ok := Schedule(vmReq("100"), pools, nil); ok { t.Fatalf("want unschedulable") }

	// gpu request but no pool advertises gpu -> unschedulable.
	gpu := &netv1.VirtualMachine{Spec: netv1.VirtualMachineSpec{Resources: corev1.ResourceRequirements{
		Requests: corev1.ResourceList{"nvidia.com/gpu": resource.MustParse("1")}}}}
	if _, _, ok := Schedule(gpu, pools, nil); ok { t.Fatalf("want unschedulable (no gpu)") }

	// Unknown pool c never chosen even though it has the most CPU.
	got, _, _ = Schedule(vmReq("2"), pools, nil)
	if got == "c" { t.Fatalf("must not pick Unknown pool") }

	// PoolSelector filters to labeled pools.
	labeled := []platformv1.ClusterPool{pool("a", ready, "4", map[string]string{"tier":"gold"}), pool("b", ready, "8", nil)}
	sel := vmReq("1"); sel.Spec.PoolSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tier":"gold"}}
	got, _, ok = Schedule(sel, labeled, nil)
	if !ok || got != "a" { t.Fatalf("selector: want a, got %q", got) }
}
```
Run → FAIL (no `Schedule`).

- [ ] **Step 2: Implement `schedule.go`.**

```go
package scheduler

import (
	"fmt"; "sort"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	"github.com/trevex/ectobase/central/internal/clusterpool"
)

// Schedule picks a ClusterPool for vm: Ready + PoolSelector match + resource fit
// (allocated[r]+request[r] <= Allocatable[r] for every requested r). Among fitting
// pools it returns the one with the highest minimum free fraction across the
// requested resources (spread), tie-broken by lowest name. ok=false + reason if none.
func Schedule(vm *netv1.VirtualMachine, pools []platformv1.ClusterPool, allocated map[string]corev1.ResourceList) (string, string, bool) {
	req := vm.Spec.Resources.Requests
	var sel labels.Selector
	if vm.Spec.PoolSelector != nil {
		s, err := metav1.LabelSelectorAsSelector(vm.Spec.PoolSelector)
		if err != nil { return "", fmt.Sprintf("invalid poolSelector: %v", err), false }
		sel = s
	}
	type cand struct{ name string; score float64 }
	var cands []cand
	for i := range pools {
		p := &pools[i]
		if p.Status.Phase != clusterpool.PhaseReady { continue }
		if sel != nil && !sel.Matches(labels.Set(p.Labels)) { continue }
		score, ok := fitScore(req, p.Status.Allocatable, allocated[p.Name])
		if !ok { continue }
		cands = append(cands, cand{p.Name, score})
	}
	if len(cands) == 0 { return "", "no Ready pool fits the request", false }
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score { return cands[i].score > cands[j].score }
		return cands[i].name < cands[j].name
	})
	return cands[0].name, "", true
}

// fitScore returns (minFreeFraction, fits). A requested resource the pool doesn't
// advertise => does not fit. A VM with no requests fits any pool and scores 1.
func fitScore(req, allocatable, used corev1.ResourceList) (float64, bool) {
	minFree := 1.0
	for name, q := range req {
		cap, ok := allocatable[name]
		if !ok { return 0, false }
		u := used[name] // zero value if absent
		need := u.DeepCopy(); need.Add(q)
		if need.Cmp(cap) > 0 { return 0, false }
		capv, needv := cap.AsApproximateFloat64(), need.AsApproximateFloat64()
		free := 1.0
		if capv > 0 { free = (capv - needv) / capv }
		if free < minFree { minFree = free }
	}
	return minFree, true
}
```
Imports for `schedule.go`: `fmt`, `sort`, `corev1`, `labels "k8s.io/apimachinery/pkg/labels"`, `metav1`, `netv1`, `platformv1`, `clusterpool`. NOTE: `resource` is NOT imported in `schedule.go` — `.Add/.Cmp/.DeepCopy/.AsApproximateFloat64` are methods on the `resource.Quantity` values ranged out of the `corev1.ResourceList` maps, needing no explicit package reference (the test file imports `resource` for `MustParse`). Drop the `metav1`/`netv1` imports if a final vet shows them unused. Run → PASS.

- [ ] **Step 3: Write the controller** `central/internal/scheduler/controller.go`. Watches `VirtualMachine`; on an unbound VM computes `allocated` (list VMs bound to each pool, sum Requests), runs `Schedule`, writes `spec.clusterName` or an `Unschedulable` condition.

```go
package scheduler

import (
	"context"; "fmt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

// Reconciler binds unbound VirtualMachines to a ClusterPool.
type Reconciler struct{ Client client.Client }

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vm netv1.VirtualMachine
	if err := r.Client.Get(ctx, req.NamespacedName, &vm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if vm.Spec.ClusterName != "" { return ctrl.Result{}, nil } // already bound
	var pools platformv1.ClusterPoolList
	if err := r.Client.List(ctx, &pools); err != nil { return ctrl.Result{}, fmt.Errorf("list pools: %w", err) }
	allocated, err := r.allocatedByPool(ctx)
	if err != nil { return ctrl.Result{}, err }
	pool, reason, ok := Schedule(&vm, pools.Items, allocated)
	if !ok {
		meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "Scheduled", Status: metav1.ConditionFalse, Reason: "Unschedulable", Message: reason, ObservedGeneration: vm.Generation})
		if err := r.Client.Status().Update(ctx, &vm); err != nil { return ctrl.Result{}, err }
		return ctrl.Result{}, nil // re-triggered when a pool changes
	}
	vm.Spec.ClusterName = pool
	if err := r.Client.Update(ctx, &vm); err != nil { return ctrl.Result{}, fmt.Errorf("bind vm: %w", err) }
	meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "Scheduled", Status: metav1.ConditionTrue, Reason: "Bound", Message: "bound to "+pool, ObservedGeneration: vm.Generation})
	if err := r.Client.Status().Update(ctx, &vm); err != nil { return ctrl.Result{}, err }
	return ctrl.Result{}, nil
}

// allocatedByPool sums the resource Requests of every bound VM, grouped by its pool.
func (r *Reconciler) allocatedByPool(ctx context.Context) (map[string]corev1.ResourceList, error) {
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms); err != nil { return nil, fmt.Errorf("list vms: %w", err) }
	out := map[string]corev1.ResourceList{}
	for i := range vms.Items {
		v := &vms.Items[i]
		if v.Spec.ClusterName == "" { continue }
		cur := out[v.Spec.ClusterName]
		if cur == nil { cur = corev1.ResourceList{} }
		for name, q := range v.Spec.Resources.Requests {
			c := cur[name]; c.Add(q); cur[name] = c
		}
		out[v.Spec.ClusterName] = cur
	}
	return out, nil
}

// SetupWithManager watches VirtualMachines and re-enqueues all unbound VMs when any ClusterPool changes.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.VirtualMachine{}).
		Watches(&platformv1.ClusterPool{}, handler.EnqueueRequestsFromMapFunc(r.unboundVMs)).
		Complete(r)
}

func (r *Reconciler) unboundVMs(ctx context.Context, _ client.Object) []ctrl.Request {
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms); err != nil { return nil }
	var reqs []ctrl.Request
	for i := range vms.Items {
		if vms.Items[i].Spec.ClusterName == "" {
			reqs = append(reqs, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&vms.Items[i])})
		}
	}
	return reqs
}
```

- [ ] **Step 4: Register the scheduler** in `central/cmd/controller/main.go`: `if err := (&scheduler.Reconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil { log.Fatal(...) }`. Confirm the manager scheme installs BOTH platform + net (the controller reads both) — add `netinstall.Install(scheme)` if the controller main only installed platform. Ensure `KUBE_FEATURE_WatchListClient=false` is set at the top of the controller main (add it if absent — the scheduler informer needs it).

- [ ] **Step 5: Build + test.**

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go build ./... && go test ./internal/scheduler/... 2>&1 | tail'`
Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/internal/scheduler central/cmd/controller
git commit -m "feat(central): scheduler binds VirtualMachine.spec.clusterName (Ready+fit+spread)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Tier-2 failover skeleton — Fencer seam + controller (TDD)

**Files:** `central/internal/failover/failover.go`, `central/internal/failover/failover_test.go`, `central/cmd/controller/main.go`.

- [ ] **Step 1: Write the failing unit test** with fake clients + injected Fencers. `central/internal/failover/failover_test.go`:

```go
package failover

import (
	"context"; "errors"; "testing"; "time"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platforminstall "github.com/trevex/ectobase/central/apis/platform/install"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	netinstall "github.com/trevex/ectobase/central/apis/net/install"
)

type fakeFencer struct{ err error }
func (f fakeFencer) FenceStorage(context.Context, *netv1.VirtualMachine) error { return f.err }
func (f fakeFencer) FenceNetwork(context.Context, *netv1.VirtualMachine) error { return f.err }

func scheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := platforminstall.AddToScheme(s); err != nil { t.Fatal(err) }
	if err := netinstall.AddToScheme(s); err != nil { t.Fatal(err) }
	return s
}

func lostPool(name string) *platformv1.ClusterPool { // Unknown, well past threshold
	old := metav1.NewMicroTime(time.Now().Add(-1 * time.Hour))
	return &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: platformv1.ClusterPoolStatus{Phase: "Unknown", Lease: &platformv1.ClusterPoolLease{RenewTime: &old}}}
}

func TestFailover_ConfirmedRebind(t *testing.T) {
	s := scheme(t)
	lost, healthy := lostPool("c1"), &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name:"c2"}, Status: platformv1.ClusterPoolStatus{Phase:"Ready"}}
	vm := &netv1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace:"default", Name:"vm1"}, Spec: netv1.VirtualMachineSpec{ClusterName:"c1"}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(lost, healthy, vm).WithStatusSubresource(vm, lost, healthy).Build()

	r := &Reconciler{Client: c, Fencer: fakeFencer{nil}, FailoverThreshold: time.Minute}
	if _, err := r.Reconcile(context.Background(), reqFor("c1")); err != nil { t.Fatal(err) }

	got := &netv1.VirtualMachine{}
	c.Get(context.Background(), client.ObjectKey{Namespace:"default", Name:"vm1"}, got)
	if got.Spec.ClusterName != "c2" { t.Fatalf("want rebound to c2, got %q", got.Spec.ClusterName) }
}

func TestFailover_FenceDenied_StaysAndBlocks(t *testing.T) {
	s := scheme(t)
	lost := lostPool("c1")
	vm := &netv1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace:"default", Name:"vm1"}, Spec: netv1.VirtualMachineSpec{ClusterName:"c1"}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(lost, vm).WithStatusSubresource(vm, lost).Build()

	r := &Reconciler{Client: c, Fencer: fakeFencer{errors.New("no ceph")}, FailoverThreshold: time.Minute}
	if _, err := r.Reconcile(context.Background(), reqFor("c1")); err != nil { t.Fatal(err) }

	got := &netv1.VirtualMachine{}
	c.Get(context.Background(), client.ObjectKey{Namespace:"default", Name:"vm1"}, got)
	if got.Spec.ClusterName != "c1" { t.Fatalf("must NOT rebind when fence unconfirmed, got %q", got.Spec.ClusterName) }
	// FailoverBlocked condition set
	blocked := false
	for _, cond := range got.Status.Conditions { if cond.Type == "FailoverBlocked" && cond.Status == metav1.ConditionTrue { blocked = true } }
	if !blocked { t.Fatalf("want FailoverBlocked condition") }
}
```
Add a `reqFor(name)` helper returning `ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}`. Run → FAIL.

- [ ] **Step 2: Implement `failover.go`.**

```go
package failover

import (
	"context"; "fmt"; "time"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	"github.com/trevex/ectobase/central/internal/clusterpool"
	"github.com/trevex/ectobase/central/internal/scheduler"
)

// Fencer externally excludes a lost instance from storage + network so a VM can
// be safely restarted elsewhere. Phase 3 ships DenyFencer (fail-safe) + tests;
// real Ceph/overlay actuators are Phase 4+.
type Fencer interface {
	FenceStorage(ctx context.Context, vm *netv1.VirtualMachine) error
	FenceNetwork(ctx context.Context, vm *netv1.VirtualMachine) error
}

// DenyFencer refuses to confirm any fence; wiring it means Tier-2 always fails safe.
type DenyFencer struct{}
func (DenyFencer) FenceStorage(context.Context, *netv1.VirtualMachine) error { return fmt.Errorf("no storage fence actuator configured") }
func (DenyFencer) FenceNetwork(context.Context, *netv1.VirtualMachine) error { return fmt.Errorf("no network fence actuator configured") }

// Reconciler runs Tier-2 fence-gated failover for VMs bound to a lost pool.
type Reconciler struct {
	Client            client.Client
	Fencer            Fencer
	FailoverThreshold time.Duration
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pool platformv1.ClusterPool
	if err := r.Client.Get(ctx, req.NamespacedName, &pool); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !poolLost(&pool, time.Now(), r.FailoverThreshold) {
		return ctrl.Result{RequeueAfter: r.FailoverThreshold}, nil
	}
	// VMs bound to this lost pool.
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms); err != nil { return ctrl.Result{}, fmt.Errorf("list vms: %w", err) }
	var pools platformv1.ClusterPoolList
	if err := r.Client.List(ctx, &pools); err != nil { return ctrl.Result{}, fmt.Errorf("list pools: %w", err) }
	for i := range vms.Items {
		vm := &vms.Items[i]
		if vm.Spec.ClusterName != pool.Name { continue }
		if err := r.failoverVM(ctx, vm, pool.Name, pools.Items); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: r.FailoverThreshold}, nil
}

func (r *Reconciler) failoverVM(ctx context.Context, vm *netv1.VirtualMachine, lostPool string, pools []platformv1.ClusterPool) error {
	// Fence-gate: BOTH must confirm or we fail safe.
	if err := r.Fencer.FenceStorage(ctx, vm); err != nil { return r.block(ctx, vm, "storage fence unconfirmed: "+err.Error()) }
	if err := r.Fencer.FenceNetwork(ctx, vm); err != nil { return r.block(ctx, vm, "network fence unconfirmed: "+err.Error()) }
	// Both fences confirmed -> re-bind to another Ready pool (excluding the lost one).
	var candidates []platformv1.ClusterPool
	for _, p := range pools { if p.Name != lostPool { candidates = append(candidates, p) } }
	newPool, reason, ok := scheduler.Schedule(vm, candidates, nil)
	if !ok { return r.block(ctx, vm, "no pool to fail over to: "+reason) }
	vm.Spec.ClusterName = newPool
	if err := r.Client.Update(ctx, vm); err != nil { return fmt.Errorf("rebind vm: %w", err) }
	meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "FailoverBlocked", Status: metav1.ConditionFalse, Reason: "FailedOver", Message: "failed over to "+newPool, ObservedGeneration: vm.Generation})
	meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "Scheduled", Status: metav1.ConditionTrue, Reason: "FailedOver", Message: "bound to "+newPool, ObservedGeneration: vm.Generation})
	return r.Client.Status().Update(ctx, vm)
}

func (r *Reconciler) block(ctx context.Context, vm *netv1.VirtualMachine, msg string) error {
	meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "FailoverBlocked", Status: metav1.ConditionTrue, Reason: "FenceUnconfirmed", Message: msg, ObservedGeneration: vm.Generation})
	return r.Client.Status().Update(ctx, vm)
}

// poolLost reports whether pool is Unknown and its lease has been stale longer than threshold.
func poolLost(pool *platformv1.ClusterPool, now time.Time, threshold time.Duration) bool {
	if pool.Status.Phase != clusterpool.PhaseUnknown { return false }
	if pool.Status.Lease == nil || pool.Status.Lease.RenewTime == nil { return true }
	return now.Sub(pool.Status.Lease.RenewTime.Time) > threshold
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&platformv1.ClusterPool{}).Complete(r)
}
```
Run → PASS.

- [ ] **Step 3: Register failover** in `central/cmd/controller/main.go`: `(&failover.Reconciler{Client: mgr.GetClient(), Fencer: failover.DenyFencer{}, FailoverThreshold: 2*time.Minute}).SetupWithManager(mgr)`. (Deny by default — real actuators are Phase 4; the threshold is deliberately > pool-health's HealthStale.)

- [ ] **Step 4: Build + test.**

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go build ./... && go test ./internal/failover/... 2>&1 | tail'`
Expected: PASS (confirmed→rebind, denied→FailoverBlocked+stay).

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/internal/failover central/cmd/controller
git commit -m "feat(central): Tier-2 failover skeleton (Fencer seam, fail-safe rebind)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: ClusterRestriction thin admission — spike + pure Review + wire (TDD)

**Files:** `central/internal/clusterrestriction/admission.go`, `.../admission_test.go`, `central/cmd/apiserver/main.go`.

- [ ] **Step 1: Write the failing unit test** for the pure `Review` decision. `central/internal/clusterrestriction/admission_test.go`:

```go
package clusterrestriction

import (
	"testing"
	authuser "k8s.io/apiserver/pkg/authentication/user"
)

func TestReview(t *testing.T) {
	brokerC1 := &authuser.DefaultInfo{Name: "ectobase:cluster:c1"}
	admin := &authuser.DefaultInfo{Name: "admin"}
	cases := []struct{ name string; user authuser.Info; in Attr; wantAllow bool }{
		{"broker writes own pool status", brokerC1, Attr{Resource:"clusterpools", Name:"c1", Subresource:"status"}, true},
		{"broker writes other pool status", brokerC1, Attr{Resource:"clusterpools", Name:"c2", Subresource:"status"}, false},
		{"broker writes own pool spec", brokerC1, Attr{Resource:"clusterpools", Name:"c1", Subresource:""}, false},
		{"broker sets clusterName", brokerC1, Attr{Resource:"virtualmachines", Name:"vm1", SetsClusterName:true}, false},
		{"broker writes vm w/o clusterName change", brokerC1, Attr{Resource:"virtualmachines", Name:"vm1"}, true},
		{"admin unrestricted", admin, Attr{Resource:"clusterpools", Name:"c2", Subresource:""}, true},
		{"admin sets clusterName", admin, Attr{Resource:"virtualmachines", SetsClusterName:true}, true},
	}
	for _, tc := range cases {
		allow, _ := Review(tc.user, tc.in)
		if allow != tc.wantAllow { t.Errorf("%s: got allow=%v want %v", tc.name, allow, tc.wantAllow) }
	}
}
```
Run → FAIL.

- [ ] **Step 2: Implement the pure decision `admission.go`.**

```go
package clusterrestriction

import (
	"fmt"; "strings"
	authuser "k8s.io/apiserver/pkg/authentication/user"
)

// brokerPrefix is the username convention identifying a per-cluster broker.
const brokerPrefix = "ectobase:cluster:"

// Attr is the minimal admission context Review needs (decoupled from the k8s
// admission.Attributes type so the decision is pure + unit-testable).
type Attr struct {
	Resource        string // plural, e.g. "clusterpools", "virtualmachines"
	Name            string
	Subresource     string // "status" for status writes
	SetsClusterName bool   // the write creates/changes spec.clusterName
}

// clusterOf returns the cluster a broker identity is scoped to, and whether the
// user is a broker at all.
func clusterOf(u authuser.Info) (string, bool) {
	if u == nil { return "", false }
	if strings.HasPrefix(u.GetName(), brokerPrefix) {
		return strings.TrimPrefix(u.GetName(), brokerPrefix), true
	}
	return "", false
}

// Review is the thin ClusterRestriction: a broker identity ectobase:cluster:<name>
// may write ONLY its own ClusterPool's status, and may never set spec.clusterName.
// Non-broker identities are unrestricted.
func Review(u authuser.Info, a Attr) (bool, string) {
	cluster, isBroker := clusterOf(u)
	if !isBroker { return true, "" }
	if a.SetsClusterName {
		return false, "broker may not set spec.clusterName (cannot bind/re-bind workloads)"
	}
	if a.Resource == "clusterpools" {
		if a.Name != cluster {
			return false, fmt.Sprintf("broker %q may only write its own ClusterPool %q, not %q", u.GetName(), cluster, a.Name)
		}
		if a.Subresource != "status" {
			return false, "broker may only write the status of its own ClusterPool"
		}
	}
	return true, ""
}
```
Run → PASS.

- [ ] **Step 3: SPIKE the apiserver-kit admission wiring.** Determine how to register an in-process validating admission plugin with apiserver-kit's `Builder` (it exposes `WithExtraAdmissionInitializers` + uses `genericoptions.RecommendedOptions`, whose `.Admission.Plugins` is the registry + `.Admission.RecommendedPluginOrder`/enable list). Write `central/internal/clusterrestriction/plugin.go`: a plugin implementing `admission.ValidationInterface` whose `Validate` builds an `Attr` from `admission.Attributes` (resource, name, subresource; `SetsClusterName` by decoding the incoming object's `spec.clusterName` vs the old object — for creates, non-empty clusterName counts as setting it; for updates, changed counts) and calls `Review(a.GetUserInfo(), attr)`. Then wire it in `central/cmd/apiserver/main.go`:
  - If apiserver-kit lets you reach `RecommendedOptions.Admission` (via a builder setter or `WithExtraAdmissionInitializers`), register the plugin name + factory and add it to the enabled plugins.
  - **If the builder does NOT expose enough** to register+enable a custom plugin, add a minimal setter to the LOCAL apiserver-kit (as was done for multi-group at f365c59) — e.g. `WithAdmissionPlugin(name string, factory admission.Factory)` that registers on `recommendedOptions.Admission.Plugins` and appends to the enabled order. Document the addition in the commit.
  - **Fallback:** if in-process registration proves intractable, serve a `ValidatingAdmissionWebhook` from central instead (a small HTTPS handler calling `Review`), and register a `ValidatingWebhookConfiguration`. Prefer in-process; use the webhook only if blocked, and note it.

Build: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go build ./... 2>&1 | tail'` → exit 0.

- [ ] **Step 4: Wire + build.** Ensure the plugin is enabled by default in the apiserver (so envtest exercises it). Keep the Phase-1 admission-plugin disables (`MutatingAdmissionPolicy`,`ValidatingAdmissionPolicy`) intact.

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go build ./... && go test ./internal/clusterrestriction/... 2>&1 | tail'`
Expected: unit PASS; build clean. (The envtest for the wired plugin is Task 7.)

- [ ] **Step 5: Commit** (record the wiring recipe, incl. any apiserver-kit addition).

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/internal/clusterrestriction central/cmd/apiserver/main.go central/go.mod central/go.sum
git commit -m "feat(central): thin ClusterRestriction admission (broker writes own pool status only)

Wiring: <RECORD in-process plugin vs webhook + any apiserver-kit setter added>.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Envtests (scheduler, failover, admission) + chained e2e + wrap

**Files:** `central/test/scheduler_test.go`, `central/test/failover_test.go`, `central/test/clusterrestriction_test.go`, `central/test/phase3_e2e_test.go`.

- [ ] **Step 1: Scheduler + failover envtests.** `central/test/scheduler_test.go`: boot the central kit-aggregated apiserver (reuse the `startNetEnv`/kit boot helper from `net_envtest_test.go`), create a `ClusterPool{c1}` with `Status.Phase=Ready` + `Allocatable{cpu:8}` (status write), create an unbound `VirtualMachine`, run `scheduler.Reconciler{Client}.Reconcile(...)` once, assert `vm.Spec.ClusterName=="c1"` + `Scheduled` condition True. `central/test/failover_test.go`: pool `c1` `Unknown` with a stale lease + a Ready `c2`, a VM bound to c1; run `failover.Reconciler{Client, Fencer: fakeConfirm{}, FailoverThreshold: small}` → assert rebind to c2; repeat with a denying fencer → assert `FailoverBlocked` + still c1. (Use direct `Reconcile` calls against the real apiserver, mirroring `phase1b_e2e_test.go`.)

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go test ./test/ -run "Scheduler|Failover" -v 2>&1 | tail -30'`
Expected: PASS.

- [ ] **Step 2: ClusterRestriction impersonation envtest.** `central/test/clusterrestriction_test.go`: boot central; build a client that impersonates the broker identity via `rest.Config.Impersonate = rest.ImpersonationConfig{UserName: "ectobase:cluster:c1"}`. Assert: (a) the impersonated client CAN update `ClusterPool c1` status; (b) CANNOT update `ClusterPool c2` status (Forbidden); (c) CANNOT create/update a `VirtualMachine` with a non-empty `spec.clusterName` (Forbidden); (d) an unimpersonated (admin) client CAN. If the wiring used the webhook fallback, ensure the webhook is running in the test.

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go test ./test/ -run ClusterRestriction -v 2>&1 | tail -30'`
Expected: PASS (the admission decisions are enforced by the server).

- [ ] **Step 3: Chained single-cluster e2e.** `central/test/phase3_e2e_test.go` (extends the Phase-1b chain): boot central + a downstream envtest (CompiledNIC CRD). Create `ClusterPool{c1}`; run `broker.Heartbeater{...,Reporter: static cpu:8}.heartbeatOnce` → run `clusterpool.Reconciler{HealthStale}.Reconcile` → assert pool `Ready`. Create an unbound `VirtualMachine{vm1, interfaceRefs:[nic-a]}` + `NetworkInterface{nic-a}` (+status VNI as in the Phase-1b e2e); run `scheduler.Reconciler.Reconcile` → assert `vm1.Spec.ClusterName=="c1"`. Run the compiler `controllers.CompiledNICReconciler.Reconcile` (import netplane, as the Phase-1b e2e does) → assert `CompiledNIC default-nic-a` has `Spec.ClusterName=="c1"`. Run `broker.Broker{ClusterName:"c1"}.SyncOnce` → assert it materializes downstream. This proves heartbeat→Ready→schedule→compile→sync end to end.

Run: `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/central && go test ./test/ -run Phase3 -v 2>&1 | tail -30'`
Expected: PASS.

- [ ] **Step 4: Full build + tests + commit.**

Run: `nix develop --command bash -c 'for m in api central netplane; do echo "== $m =="; (cd /home/nik/Development/ironcore-net-xdp/$m && go build ./... && go test ./... 2>&1 | grep -vE "no test files"); done 2>&1 | tail -40'`
Expected: green (kine durability test skips; the benign SSA managedFields log is non-fatal).

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/test
git commit -m "test(central): Phase 3 envtests (scheduler, failover, ClusterRestriction) + chained e2e

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

- [ ] **Step 5: Wrap (controller-run).** Update memory (`phase3-scheduler-failover.md` + MEMORY.md index): scheduler binds VM.spec.clusterName from ClusterPool health(lease)+capacity(corev1.ResourceList); broker heartbeat = first upward status; Tier-2 failover skeleton (Fencer seam, DenyFencer default, fail-safe); thin ClusterRestriction admission (`ectobase:cluster:<name>`, impersonation-tested; record the apiserver-kit wiring); open: real fence actuators + Tier-1 + VMI lifecycle (Phase 4), full authorizer + broker identity issuance. Then finish the branch via superpowers:finishing-a-development-branch.

---

## Notes for the executor

- **Additive** types (new optional Spec/Status fields); the datapath, compiler, and broker-sync are unchanged — the scheduler operates on the VM one level up.
- **Net-group types (VirtualMachine)** need the hand-written conversion updated (Task 1 Step 3) — the roundtrip fuzz test is the guard; if it fails, a field wasn't copied both ways.
- **`corev1` everywhere** for capacity — no custom resource types.
- **`WatchListClient=false`** on the scheduler/failover/pool-health informers (aggregated apiserver).
- **Two thresholds:** pool-health `HealthStale` (→Unknown) must be < failover `FailoverThreshold` (→rebind).
- **Failover is fail-safe by default** (`DenyFencer`); real actuators are Phase 4.
- **Admission spike (Task 6 Step 3)** is the one real unknown — resolve in-process vs webhook before writing the envtest (Task 7 Step 2). Record the recipe in the commit.
- Sequential git; per-task spec + quality review; envtest/codegen via the nix devShell.
