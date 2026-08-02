# Phase 2: Broker Vertical Slice (kubelet-analog) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the core multi-cluster mechanism from the vision (`2026-08-01-multicluster-control-plane-design.md` M2/M3/M4): a central compiled object bound to a cluster via `spec.clusterName`, and a **per-cluster broker (kubelet-analog)** that field-selector-watches its own binding on the central aggregated apiserver and **set-reconciles** the objects down into a downstream cluster as local CRDs (with GC + partition tolerance). Prove it loopback (two in-process apiservers) then across two kind clusters.

**Architecture:** Add a `CompiledWorkload` type to the central aggregated apiserver (`central`, from Phase 1) carrying `spec.clusterName` (selectable field, reusing the Phase-1 hook) + a small payload. Generate a CRD manifest for the SAME type for downstream install. The broker (`central/cmd/broker`) holds one connection to central, watches `CompiledWorkload` where `spec.clusterName == <myCluster>` (field selector), and reconciles the downstream cluster's `CompiledWorkload` CRDs to exactly match the bound set (create/update/delete). Downstream materialization + local reconcile is the existing agent pattern; the broker never lets central watch it.

**Tech Stack:** Go 1.26.4, `central` module (apiserver-kit v0.3.4 via local `replace`, kine/Postgres), controller-runtime v0.24.1 (client + manager), `k8s.io/code-generator` (kube::codegen, already wired) + `controller-gen` (CRD manifest, as api module uses), envtest (kit envtest for central-aggregated; controller-runtime envtest for downstream), kind (2-cluster smoke).

**Scope note:** Phase 2 of the 7-phase vision. It proves the broker/binding/sync loop with a stand-in `CompiledWorkload`; wiring the REAL compiled objects (CompiledNIC etc.) + the compiler is Phase 1b, and the scheduler/failover are Phase 3+. Single-cluster invariant holds: the loopback test (Task 5) is the standing gate before the 2-cluster smoke (Task 6). Builds additively on Phase 1; keeps the local apiserver-kit `replace`.

**Critical Phase-1 carry-over (do not relearn the hard way):** a controller/informer talking to the aggregated apiserver MUST set `KUBE_FEATURE_WatchListClient=false` (client-go streaming list-watch is unsupported by the aggregated server → informer silently stuck, zero events). The broker's central-side watch is exactly this path.

---

## File structure

- `central/apis/platform/compiledworkload_types.go` (internal) + `compiledworkload_rest.go` (resource.Object + selectable-field impls) — new type.
- `central/apis/platform/v1alpha1/compiledworkload_types.go` (versioned) + regenerated codegen.
- `central/config/crd/platform.ectobase.dev_compiledworkloads.yaml` — CRD manifest for DOWNSTREAM install (controller-gen).
- `central/internal/broker/broker.go` — the set-reconcile sync engine (central→downstream), testable with injected clients.
- `central/cmd/broker/main.go` — broker entrypoint (central kubeconfig + downstream kubeconfig + `--cluster-name`).
- `central/test/broker_test.go` — loopback envtest (central aggregated + downstream plain apiserver).
- `central/config/broker.yaml` + `central/hack/broker-smoke.sh` — 2-cluster kind smoke.

---

## Task 1: `CompiledWorkload` type with `spec.clusterName` binding

**Files:** `central/apis/platform/compiledworkload_types.go`, `compiledworkload_rest.go`, `central/apis/platform/v1alpha1/compiledworkload_types.go` + regenerated codegen.

- [ ] **Step 1: Add the types (internal + versioned), modeled on ClusterPool.** `CompiledWorkload` is cluster-scoped, has a status subresource. Spec: `ClusterName string` (the binding), `Payload string` (stand-in for the materialized content). Status: `Phase string`. Mirror EXACTLY how `ClusterPool` is split across `central/apis/platform/` (internal + `_rest.go` impls) and `central/apis/platform/v1alpha1/` — read those files first and copy the structure. Give the internal type: `GetObjectMeta`, `NamespaceScoped()→false`, `New`, `NewList`, `GetGroupResource()` (`WithResource("compiledworkloads")`), `CopyStatusTo`, and — reusing the Phase-1 hook — `SelectableFields() fields.Set{"spec.clusterName": o.Spec.ClusterName}` + `SupportedFieldSelectors() []string{"spec.clusterName"}` (same interfaces `ClusterPool` implements in `compiledworkload_rest.go`; check the exact interface names in `central/apis/platform/clusterpool_rest.go`).

- [ ] **Step 2: Register in scheme.** Add `&CompiledWorkload{}, &CompiledWorkloadList{}` to `addKnownTypes` in both internal `central/apis/platform/register.go` and versioned `.../v1alpha1/register.go` (mirror how ClusterPool is registered).

- [ ] **Step 3: Regenerate codegen.**

Run: `cd /home/nik/Development/ironcore-net-xdp/central && bash hack/update-codegen.sh 2>&1 | tail -15`
Expected: deepcopy/conversion/defaults/openapi/clientset/informers/listers updated to include `CompiledWorkload`. Build: `go build ./... 2>&1 | tail` → exit 0. Roundtrip: `go test ./apis/... 2>&1 | tail` → PASS.

- [ ] **Step 4: Serve it from the apiserver.** In `central/cmd/apiserver/main.go`, add `.With(apiserver.Resource(&platform.CompiledWorkload{}, v1alpha1.SchemeGroupVersion))` next to the ClusterPool line. Update the envtest APIService fixture only if a second resource needs it (it doesn't — same group/APIService).

- [ ] **Step 5: Extend the CRUD envtest.** In `central/test/envtest_test.go`, add a `CompiledWorkload` create/get + `spec.clusterName` field-selector list assertion (mirror `TestClusterPool_SpecFieldSelector`): create wl-a{clusterName:c1}, wl-b{clusterName:c2}, `List(MatchingFields{"spec.clusterName":"c1"})` → exactly [wl-a]. Run:

`cd /home/nik/Development/ironcore-net-xdp/central && go test ./test/ -run "CompiledWorkload|ClusterPool" -v 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/apis central/client-go central/cmd/apiserver/main.go central/test/envtest_test.go
git commit -m "feat(central): CompiledWorkload type with spec.clusterName binding

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Downstream CRD manifest for `CompiledWorkload`

**Files:** `central/config/crd/platform.ectobase.dev_compiledworkloads.yaml`, `central/hack/update-crd.sh`

- [ ] **Step 1: Generate the CRD manifest** from the versioned type using controller-gen (as the `api` module does — see `/home/nik/Development/ironcore-net-xdp/Makefile` target `generate`, which runs `controller-gen crd`). The type needs `+kubebuilder:object:root=true` / `+kubebuilder:resource:scope=Cluster` / `+kubebuilder:subresource:status` markers on the VERSIONED type (add them if kube::codegen didn't need them). Create `central/hack/update-crd.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
controller-gen crd paths=./apis/platform/v1alpha1/... output:crd:artifacts:config=./config/crd
```
Run it; expected output `central/config/crd/platform.ectobase.dev_compiledworkloads.yaml` with the CompiledWorkload schema (spec.clusterName, spec.payload, status.phase), `scope: Cluster`, status subresource.

- [ ] **Step 2: Sanity-check the manifest.** `kubectl --dry-run=client apply -f central/config/crd/platform.ectobase.dev_compiledworkloads.yaml` (via `nix develop --command kubectl` if needed) → no schema error.

- [ ] **Step 3: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/config/crd central/hack/update-crd.sh central/apis/platform/v1alpha1/compiledworkload_types.go
git commit -m "feat(central): downstream CRD manifest for CompiledWorkload

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Broker set-reconcile engine (TDD, injected clients)

**Files:** `central/internal/broker/broker.go`, `central/internal/broker/broker_test.go`

- [ ] **Step 1: Write the failing unit test** with fake clients. The engine's contract: given a `clusterName`, the desired set = CompiledWorkloads in central with `spec.clusterName == clusterName`; reconcile the downstream set to match — create missing, update drifted (by spec), delete extra (GC). It must be declarative/idempotent (the `ReplaceInterfaceFirewall`/appliedFw lesson — no in-memory diff state; derive from the two live sets each pass). Use controller-runtime `fake.NewClientBuilder()` for both central and downstream clients.

```go
package broker

import (
	"context"; "testing"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"k8s.io/apimachinery/pkg/runtime"
	platforminstall "github.com/trevex/ectobase/central/apis/platform/install"
	v1alpha1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

func scheme(t *testing.T) *runtime.Scheme { s := runtime.NewScheme(); if err := platforminstall.AddToScheme(s); err != nil { /* use v1alpha1.AddToScheme if that's the exported one */ t.Fatal(err) }; return s }

func TestSync_CreatesUpdatesDeletes(t *testing.T) {
	s := scheme(t)
	wl := func(name, cn, payload string) *v1alpha1.CompiledWorkload {
		return &v1alpha1.CompiledWorkload{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.CompiledWorkloadSpec{ClusterName: cn, Payload: payload}}
	}
	central := fake.NewClientBuilder().WithScheme(s).WithObjects(wl("a","c1","x"), wl("b","c2","y")).Build()
	// downstream starts with a stale object (should be GC'd) + an object needing update.
	downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(wl("stale","c1","old"), wl("a","c1","OLD")).Build()

	b := &Broker{Central: central, Downstream: downstream, ClusterName: "c1", Scheme: s}
	if err := b.SyncOnce(context.Background()); err != nil { t.Fatal(err) }

	// downstream must now be exactly {a(payload x)}: b is not ours (c2), stale is gone, a is updated.
	list := &v1alpha1.CompiledWorkloadList{}
	if err := downstream.List(context.Background(), list); err != nil { t.Fatal(err) }
	if len(list.Items) != 1 || list.Items[0].Name != "a" || list.Items[0].Spec.Payload != "x" {
		t.Fatalf("want exactly [a(x)], got %+v", list.Items)
	}
}
```
Run → FAIL (no Broker).

- [ ] **Step 2: Implement `Broker` + `SyncOnce`.** In `central/internal/broker/broker.go`:

```go
package broker

import (
	"context"; "fmt"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	v1alpha1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

// Broker is the per-cluster kubelet-analog: it syncs CompiledWorkloads bound to
// ClusterName from Central down into Downstream as local CRDs (declarative set-reconcile).
type Broker struct {
	Central    client.Client // the central aggregated apiserver
	Downstream client.Client // the local cluster apiserver
	ClusterName string
	Scheme     *runtime.Scheme
}

// SyncOnce makes the downstream set exactly match the central objects bound to ClusterName.
// Declarative: derived from the two live sets each call — no in-memory diff to lose on restart.
func (b *Broker) SyncOnce(ctx context.Context) error {
	desired := &v1alpha1.CompiledWorkloadList{}
	if err := b.Central.List(ctx, desired, client.MatchingFields{"spec.clusterName": b.ClusterName}); err != nil {
		return fmt.Errorf("list central: %w", err)
	}
	want := map[string]*v1alpha1.CompiledWorkload{}
	for i := range desired.Items { want[desired.Items[i].Name] = &desired.Items[i] }

	have := &v1alpha1.CompiledWorkloadList{}
	if err := b.Downstream.List(ctx, have); err != nil { return fmt.Errorf("list downstream: %w", err) }
	haveSet := map[string]bool{}
	for i := range have.Items {
		name := have.Items[i].Name
		haveSet[name] = true
		if _, ok := want[name]; !ok {
			if err := b.Downstream.Delete(ctx, &have.Items[i]); err != nil { return fmt.Errorf("gc %s: %w", name, err) }
		}
	}
	for name, w := range want {
		local := &v1alpha1.CompiledWorkload{}
		if !haveSet[name] {
			local.Name = name
			local.Spec = w.Spec
			if err := b.Downstream.Create(ctx, local); err != nil { return fmt.Errorf("create %s: %w", name, err) }
			continue
		}
		if err := b.Downstream.Get(ctx, client.ObjectKey{Name: name}, local); err != nil { return fmt.Errorf("get %s: %w", name, err) }
		if local.Spec != w.Spec {
			local.Spec = w.Spec
			if err := b.Downstream.Update(ctx, local); err != nil { return fmt.Errorf("update %s: %w", name, err) }
		}
	}
	return nil
}
```
NOTE: for the fake-client `List(..., MatchingFields{"spec.clusterName":...})` to work in the UNIT test, register a field index on the fake builder (`WithIndex(&v1alpha1.CompiledWorkload{}, "spec.clusterName", func(o client.Object) []string {...})`), OR in the unit test filter client-side and reserve the true field-selector for the envtest (Task 5) where the real apiserver honors it. Prefer: add the index in the test so the same code path is exercised. Adjust the test's client build accordingly.

Run → PASS.

- [ ] **Step 3: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/internal/broker/
git commit -m "feat(central): broker set-reconcile engine (declarative central->downstream sync)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Broker manager entrypoint (informer-driven, WatchListClient=false)

**Files:** `central/cmd/broker/main.go`

- [ ] **Step 1: Implement the broker main.** A controller-runtime manager whose CENTRAL client drives an informer (watch `CompiledWorkload` filtered by `spec.clusterName == --cluster-name`), and whose reconcile calls the Task-3 engine `SyncOnce` (or a per-object variant) against the DOWNSTREAM client built from `--downstream-kubeconfig`. Flags: `--central-kubeconfig`, `--downstream-kubeconfig`, `--cluster-name`. Set `Metrics: server.Options{BindAddress:"0"}`. **CRITICAL:** set `os.Setenv("KUBE_FEATURE_WatchListClient","false")` at the top of main (or document it as a required env in the Deployment) — otherwise the central informer silently stalls against the aggregated apiserver (Phase-1 finding). Model manager wiring on `central/cmd/controller/main.go`. A full-resync (`SyncOnce`) on each reconcile is acceptable for the slice (declarative + simple); optimize later.

- [ ] **Step 2: Build.** `cd central && go build ./... 2>&1 | tail` → exit 0.

- [ ] **Step 3: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/cmd/broker/
git commit -m "feat(central): broker entrypoint (central informer -> downstream set-reconcile)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Loopback envtest — central aggregated + downstream plain apiserver (the §9 gate)

**Files:** `central/test/broker_test.go`

- [ ] **Step 1: Write the loopback integration test.** Two apiservers in one test: (a) CENTRAL = the kit aggregated apiserver via `kitenvtest` (serves CompiledWorkload), as in `envtest_test.go`; (b) DOWNSTREAM = a plain controller-runtime `envtest.Environment` with the `central/config/crd/platform.ectobase.dev_compiledworkloads.yaml` CRD installed. Build a central client + a downstream client. Run the broker engine (`broker.Broker{Central, Downstream, ClusterName:"c1"}`) — either call `SyncOnce` directly or start the manager. Assert:
  - Create `CompiledWorkload{clusterName:c1,payload:x}` + `{clusterName:c2}` in central → after sync, downstream has exactly the c1 one (bounded pull: c2 never crosses).
  - Update the c1 payload in central → downstream converges.
  - Delete the c1 object in central → downstream GCs it.
  - (Partition-tolerance smoke) stop the central env; the downstream object REMAINS (local cache survives central outage).

```go
func TestBroker_Loopback_SyncAndGC(t *testing.T) {
	// central = kitenvtest (aggregated, serves CompiledWorkload)
	// downstream = controller-runtime envtest with the CompiledWorkload CRD
	// broker.SyncOnce -> assert create/update/delete/bounded-by-clusterName + survives central stop
}
```

- [ ] **Step 2: Run.**

`cd /home/nik/Development/ironcore-net-xdp/central && go test ./test/ -run TestBroker_Loopback -v 2>&1 | tail -30`
Expected: PASS. (Both envtests need KUBEBUILDER_ASSETS — devShell. If `WatchListClient` bites when using a manager/informer, the direct `SyncOnce` path avoids it for the test; the env var is still set in the broker main for the live path.)

- [ ] **Step 3: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/test/broker_test.go
git commit -m "test(central): broker loopback envtest (central->downstream sync, GC, bounded, partition-survive)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Two-cluster kind smoke (best-effort; loopback is the gate)

**Files:** `central/config/broker.yaml`, `central/hack/broker-smoke.sh`, `central/Dockerfile.broker`

- [ ] **Step 1: Broker image + Deployment.** `central/Dockerfile.broker` (COPY host-built static binary, like the Phase-1 Dockerfiles — the local `replace` requires it). `central/config/broker.yaml`: the broker Deployment with `--central-kubeconfig` (a secret/mount for the central cluster) + `--downstream-kubeconfig` (in-cluster, the downstream) + `--cluster-name`, and env `KUBE_FEATURE_WatchListClient=false`.

- [ ] **Step 2: Two-cluster smoke script.** `central/hack/broker-smoke.sh`: create kind cluster `central` (deploy the Phase-1 `central/config` stack: kine + apiserver + APIService) and kind cluster `edge1` (apply the CompiledWorkload CRD + run the broker with `--cluster-name=edge1` pointed at central). Create a `CompiledWorkload{clusterName:edge1}` in central; assert it materializes as a CRD in edge1; delete it; assert GC. Reuse the Phase-1 aggregated-apiserver deploy fixes (readyz RBAC, disabled admission plugins). ATTEMPT to run; if the cross-cluster kubeconfig/cert wiring is finicky within ~25 min, mark DONE_WITH_CONCERNS (loopback Task 5 is the authoritative gate), commit the manifests+script, and report what's left.

- [ ] **Step 3: Verify default tests + commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp/central && go build ./... && go test ./... 2>&1 | grep -vE "no test files" | tail
cd /home/nik/Development/ironcore-net-xdp
git add central/config/broker.yaml central/hack/broker-smoke.sh central/Dockerfile.broker
git commit -m "feat(central): broker deploy manifest + 2-cluster kind smoke

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Wrap — memory + finish

- [ ] **Step 1: Full build + test.** `(cd central && go build ./... && go test ./... 2>&1 | grep -vE "no test files" | tail)`; other modules build. Expected: green.
- [ ] **Step 2: Update memory** `central-apiserver-foundation` (or a new `central-broker` memory): the broker/binding/sync loop proven (loopback + 2-cluster status), `CompiledWorkload{spec.clusterName}`, set-reconcile GC, WatchListClient carry-over, partition-survive test. Update MEMORY.md index. Note open: Phase 1b (real compiled types + compiler), Phase 3 (scheduler binding + failover), ClusterRestriction authorizer, status-back-to-central.
- [ ] **Step 3: Finish the branch** via superpowers:finishing-a-development-branch (merge to main; the local apiserver-kit `replace` caveat carries over — merge is fine per the Phase-1 decision).

---

## Notes for the executor

- **Additive**; keep the local `replace go.opendefense.cloud/kit => /home/nik/Development/apiserver-kit`. Only the `central` module changes.
- **WatchListClient=false** on any informer against the aggregated apiserver (Phase-1 finding) — non-negotiable for the broker main.
- **Declarative set-reconcile, no in-memory diff** — derive desired+have from the live sets each pass (the `appliedFw`/ReplaceInterfaceFirewall lesson).
- Run git-mutating tasks sequentially. envtest needs the devShell (KUBEBUILDER_ASSETS).
- Loopback (Task 5) is the standing single-cluster gate; the 2-cluster smoke is the multi-cluster proof but best-effort if cross-cluster cert wiring fights back.
- Branch: create `feat/phase2-broker` off main before Task 1.
