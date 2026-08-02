# Phase 1: Central Aggregated Apiserver Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the central control plane's **aggregated (extension) apiserver** — `apiserver-kit` backed by **kine → Postgres** (no etcd) — serving a new `ClusterPool` type, with **selectable spec-field** support (upstreamed to apiserver-kit) proven end-to-end, and an envtest harness. This is the foundation the broker/scheduler/compiler build on; it is **additive** and does not touch the working single-cluster netplane/flowplane system.

**Architecture:** A new `central` Go module in the workspace hosts a `apiserver-kit` server (`central/cmd/apiserver`) exposing group `platform.ectobase.dev/v1alpha1` with a `ClusterPool` resource. Storage is kine (etcd-v3 shim) over Postgres via the stock `--etcd-servers` flag. To support the pod→node binding model (a controller watching by `spec.<field>`), we add a small, backward-compatible **selectable-fields hook** to apiserver-kit upstream and consume it here, proving a `spec`-field watch works. Testing uses apiserver-kit's `envtest` (embedded etcd for CI) plus a kine-backed durability check.

**Tech Stack:** Go 1.26, `go.opendefense.cloud/kit` v0.3.4 (`github.com/opendefensecloud/apiserver-kit`, k8s.io v0.36.2), `k8s.io/apimachinery` v0.36.2, kine (`github.com/k3s-io/kine`) over Postgres, `k8s.io/code-generator` (deepcopy + openapi), controller-runtime envtest (KUBEBUILDER_ASSETS via the nix devShell).

**Scope note:** This is **Phase 1 of the 7-phase** `docs/superpowers/specs/2026-08-01-multicluster-control-plane-design.md`. It delivers the apiserver foundation only. Migrating existing `net.ectobase.dev` types into the aggregated server + repointing the compiler is **Phase 1b (next plan)**; the broker is **Phase 2**. Each satisfies the single-cluster invariant (§9 of the spec).

---

## File structure (created/modified)

- `central/` — **new Go module** `github.com/trevex/ectobase/central` (added to `go.work`).
  - `central/apis/platform/v1alpha1/` — `ClusterPool` types, `register.go`, `doc.go`, generated `zz_generated.deepcopy.go`, generated openapi.
  - `central/apis/platform/install/install.go` — scheme install.
  - `central/cmd/apiserver/main.go` — the apiserver-kit server entrypoint.
  - `central/internal/clusterpool/strategy.go` — custom strategy exposing selectable `spec` fields.
  - `central/test/envtest_test.go` — aggregated-server integration tests (CRUD + spec-field watch).
  - `central/hack/kine-up.sh`, `central/hack/kine-down.sh` — local kine+Postgres for the durability test.
- `hack/apiserver-kit/` — a **clone/worktree of apiserver-kit** for the upstream PR (not committed to this repo; PR pushed to the fork).
- `go.work` — add `./central`.

---

## Task 1: Scaffold the `central` module + confirm apiserver-kit against v0.3.4 (grounding spike)

**Files:**
- Create: `central/go.mod`, `central/apis/platform/v1alpha1/doc.go`
- Modify: `go.work`

- [ ] **Step 1: Create the module + wire the workspace.**

```bash
cd /home/nik/Development/ironcore-net-xdp
mkdir -p central/apis/platform/v1alpha1 central/cmd/apiserver central/internal/clusterpool central/test central/hack
cd central && go mod init github.com/trevex/ectobase/central
go get go.opendefense.cloud/kit@v0.3.4
go get k8s.io/apimachinery@v0.36.2 k8s.io/apiserver@v0.36.2 k8s.io/client-go@v0.36.2 k8s.io/code-generator@v0.36.2
cd /home/nik/Development/ironcore-net-xdp
go work use ./central
```
Expected: `central/go.mod` created with the deps; `go.work` lists `./central`.

- [ ] **Step 2: Confirm the apiserver-kit API surface against the resolved version.** The plan's code sketches were written from the research brief; a pre-1.0 dep may have drifted. Read the resolved source and confirm the exact symbols before writing code against them:

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp/central
KIT=$(go list -m -f '{{.Dir}}' go.opendefense.cloud/kit)
echo "$KIT"
grep -rn "func NewBuilder\|func (b \*Builder)\|func Resource\|func NewStore\|func NewDefaultStrategy\|type Strategy\|func GetAttrs\|func SelectableFields\|type Object\b" "$KIT/apiserver" "$KIT/apiserver/rest" "$KIT/apiserver/resource" | head -40
ls "$KIT/example"/... 2>/dev/null; find "$KIT/example" -name main.go
```
Expected: prints the real signatures for `NewBuilder`, `Builder.With*`, `Resource[...]`, `rest.NewStore`, `Strategy`, `GetAttrs`/`SelectableFields`, and the `resource.Object` interface, plus the shipped `example/` server main. **Record any signature that differs from this plan's sketches and adapt subsequent tasks accordingly** (this is the grounding step for a pre-1.0 dep, not a placeholder — the concrete signatures are in the research brief and expected to match).

- [ ] **Step 3: Add the package doc + groupName marker.** Create `central/apis/platform/v1alpha1/doc.go`:

```go
// Package v1alpha1 contains the platform.ectobase.dev central control-plane API
// (ClusterPool and, later, the compiled objects), served by the aggregated apiserver.
// +groupName=platform.ectobase.dev
// +k8s:deepcopy-gen=package
package v1alpha1
```

- [ ] **Step 4: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/go.mod central/go.sum go.work go.work.sum central/apis/platform/v1alpha1/doc.go
git commit -m "feat(central): scaffold central module + apiserver-kit dep

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `ClusterPool` API types + scheme + codegen

> **⚠ Task-1 finding (authoritative — overrides the sub-steps below where they differ):** apiserver-kit requires the full **sample-apiserver layout**: an **internal** types package `central/apis/platform` (with the `resource.Object` method impls — `GetObjectMeta`/`NamespaceScoped`/`New`/`NewList`/`GetGroupResource`, and `CopyStatusTo` for the status subresource) **plus** a **versioned** package `central/apis/platform/v1alpha1`, an `install/`, `register.go` (internal + versioned), a `fuzzer/`, and an `install/roundtrip_test.go`. Codegen is driven by **`kube::codegen`** (sourced from `k8s.io/code-generator`'s `kube_codegen.sh`), not raw `deepcopy-gen`/`openapi-gen`. **Replicate the shipped example verbatim, adapted:** `$KIT/example/api/foo` (where `KIT=$(go list -m -f '{{.Dir}}' go.opendefense.cloud/kit)`) is the template for the API tree, and `$KIT/example/hack/update-codegen.sh` (+ its `boilerplate.go.txt`, `use-local-modules.sh` openapi-gen workaround) is the template for `central/hack/update-codegen.sh`. Model `ClusterPool` on `foo.ClusterBar` (cluster-scoped: `NamespaceScoped() → false`). The `WithOpenAPIDefinitions` arg comes from the generated `central/client-go/openapi` package (like the example's `example/client-go/openapi`), NOT the v1alpha1 package. The sub-steps below give the type shapes + intent; use the example for the exact codegen wiring.

**Files:**
- Create (internal): `central/apis/platform/types.go` (or `clusterpool_types.go`), `clusterpool_rest.go` (resource.Object impls), `register.go`, `doc.go`, `fuzzer/fuzzer.go`, `install/install.go`, `install/roundtrip_test.go`
- Create (versioned): `central/apis/platform/v1alpha1/types.go`, `register.go`, `defaults.go`, `doc.go`
- Create: `central/hack/update-codegen.sh` (modeled on `$KIT/example/hack/update-codegen.sh`), `central/hack/boilerplate.go.txt`
- Generate (via kube::codegen): internal + versioned `zz_generated.deepcopy.go`, versioned `zz_generated.conversion.go`, `zz_generated.defaults.go`, `zz_generated.model_name.go`, and `central/client-go/{openapi,clientset,listers,informers,applyconfigurations}`

- [ ] **Step 1: Define the `ClusterPool` types.** Create `central/apis/platform/v1alpha1/types.go`. `ClusterPool` is an attached cluster as a schedulable capacity domain (the "node" in the pod→node model). Include a `Region` spec field now purely to **prove selectable spec fields** in Task 5 (it is a realistic field; the binding `spec.clusterName` lands on compiled objects in a later phase).

```go
package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ClusterPool is an attached cluster registered as a schedulable capacity domain.
type ClusterPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ClusterPoolSpec   `json:"spec,omitempty"`
	Status            ClusterPoolStatus `json:"status,omitempty"`
}

type ClusterPoolSpec struct {
	// Region is a coarse placement domain (used to prove spec-field selection).
	Region string `json:"region,omitempty"`
	// Endpoint is the attached cluster's apiserver URL (used by the broker later).
	Endpoint string `json:"endpoint,omitempty"`
}

type ClusterPoolStatus struct {
	// Phase is Pending|Ready|Unknown (lease-driven; populated in a later phase).
	Phase string `json:"phase,omitempty"`
	// Conditions carries standard condition entries.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// ClusterPoolList is a list of ClusterPool.
type ClusterPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterPool `json:"items"`
}
```

- [ ] **Step 2: Scheme registration.** Create `central/apis/platform/v1alpha1/register.go` mirroring the existing `api/v1alpha1/register.go` pattern:

```go
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const GroupName = "platform.ectobase.dev"

var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

var (
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion, &ClusterPool{}, &ClusterPoolList{})
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
```

Create `central/apis/platform/install/install.go`:

```go
package install

import (
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	v1alpha1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

// Install registers platform.ectobase.dev into the scheme.
func Install(scheme *runtime.Scheme) {
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}
```

- [ ] **Step 3: Generate deepcopy + openapi.** apiserver-kit's `Resource[...]` bound requires `DeepCopy`, and the builder requires `GetOpenAPIDefinitions`. Use `k8s.io/code-generator`. First confirm the generator entrypoints available in the resolved code-generator, then run:

```bash
cd /home/nik/Development/ironcore-net-xdp/central
CODEGEN=$(go list -m -f '{{.Dir}}' k8s.io/code-generator)
# deepcopy:
go run k8s.io/code-generator/cmd/deepcopy-gen \
  --output-file zz_generated.deepcopy.go \
  --go-header-file "$CODEGEN/hack/boilerplate.go.txt" \
  ./apis/platform/v1alpha1
# openapi:
go run k8s.io/code-generator/cmd/openapi-gen \
  --output-dir ./apis/platform/v1alpha1 --output-pkg github.com/trevex/ectobase/central/apis/platform/v1alpha1 \
  --output-file zz_generated.openapi.go \
  k8s.io/apimachinery/pkg/apis/meta/v1 k8s.io/apimachinery/pkg/runtime k8s.io/apimachinery/pkg/version \
  ./apis/platform/v1alpha1
```
Expected: `zz_generated.deepcopy.go` (with `ClusterPool`/`ClusterPoolList`/spec/status `DeepCopy*`) and `zz_generated.openapi.go` created. **If the code-generator flag surface differs at v0.36.2, confirm with `go run k8s.io/code-generator/cmd/deepcopy-gen --help` and adjust flags** (grounding, not a placeholder — deepcopy-gen/openapi-gen are standard). Record the exact working invocation into a `central/hack/update-codegen.sh` script and commit it too.

- [ ] **Step 4: Build.**

Run: `cd /home/nik/Development/ironcore-net-xdp/central && go build ./...`
Expected: exit 0.

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/apis central/hack/update-codegen.sh
git commit -m "feat(central): ClusterPool API types + scheme + codegen

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Aggregated apiserver entrypoint + envtest CRUD/watch (embedded etcd)

**Files:**
- Create: `central/cmd/apiserver/main.go`, `central/test/envtest_test.go`

- [ ] **Step 1: Write the failing envtest.** Create `central/test/envtest_test.go`. It starts the aggregated server via apiserver-kit's `envtest` (embedded etcd), then creates/gets/lists/watches a `ClusterPool` through the returned client. Confirm the `envtest.NewEnvironment`/`Start`/`Stop` signatures from Task 1 Step 2 and adapt the calls if they differ.

```go
package test

import (
	"context"
	"os"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kitenvtest "go.opendefense.cloud/kit/envtest"
	platforminstall "github.com/trevex/ectobase/central/apis/platform/install"
	v1alpha1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

func TestClusterPool_CRUDAndWatch(t *testing.T) {
	scheme := kitScheme(t)
	env, err := kitenvtest.NewEnvironment("../cmd/apiserver", nil, nil)
	if err != nil { t.Fatal(err) }
	c, err := env.Start(scheme, os.Stderr)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = env.Stop() })

	ctx := context.Background()
	cp := &v1alpha1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "pool-a"}, Spec: v1alpha1.ClusterPoolSpec{Region: "eu"}}
	if err := c.Create(ctx, cp); err != nil { t.Fatalf("create: %v", err) }

	got := &v1alpha1.ClusterPool{}
	if err := c.Get(ctx, client.ObjectKey{Name: "pool-a"}, got); err != nil { t.Fatalf("get: %v", err) }
	if got.Spec.Region != "eu" { t.Fatalf("region = %q, want eu", got.Spec.Region) }

	list := &v1alpha1.ClusterPoolList{}
	if err := c.List(ctx, list); err != nil { t.Fatalf("list: %v", err) }
	if len(list.Items) != 1 { t.Fatalf("want 1 item, got %d", len(list.Items)) }
	_ = time.Second
}

// kitScheme builds the scheme the client + server share.
func kitScheme(t *testing.T) *runtimeScheme { /* see Step 3 helper */ return newKitScheme(t) }
```

(The `kitScheme`/`newKitScheme`/`runtimeScheme` helper is defined in Step 3 to keep this compiling; if apiserver-kit's envtest takes a `*runtime.Scheme` directly, use that type and drop the alias.)

- [ ] **Step 2: Run it — expect failure (no server main yet).**

Run: `cd /home/nik/Development/ironcore-net-xdp/central && go test ./test/ -run TestClusterPool -v 2>&1 | tail -20`
Expected: FAIL — build error (no `cmd/apiserver`) or env start error. (KUBEBUILDER_ASSETS must be set by the devShell; if the env can't find control-plane binaries, that's the known envtest requirement — ensure the devShell is active.)

- [ ] **Step 3: Write the apiserver entrypoint.** Create `central/cmd/apiserver/main.go` using the confirmed builder API (adapt names to Task 1 Step 2 findings):

```go
package main

import (
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"go.opendefense.cloud/kit/apiserver"
	platforminstall "github.com/trevex/ectobase/central/apis/platform/install"
	platform "github.com/trevex/ectobase/central/apis/platform"            // INTERNAL type (passed to Resource)
	v1alpha1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	openapi "github.com/trevex/ectobase/central/client-go/openapi"          // generated: GetOpenAPIDefinitions
)

func newScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	platforminstall.Install(scheme)
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
	return scheme
}

func main() {
	scheme := newScheme()
	code := apiserver.NewBuilder(scheme).
		WithComponentName("central-apiserver").
		WithGroupVersions(v1alpha1.SchemeGroupVersion).
		With(apiserver.Resource(&platform.ClusterPool{}, v1alpha1.SchemeGroupVersion)). // INTERNAL type, versioned GV (see example: Resource(&foo.Bar{}, v1alpha1.SchemeGroupVersion))
		WithOpenAPIDefinitions("central", "v0.1.0", openapi.GetOpenAPIDefinitions).
		Execute()
	os.Exit(code)
}
```

Then add the test scheme helper in `central/test/envtest_test.go` (replace the Step-1 placeholder helper):

```go
import (
	"k8s.io/apimachinery/pkg/runtime"
	platforminstall "github.com/trevex/ectobase/central/apis/platform/install"
)
type runtimeScheme = runtime.Scheme
func newKitScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	platforminstall.Install(s)
	return s
}
```

- [ ] **Step 4: Run the test — expect pass.**

Run: `cd /home/nik/Development/ironcore-net-xdp/central && go test ./test/ -run TestClusterPool -v 2>&1 | tail -25`
Expected: PASS — `ClusterPool` create/get/list succeed against the in-process aggregated server (embedded etcd). If `Execute()` needs flags that envtest doesn't supply, use `env.SetAPIServerExtraArgs(...)` (from Task 1 findings) to pass them.

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/cmd/apiserver/main.go central/test/envtest_test.go
git commit -m "feat(central): aggregated apiserver serving ClusterPool + envtest CRUD

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: kine → Postgres backend (durability, no etcd)

**Files:**
- Create: `central/hack/kine-up.sh`, `central/hack/kine-down.sh`, `central/test/kine_durability_test.go`

- [ ] **Step 1: kine+Postgres bring-up script.** Create `central/hack/kine-up.sh` — runs Postgres + kine in docker, kine listening on `127.0.0.1:2379` (etcd v3 endpoint) backed by Postgres. (Confirm the kine image tag exists; kine is `rancher/kine`.)

```bash
#!/usr/bin/env bash
set -euo pipefail
docker run -d --name central-pg -e POSTGRES_PASSWORD=kine -e POSTGRES_DB=kine -p 5432:5432 postgres:16
sleep 5
docker run -d --name central-kine --network host rancher/kine:v0.13.0 \
  --endpoint "postgres://postgres:kine@127.0.0.1:5432/kine?sslmode=disable" --listen-address 127.0.0.1:2379
echo "kine on 127.0.0.1:2379 (Postgres-backed)"
```
Create `central/hack/kine-down.sh`: `docker rm -f central-kine central-pg 2>/dev/null || true`.

- [ ] **Step 2: Write the durability test (manual/tagged).** Create `central/test/kine_durability_test.go` guarded by an env flag so it only runs when kine is up (not in normal CI). It: starts the apiserver process pointed at `--etcd-servers=http://127.0.0.1:2379`, creates a `ClusterPool`, restarts *the apiserver* (not kine), and asserts the object survives — proving durability lives in Postgres, not apiserver memory.

```go
//go:build kine
package test

import (
	"context"; "os"; "os/exec"; "testing"; "time"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	// ... client wiring to the local apiserver via a kubeconfig the script emits ...
)

func TestKineDurability(t *testing.T) {
	if os.Getenv("KINE_ENDPOINT") == "" { t.Skip("set KINE_ENDPOINT + run central/hack/kine-up.sh") }
	// 1. start apiserver --etcd-servers=$KINE_ENDPOINT (exec.Command), wait ready
	// 2. create ClusterPool pool-durable
	// 3. kill + restart the apiserver (same --etcd-servers)
	// 4. GET pool-durable -> must still exist
	_ = exec.Command; _ = context.Background; _ = time.Second; _ = metav1.ObjectMeta{}
	t.Fatal("fill in per the confirmed apiserver flag/kubeconfig surface from Task 3")
}
```

Note to executor: flesh this out using the exact server flags/kubeconfig from Task 3 (the `Execute()` flag surface). This is the one test that requires the local kine stack; keep it `//go:build kine` so default `go test` skips it.

- [ ] **Step 3: Run the durability test against kine.**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp/central
bash hack/kine-up.sh
KINE_ENDPOINT=http://127.0.0.1:2379 go test -tags kine ./test/ -run TestKineDurability -v 2>&1 | tail -25
bash hack/kine-down.sh
```
Expected: PASS — `pool-durable` survives an apiserver restart with kine/Postgres as the only persistence. This proves M1 (no etcd; durable non-etcd backend).

- [ ] **Step 4: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/hack/kine-up.sh central/hack/kine-down.sh central/test/kine_durability_test.go
git commit -m "test(central): kine/Postgres durability (no etcd) for the aggregated apiserver

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Selectable spec fields — upstream apiserver-kit PR + consume it

**Files:**
- Upstream (separate repo): `apiserver-kit` `apiserver/rest/rest.go`, `apiserver/rest/strategy.go`, `apiserver/builder.go` (+ tests)
- This repo: `central/internal/clusterpool/strategy.go`, `central/cmd/apiserver/main.go`, `central/test/envtest_test.go`

- [ ] **Step 1: Reproduce the gap (failing test).** Add a field-selector watch test to `central/test/envtest_test.go` that lists `ClusterPool` with `fields.OneTermEqualSelector("spec.region", "eu")`:

```go
func TestClusterPool_SpecFieldSelector(t *testing.T) {
	scheme := newKitScheme(t)
	env, err := kitenvtest.NewEnvironment("../cmd/apiserver", nil, nil)
	if err != nil { t.Fatal(err) }
	c, err := env.Start(scheme, os.Stderr)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = env.Stop() })
	ctx := context.Background()
	mk := func(name, region string) *v1alpha1.ClusterPool {
		return &v1alpha1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.ClusterPoolSpec{Region: region}}
	}
	if err := c.Create(ctx, mk("a", "eu")); err != nil { t.Fatal(err) }
	if err := c.Create(ctx, mk("b", "us")); err != nil { t.Fatal(err) }
	list := &v1alpha1.ClusterPoolList{}
	if err := c.List(ctx, list, client.MatchingFields{"spec.region": "eu"}); err != nil { t.Fatalf("field list: %v", err) }
	if len(list.Items) != 1 || list.Items[0].Name != "a" { t.Fatalf("want [a], got %+v", list.Items) }
}
```

Run: `go test ./test/ -run SpecFieldSelector -v` → Expected: FAIL (`field label not supported: spec.region`), confirming apiserver-kit's hardcoded `GetAttrs` (name/namespace only).

- [ ] **Step 2: Upstream the selectable-fields hook in apiserver-kit.** Clone the fork and implement the scoped change identified in research:

```bash
cd /home/nik/Development/ironcore-net-xdp/hack
git clone https://github.com/opendefensecloud/apiserver-kit && cd apiserver-kit && git checkout -b feat/selectable-spec-fields
```
Changes (backward-compatible, additive):
1. `apiserver/rest/strategy.go`: define an optional interface a type or strategy can implement — `type SelectableFieldsProvider interface { SelectableFields(obj runtime.Object) fields.Set }`.
2. `apiserver/rest/rest.go`: change `GetAttrs` to merge `generic.ObjectMetaFieldsSet(om, true)` with the provider's fields when the object (or the store's strategy) implements `SelectableFieldsProvider`; keep name/namespace-only default otherwise.
3. Thread it: `DefaultStrategy.Match` already carries the strategy — use a strategy-carried attr func so `NewStore`'s `AttrFunc` and `Match` use the merged function (no `NewStore` signature change).
4. Add a builder/registration hook to register `scheme.AddFieldLabelConversionFunc(gvk, fn)` for the type's selectable fields (so the apiserver accepts the selector). Expose via `Resource[...]` options or a `Builder.WithFieldLabelConversion(...)`.
5. Add an upstream unit test proving a `spec.X` selector works.

Push the branch and open a PR against `opendefensecloud/apiserver-kit`. Point `central/go.mod` at the branch temporarily via `replace go.opendefense.cloud/kit => ../hack/apiserver-kit` for local dev, to be swapped to the tagged release once merged.

```bash
cd /home/nik/Development/ironcore-net-xdp/central
go mod edit -replace go.opendefense.cloud/kit=../hack/apiserver-kit
go mod tidy
```

- [ ] **Step 3: Consume it — custom ClusterPool strategy exposing `spec.region`.** Create `central/internal/clusterpool/strategy.go` implementing `SelectableFieldsProvider` (per the exact upstream interface merged in Step 2):

```go
package clusterpool

import (
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	v1alpha1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

// SelectableFields exposes spec.region for field-selector watches (the binding-field
// mechanism the broker will use with spec.clusterName on compiled types in Phase 2).
func SelectableFields(obj runtime.Object) fields.Set {
	cp, ok := obj.(*v1alpha1.ClusterPool)
	if !ok { return nil }
	return fields.Set{"spec.region": cp.Spec.Region}
}
```

Wire it into the server (the exact wiring depends on the merged hook — either implement the interface on a custom strategy passed via `apiserver.Resource(...)` options, or register `SelectableFields` + the field-label conversion in `main.go`). Update `central/cmd/apiserver/main.go` accordingly.

- [ ] **Step 4: Run the field-selector test — expect pass.**

Run: `cd /home/nik/Development/ironcore-net-xdp/central && go test ./test/ -run "SpecFieldSelector|CRUDAndWatch" -v 2>&1 | tail -25`
Expected: PASS — both the CRUD test and the `spec.region` field-selector list. This proves the pod→node binding mechanism (M3) end-to-end on our stack.

- [ ] **Step 5: Commit (this repo) + note the upstream PR.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/internal/clusterpool/strategy.go central/cmd/apiserver/main.go central/test/envtest_test.go central/go.mod central/go.sum
git commit -m "feat(central): selectable spec.region field selector (consumes apiserver-kit hook)

Requires apiserver-kit PR (selectable-fields hook); using a local replace until merged.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Deployment manifests + a minimal ClusterPool controller (single-cluster smoke)

**Files:**
- Create: `central/config/apiservice.yaml`, `central/config/deployment.yaml`, `central/config/kine.yaml`
- Create: `central/internal/clusterpool/controller.go`, `central/cmd/controller/main.go`, `central/test/controller_test.go`

- [ ] **Step 1: A trivial ClusterPool controller (TDD).** Prove a controller can reconcile against the aggregated apiserver: on `ClusterPool` create, set `status.phase = "Pending"`. Write `central/test/controller_test.go` (envtest) that creates a `ClusterPool` and asserts `status.phase` becomes `Pending`.

```go
func TestClusterPoolController_SetsPending(t *testing.T) {
	// start envtest aggregated server; run the reconciler; create pool; Eventually status.phase == "Pending"
}
```
Run → FAIL (no controller).

- [ ] **Step 2: Implement the reconciler** in `central/internal/clusterpool/controller.go` (controller-runtime, watching `ClusterPool`, patching status), and a `central/cmd/controller/main.go` manager entrypoint. Run the test → PASS. (This proves the aggregated apiserver supports the standard controller-runtime informer/watch/patch path controllers need — the foundation Phase 2's scheduler/failover controllers rely on.)

- [ ] **Step 3: Deployment manifests.** Create `central/config/` with: `kine.yaml` (kine+Postgres), `deployment.yaml` (the central-apiserver Deployment, `--etcd-servers` → kine Service), `apiservice.yaml` (the `APIService` registering `v1alpha1.platform.ectobase.dev` with the kube-aggregator). Validate they render: `kubectl kustomize central/config` (or `kubectl apply --dry-run=client -f`).

- [ ] **Step 4: Single-cluster smoke on kind (the §9 invariant gate).** Bring up a plain kind cluster, deploy kine + central-apiserver + APIService, and confirm `kubectl get clusterpools.platform.ectobase.dev` works and a created ClusterPool gets `status.phase: Pending`. Document the commands in `central/hack/smoke.sh`.

Run: `bash central/hack/smoke.sh 2>&1 | tail -20`
Expected: `clusterpools` served by the aggregated apiserver in a real cluster; controller sets Pending. (This is the standing single-cluster acceptance test for the foundation.)

- [ ] **Step 5: Commit.**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/internal/clusterpool/controller.go central/cmd/controller/main.go central/test/controller_test.go central/config central/hack/smoke.sh
git commit -m "feat(central): ClusterPool controller + deploy manifests + single-cluster smoke

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Update memory + phase-1 wrap

- [ ] **Step 1: Full build + test.**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
(cd central && go build ./... && go test ./... 2>&1 | grep -vE "no test files" | tail -15)
```
Expected: build clean; envtest CRUD + field-selector + controller tests PASS (kine durability is `//go:build kine`, run separately).

- [ ] **Step 2: Update memory.** Create/update a memory `central-apiserver-foundation`: apiserver-kit v0.3.4 on kine/Postgres proven; selectable-fields hook upstreamed (PR link + whether merged / still on local `replace`); ClusterPool served + controller reconciles; single-cluster smoke green; the exact codegen invocation; the kine-durability test is `//go:build kine`. Cross-link `[[multicluster-kubevirt-platform]]` and the 2026-08-01 spec. Add the MEMORY.md index line. Note the OPEN follow-ups: swap the apiserver-kit `replace` for a tagged release once the PR merges; Phase 1b (migrate net.ectobase.dev types + repoint compiler); Phase 2 (broker).

- [ ] **Step 3: Finish the branch** via superpowers:finishing-a-development-branch (merge to main or PR).

---

## Notes for the executor

- **This phase is additive** — it must not modify or break the existing `netplane`/`flowplane`/`api` single-cluster system. Everything lives under `central/` + one `go.work` line + the upstream apiserver-kit PR.
- **apiserver-kit is pre-1.0**; Task 1 Step 2 confirms real signatures before code. Where this plan's sketches differ from the resolved source, adapt — the shapes are from a web research brief, high-confidence but not compiler-verified.
- **envtest needs KUBEBUILDER_ASSETS** (nix devShell — already active in this environment for the existing controller envtests).
- **Run git-mutating tasks sequentially** (the DPDK-backlog lesson: parallel git subagents corrupt the tree). The upstream apiserver-kit PR is in a **separate clone** under `hack/apiserver-kit` (not this repo's tree) — push it to the fork, don't commit it here; the local `replace` directive is the only footprint in this repo until it merges.
- **Gate to Phase 1b/2:** do not migrate `net.ectobase.dev` types or repoint the compiler in this plan; that's the next spec/plan, and it depends on this foundation (esp. the selectable-fields PR) being merged/stable.
