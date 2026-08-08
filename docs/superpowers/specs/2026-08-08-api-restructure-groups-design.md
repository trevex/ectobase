# API Restructure: Group Split + Single-Module Types + Generated Conversions

**Status:** Approved design (2026-08-08). Execution in three landable rounds.

**Goal:** Reorganize the ectobase API surface so that all Kubernetes API types live in one consistent place (the shared `api/` module), split across five domain-scoped API groups, with all internal↔external conversions *generated* (never hand-written), while keeping the shared `api/` module dependency-light and the aggregated apiserver the sole importer of apiserver-kit.

**Architecture:** Adopt the opendefensecloud/solution-arsenal (SolAr) convention — colocated internal (`api/<group>/`) and external (`api/<group>/v1alpha1/`) real structs with `kube::codegen`-generated deepcopy/conversion/defaults — but adapted to ectobase's multi-module reality so the shared `api/` module stays apimachinery-only. `central/apis/` is deleted; `central/internal/*` becomes `central/pkg/*`.

**Tech Stack:** Go, k8s.io/apimachinery, k8s.io/code-generator (`kube_codegen.sh`: gen_helpers/gen_openapi/gen_client), controller-gen (CRDs/RBAC), go.opendefense.cloud/kit (apiserver-kit), controller-runtime, Helm.

---

## 1. Motivation & Current State

Today the API surface has two problems the team wants fixed together:

1. **Idiom inconsistency.** Wire types live in the top-level `api/` module (`api/v1alpha1`, group `net.ectobase.dev`), but the aggregated apiserver keeps a *parallel* set under `central/apis/{net,platform}` (internal hub types + external `v1alpha1` **aliases** back to `api/v1alpha1` + hand-written conversions + REST). "`api` at the top, `apis` in central" is confusing, and the alias trick is what forces hand-written conversions (conversion-gen cannot convert a type to its own alias — the "CP.2a caveat").

2. **One overloaded group.** `net.ectobase.dev` currently holds 14 types spanning networking, workloads, storage, and controller-emitted compiled objects. That defeats RBAC scoping, blurs the "who may author `Compiled*`" boundary, and raises cognitive load.

Additionally, `CompiledWorkload` (in `platform.ectobase.dev`) is **dead**: no broker sync, no scheduler, no controller, no netplane use. Its only reference is one envtest (`TestCompiledWorkload_SpecClusterNameSelector`) proving the generic `spec.clusterName` field-selector plumbing — which is now independently proven against the real apiserver by `TestCompiledNIC/VM/VolumeAttachment_SpecClusterNameSelector` (net_envtest_test.go) and the real broker↔apiserver sync (phase1b_e2e_test.go). Dropping it loses no coverage.

### Reference: how SolAr does it

SolAr is the same authors' flagship use of apiserver-kit and is the canonical convention:

- **Colocated internal + external real structs** (`api/solar/` + `api/solar/v1alpha1/`), field-identical, with **generated** `zz_generated.conversion.go`. No aliases, no hand-written conversions. They keep the internal type even with a single version — the kit is built to want an internal hub, and they go with the grain.
- **No `internal/` packages.** Controllers live in `pkg/controller/`. "Avoid internal packages" ⇒ use `pkg/`.
- **One `hack/update-codegen.sh`** driving `kube::codegen` (gen_helpers → deepcopy+conversion+defaults, gen_openapi, gen_client `--with-watch --with-applyconfig`) plus controller-gen for CRDs/RBAC.
- **`cmd/<component>/main.go` per binary** (apiserver, controller-manager, …).

SolAr is a *single* module, which lets apiserver-kit bleed into its `api/solar` package. ectobase is deliberately multi-module (`netplane`/`cni`/`test` deploy separately from the apiserver and must import only lightweight wire types), so we adapt the convention to keep `api/` framework-free.

## 2. Key Insight: `api/` Can Hold Storage Types *and* Stay apimachinery-only

The internal ("storage") types must implement the kit's `resource.Object` interface (`New`/`NewList`/`GetGroupResource`/`NamespaceScoped`/`GetObjectMeta`) and optionally `SelectableFieldsProvider`/`SupportedFieldSelectorsProvider`. **Every one of those methods is apimachinery-typed** (`runtime.Object`, `schema.GroupResource`, `fields.Set`, `[]string`, `*metav1.ObjectMeta`). None return a kit type.

The kit interfaces are **structural** — a type satisfies them by having the methods, with no import. In the current `central/apis/*_rest.go`, the *only* references to `go.opendefense.cloud/kit` are four belt-and-suspenders assertion lines per type:

```go
var (
	_ resource.Object                         = &CompiledNIC{}
	_ resource.ObjectWithStatusSubResource    = &CompiledNIC{}
	_ kitrest.SelectableFieldsProvider        = &CompiledNIC{}
	_ kitrest.SupportedFieldSelectorsProvider = &CompiledNIC{}
)
```

**Dropping those assertions makes the type packages 100% apimachinery-only** — even when they hold the internal/storage types. The compile-time guarantee is not lost: it moves to the registration site, where the kit's generic

```go
apiserver.Resource[E resource.Object, T resource.ObjectWithDeepCopy[E]](&netapi.CompiledNIC{}, gv)
```

instantiates a generic *constrained* to `resource.Object`. If a type stops satisfying the interface, `central/cmd/apiserver` fails to compile. Same safety, better-placed.

**Consequence:** no module restructure is needed. `api/` remains a single shared module depending only on `k8s.io/apimachinery`; `central` remains the sole importer of apiserver-kit (in `cmd/apiserver`, via the `Resource(...)` calls that already do the store/strategy wiring). This is *cleaner than SolAr* for our layout — the framework dependency is contained to the one binary that runs the apiserver, and `netplane`/`cni`/`broker` import `api/<group>/v1alpha1` with zero kit in their graph (not by relying on module-graph pruning, but because the dependency genuinely is not there).

## 3. Target Architecture

### 3.1 Package layout

```
api/                              module github.com/trevex/ectobase/api  (apimachinery-only)
  net/                            internal, group net.ectobase.dev
    vpc_types.go … vpcpeering_types.go        internal structs
    *_rest.go                                  resource.Object methods + SelectableFields (NO kit import)
    register.go doc.go helpers.go
    fuzzer/ install/
    zz_generated.deepcopy.go
    v1alpha1/                     external — imported by netplane/cni/broker
      *_types.go                               real structs (no aliases)
      register.go defaults.go doc.go
      zz_generated.{deepcopy,conversion,defaults,model_name}.go
  compute/    VirtualMachine, Container                         (+ v1alpha1/)  same shape
  storage/    Volume                                            (+ v1alpha1/)  same shape
  compiled/   CompiledNIC, CompiledVM, CompiledContainer,
              CompiledVolumeAttachment                          (+ v1alpha1/)  same shape
  platform/   ClusterPool                                       (+ v1alpha1/)  same shape
  hack/update-codegen.sh, boilerplate.go.txt, use-local-modules.sh, bin/.modules/
central/
  cmd/{apiserver,controller,broker}/main.go   registers api/<group> internal types via the kit builder
  pkg/{broker,scheduler,clusterpool,clusterrestriction,failover,fence}/   (was central/internal/*)
  client-go/                      generated clientset/informers/listers/openapi over api/
netplane/, cni/, test/*           import path updates only: api/v1alpha1 → api/{net,compute,storage,compiled}/v1alpha1
```

`central/apis/` is deleted entirely.

### 3.2 Group mapping

| Group | Types |
|---|---|
| `net.ectobase.dev` | VPC, NetworkInterface, FirewallPolicy, FloatingIP, LoadBalancer, NATGateway, VPCPeering |
| `compute.ectobase.dev` | VirtualMachine, Container |
| `storage.ectobase.dev` | Volume |
| `compiled.ectobase.dev` | CompiledNIC, CompiledVM, CompiledContainer, CompiledVolumeAttachment |
| `platform.ectobase.dev` | ClusterPool |

Rationale: all controller-emitted `Compiled*` live together in `compiled.` (keeps the "gate authoring of `Compiled*`" RBAC boundary crisp); only the user-authored `Volume` spec goes to `storage.` — its compiled counterpart `CompiledVolumeAttachment` stays in `compiled.`. `CompiledWorkload` is removed.

### 3.3 Dependency invariants (must hold after every round)

- `api/` depends only on `k8s.io/apimachinery` (+ test-only codegen deps: randfill/openapi in generated files). It never imports `go.opendefense.cloud/kit` or `k8s.io/apiserver`.
- `central` is the only module importing apiserver-kit, and only in `cmd/apiserver` (registration) — not in `pkg/` controllers.
- `netplane`/`cni`/`test` import only `api/<group>/v1alpha1`.
- No hand-written conversions anywhere. `zz_generated.conversion.go` per external group, produced by `conversion-gen` via `kube::codegen::gen_helpers`.

## 4. Codegen

One `api/hack/update-codegen.sh` (SolAr-shaped), run from the `api` module:

- `kube::codegen::gen_helpers ./api/...` → deepcopy + **conversion** + defaults into the api packages. Because external structs are real (not aliases), conversion-gen emits `zz_generated.conversion.go` for every group; the previous hand-written `central/apis/net/v1alpha1/conversion.go` is deleted.
- `kube::codegen::gen_openapi` → openapi definitions (consumed by the apiserver).
- `kube::codegen::gen_client --with-watch --with-applyconfig` → clientset/listers/informers/applyconfigurations.
- controller-gen → per-group CRDs (`config/crd/bases/<group>_<plural>.yaml`) and RBAC.
- Carry over the existing `use-local-modules.sh` + `bin/.modules` chmod workaround for openapi-gen.

**Generated client-go/openapi location:** stays under `central/client-go` (regenerated from the api packages cross-module via go.work), so the api module keeps zero client-go/openapi runtime deps. gen_helpers still writes the `zz_generated.*` *type helpers* into the api packages (they are apimachinery-only). This split — helpers in `api/`, clientset/openapi in `central/` — preserves the api dependency invariant. (If a later round wants the clientset in `api/client-go`, that is a separate decision; not in scope here.)

## 5. Phased Migration (three rounds)

Each round is independently landable, must keep the full build + all envtests green, and passes a code review before the next begins. The live clab acceptance sweep runs at least at the end of R3 (and after R2 if convenient).

### R1 — Mechanical prep (no behavior change)

1. `central/internal/*` → `central/pkg/*` (broker, scheduler, clusterpool, clusterrestriction, failover, fence). Pure directory move + import-path updates within the `central` module. No `internal/` remains in `central`.
2. Drop `CompiledWorkload`: delete `central/apis/platform/{compiledworkload_types,compiledworkload_rest}.go`, `central/apis/platform/v1alpha1/compiledworkload_types.go`, its registrations (`register.go` ×2, `cmd/apiserver/main.go`), the `TestCompiledWorkload_SpecClusterNameSelector` envtest, the stale clusterrestriction comment, and regenerate client-go/openapi (removing the compiledworkload informers/listers/clientset).

Green gate: `central` builds + `go test ./...` (central) pass; no other module touched.

### R2 — Unify + generate (groups unchanged)

Move the `central/apis/{net,platform}` type system into `api/{net,platform}` under the new structure, still using the existing two groups (`net.ectobase.dev`, `platform.ectobase.dev`). This proves the new colocated-real-struct + generated-conversion + apimachinery-only-`api` structure *before* any group boundaries move.

1. In `api/`, create `api/net/` (internal) + `api/net/v1alpha1/` (external real structs, migrated from today's `api/v1alpha1` + the central internal hub), and `api/platform/` likewise from `central/apis/platform`.
2. Drop the alias packages and the four kit interface-assertion lines per type; move the `resource.Object` compile-time proof to `central/cmd/apiserver`'s `Resource(...)` generic calls.
3. Stand up `api/hack/update-codegen.sh`; generate deepcopy/conversion/defaults into `api/`, and client-go/openapi into `central/client-go`.
4. Update every consumer import (`api/v1alpha1` → `api/net/v1alpha1`; central internal-type imports → `api/net`), delete `central/apis/`.
5. Keep CRDs/RBAC/goldens byte-stable except for the path/package churn (groups have not changed, so `net.ectobase.dev_*.yaml` names are unchanged).

Green gate: all modules build; central + netplane envtests pass; `api/` imports no kit/apiserver (assert via `go list`/grep in CI); no hand-written conversion files remain.

### R3 — Group split

Carve `compute.`, `storage.`, and `compiled.` out of `net.` (and confirm `platform.`).

1. Move the type files into `api/{compute,storage,compiled}/(v1alpha1/)`, each with its own `GroupName`/`SchemeGroupVersion`/register/install/fuzzer and controller-gen `+groupName` marker.
2. Update every `TypeMeta{APIVersion: "net.ectobase.dev/v1alpha1"}` the compiler emits (e.g. `CompileContainer`, CompiledNIC/VM/VolumeAttachment emit paths) to the correct new group.
3. Update all ~73 consumer files (netplane controllers/agent, cni, central/test, central pkg) to the new per-group import paths.
4. Regenerate: per-group CRDs (`config/crd/bases/{compute,storage,compiled,net,platform}.ectobase.dev_*.yaml`), `sync-chart-crds.sh` output, and `deploy/charts/ectobase/crd-bases`.
5. Update RBAC per group: split the netplane-controller / netplane-agent / central-broker ClusterRole `apiGroups` blocks across `net./compute./storage./compiled.`, re-sync the `config/deploy/rbac.yaml` golden, and bump `deploy/charts/ectobase/tests/render.sh` expectations (CRD count unchanged at 14, but grouping/goldens change).
6. Register each group in `central/cmd/apiserver/main.go` via `apiserver.Resource(&<group>.<Type>{}, <group>v1.SchemeGroupVersion)` (the kit already serves multiple groups — no kit change needed).

Green gate: all modules build; full central + netplane envtests pass; live clab acceptance sweep (`lab down→up→ceph→tier2→test`) green — the same suite used for the container-workload feature (TestPodOverlayPing / TestVPCPeering / TestLbDistributeSmoke / TestDhcpLeaseSmoke / TestTier2Failover, with the known ceph-disk caveat on aged fabrics).

## 6. Testing & Validation

- **Roundtrip fuzz** (`api/<group>/install/roundtrip_test.go`) per group — now guards *generated* conversions instead of hand-written ones.
- **Field-selector envtests** retained per compiled type (real apiserver): `spec.clusterName` selectors the broker relies on.
- **CI invariant check:** a small script/test asserting `api/` transitively imports neither `go.opendefense.cloud/kit` nor `k8s.io/apiserver`, and that `central/pkg/*` imports no kit.
- **Chart goldens:** `make chart-test` / `render.sh` updated for per-group CRDs + RBAC; `config/deploy/*.yaml` goldens re-synced from the chart.
- **Live sweep** at end of R3 (and optionally R2).

## 7. Risks & Mitigations

- **Import-path churn (~73 files).** Mechanical; done per-round with compiler as the guide. R2/R3 separation keeps each diff reviewable.
- **conversion-gen cross-module.** gen_helpers writes into `api/` (same module as the types) — no cross-module conversion. Only client-go/openapi are generated cross-module into `central`, which is already how central operates today.
- **RBAC drift → silent forbidden informers.** Learned from the container-workload feature: envtests pass without RBAC, but deployed controllers need per-group `apiGroups`. R3 explicitly updates chart RBAC + goldens, and the live sweep catches regressions.
- **Compiled object `apiVersion` strings.** The compiler hardcodes `net.ectobase.dev/v1alpha1` in several emit paths; R3 must update each to its new group, verified by envtest (broker sync + materialize chains) and the live sweep.

## 8. Out of Scope

- **Renaming `central`** (candidates: fleet/hub/apex) — deferred to a follow-up round by explicit user decision.
- **`storage.` controller logic** — this effort only relocates `Volume` into the `storage.` group; no new storage behavior.
- **A-lean / self-converting single-version resources** — rejected; we keep internal+external with generated conversions per the SolAr convention.
- **apiserver-kit changes** — none required; it already serves multiple groups via `apiserver.Resource(obj, gv)`.
