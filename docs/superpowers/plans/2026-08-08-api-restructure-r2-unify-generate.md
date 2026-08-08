# API Restructure — R2 (Unify + Generate) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move both API type systems (`central/apis/{net,platform}`) into the shared `api/` module as colocated internal (`api/<group>/`) + external (`api/<group>/v1alpha1/`) real structs with **generated** conversions, delete the alias hack + the 2210-line hand-written `net` conversion.go + the kit interface-assertions, make `api/` apimachinery-only, and repoint every consumer — all with the two groups **unchanged** (`net.ectobase.dev`, `platform.ectobase.dev`).

**Architecture:** `platform` is the pilot: it already uses real external structs + generated conversion, so moving it proves the api-module `kube::codegen` pipeline + the apimachinery-only invariant on one small type (ClusterPool) before the large `net` move. `net` then applies the proven recipe and additionally deletes the alias/hand-written-conversion tech debt: today's real external structs live in `api/v1alpha1` (moved to `api/net/v1alpha1`), and the field-identical internal structs live in `central/apis/net` (moved to `api/net`), so once both are real structs in one module, `conversion-gen` generates what was hand-written.

**Tech Stack:** Go (modules `api` and `central`, go.work + `central` replace `../api`), k8s.io/code-generator `kube_codegen.sh` (`gen_helpers` = deepcopy+conversion+defaults; `gen_openapi`; `gen_client`), controller-gen (CRDs), go.opendefense.cloud/kit (apiserver-kit — must remain a `central`-only import). Go tooling runs in the nix devShell: `nix develop --command bash -c '<cmd>'`. `central` builds with `GOWORK=off`.

**Branch:** Continue on `feat/api-restructure` (R1 landed at `3dd6373`).

**Key facts established during planning:**
- `central/apis/platform/v1alpha1` already has REAL structs + generated `zz_generated.conversion.go` (doc.go carries `+k8s:conversion-gen=github.com/trevex/ectobase/central/apis/platform`). This is the target pattern.
- `central/apis/net/v1alpha1` is the ALIAS hack: `aliases.go` re-exports `api/v1alpha1`, `conversion.go` is 2210 hand-written lines, doc.go has NO conversion-gen marker. All to be deleted.
- The `net` internal structs (`central/apis/net`) are field-identical to the external `api/v1alpha1` structs (the hand-written conversions are field-identity copies; e.g. `CompiledNIC.ClusterName` exists in `api/v1alpha1`). So the move is a clean two-real-struct-sets outcome that conversion-gen can bridge.
- The only apiserver-kit references in the `*_rest.go` files are four interface-assertion lines per type (`_ resource.Object = &X{}`, `_ resource.ObjectWithStatusSubResource`, `_ kitrest.SelectableFieldsProvider`, `_ kitrest.SupportedFieldSelectorsProvider`). Every method is apimachinery-typed. Dropping the assertions (and their two kit imports) makes the package apimachinery-only; the compile-time proof is preserved by central's `apiserver.Resource[E resource.Object,...](&X{}, gv)` generic calls in `central/cmd/apiserver/main.go`.
- `central/hack/update-codegen.sh` currently runs `gen_helpers` + `gen_openapi` + `gen_client` over `central/apis`; the root `Makefile` `generate` target runs `controller-gen object` + `controller-gen crd` over `api/v1alpha1`.

---

## File Structure (target after R2)

```
api/
  platform/                         group platform.ectobase.dev
    clusterpool_types.go clusterpool_rest.go   (internal; rest = apimachinery-only, kit assertions removed)
    doc.go register.go
    fuzzer/fuzzer.go install/install.go install/roundtrip_test.go
    zz_generated.deepcopy.go
    v1alpha1/
      clusterpool_types.go doc.go register.go defaults.go
      zz_generated.{deepcopy,conversion,defaults,model_name}.go
  net/                              group net.ectobase.dev  (ALL 14 net types)
    <type>_types.go <type>_rest.go  (internal; kit assertions removed)
    common_types.go doc.go register.go helpers (if any)
    fuzzer/fuzzer.go install/install.go install/roundtrip_test.go
    zz_generated.deepcopy.go
    v1alpha1/
      <type>_types.go annotations.go common_types.go doc.go register.go defaults.go
      zz_generated.{deepcopy,conversion,defaults,model_name}.go
  hack/update-codegen.sh boilerplate.go.txt          (gen_helpers over api/)
  (api/v1alpha1/ is DELETED — its structs moved to api/net/v1alpha1/)
central/
  apis/                             DELETED entirely
  hack/update-codegen.sh            gen_openapi + gen_client repointed to read ../api, output central/client-go
  cmd/apiserver/main.go             imports api/{net,platform} internal + their SchemeGroupVersions
  client-go/**                      regenerated for api types
consumers (import path updates):
  api/v1alpha1                 -> api/net/v1alpha1        (netplane, cni, central/pkg, central/test, central/cmd)
  central/apis/net             -> api/net
  central/apis/net/install     -> api/net/install
  central/apis/net/v1alpha1    -> api/net/v1alpha1
  central/apis/platform        -> api/platform
  central/apis/platform/install-> api/platform/install
  central/apis/platform/v1alpha1-> api/platform/v1alpha1
```

---

## Task 1: Platform pilot — move `central/apis/platform` → `api/platform`, prove api-module codegen

**Goal:** Relocate the small `platform` group into `api/` under the SolAr shape, stand up `api/hack/update-codegen.sh`, repoint central's client-go generation + apiserver + consumers, delete `central/apis/platform`. This proves the codegen pipeline before the big `net` move.

**Files:**
- Create: `api/platform/` (from `central/apis/platform/`), `api/platform/v1alpha1/`, `api/platform/install/`, `api/platform/fuzzer/`, `api/hack/update-codegen.sh`, `api/hack/boilerplate.go.txt`
- Modify: `central/hack/update-codegen.sh`, `central/cmd/apiserver/main.go`, and every `central` file importing `central/apis/platform*`
- Delete: `central/apis/platform/` (whole tree)

- [ ] **Step 1: Baseline green**

Run:
```bash
nix develop --command bash -c 'cd central && GOWORK=off go build ./... && GOWORK=off go test ./test/ -run TestClusterPool -count=1'
```
Expected: build exit 0; `ok github.com/trevex/ectobase/central/test`.

- [ ] **Step 2: Relocate the platform tree into api/ with git mv**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
mkdir -p api/platform
git mv central/apis/platform/clusterpool_types.go        api/platform/clusterpool_types.go
git mv central/apis/platform/clusterpool_rest.go         api/platform/clusterpool_rest.go
git mv central/apis/platform/doc.go                      api/platform/doc.go
git mv central/apis/platform/register.go                 api/platform/register.go
git mv central/apis/platform/zz_generated.deepcopy.go    api/platform/zz_generated.deepcopy.go
git mv central/apis/platform/fuzzer                       api/platform/fuzzer
git mv central/apis/platform/install                      api/platform/install
git mv central/apis/platform/v1alpha1                     api/platform/v1alpha1
rmdir central/apis/platform 2>/dev/null || true
```

- [ ] **Step 3: Rewrite platform import paths across the repo**

The package import path `github.com/trevex/ectobase/central/apis/platform` → `github.com/trevex/ectobase/api/platform` everywhere (central + tests). Package names are unchanged.

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
grep -rlZ 'trevex/ectobase/central/apis/platform' --include='*.go' . \
  | xargs -0 sed -i 's#trevex/ectobase/central/apis/platform#trevex/ectobase/api/platform#g'
grep -rn 'central/apis/platform' --include='*.go' . || echo "OK: no central/apis/platform refs remain"
```
Expected: `OK: no central/apis/platform refs remain`.

- [ ] **Step 4: Drop the kit interface-assertions from `api/platform/clusterpool_rest.go`**

Remove the two kit imports and the assertion block so the package is apimachinery-only. Delete these lines from the import block:
```go
	"go.opendefense.cloud/kit/apiserver/resource"
	kitrest "go.opendefense.cloud/kit/apiserver/rest"
```
And delete the entire assertion `var (...)` block:
```go
var (
	_ resource.Object                         = &ClusterPool{}
	_ resource.ObjectWithStatusSubResource    = &ClusterPool{}
	_ kitrest.SelectableFieldsProvider        = &ClusterPool{}
	_ kitrest.SupportedFieldSelectorsProvider = &ClusterPool{}
)
```
Leave all the methods (`GetObjectMeta`, `NamespaceScoped`, `New`, `NewList`, `GetGroupResource`, `CopyStatusTo`, `SelectableFields`, `SupportedFieldSelectors`) intact — they use only apimachinery types.

- [ ] **Step 5: Point the conversion-gen marker at the new internal package**

Edit `api/platform/v1alpha1/doc.go`: change the conversion-gen marker line
```go
// +k8s:conversion-gen=github.com/trevex/ectobase/central/apis/platform
```
to
```go
// +k8s:conversion-gen=github.com/trevex/ectobase/api/platform
```
(Leave the other markers — openapi-gen, deepcopy-gen, defaulter-gen, prerelease-lifecycle-gen, groupName, openapi-model-package — unchanged.)

- [ ] **Step 6: Create `api/hack/boilerplate.go.txt`**

Run (copy central's boilerplate verbatim so generated headers match):
```bash
cd /home/nik/Development/ironcore-net-xdp
mkdir -p api/hack
cp central/hack/boilerplate.go.txt api/hack/boilerplate.go.txt
```

- [ ] **Step 7: Create `api/hack/update-codegen.sh` (gen_helpers over api/)**

Create `api/hack/update-codegen.sh` with this content (adapted from `central/hack/update-codegen.sh`; only `gen_helpers` — deepcopy + conversion + defaults — belongs in the module that owns the types; openapi/client stay in central):
```bash
#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$SCRIPT_DIR/.."

(cd "$PROJECT_DIR" && go mod download k8s.io/code-generator)
CODEGEN_PKG=$(cd "$PROJECT_DIR" && go list -m -f '{{.Dir}}' k8s.io/code-generator)
# shellcheck disable=SC1091
source "${CODEGEN_PKG}/kube_codegen.sh"

kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_DIR}/boilerplate.go.txt" \
    "${PROJECT_DIR}"
```
Make it executable:
```bash
chmod +x api/hack/update-codegen.sh
```
Note: `k8s.io/code-generator` will be added to `api/go.mod` by `go mod download`/`go mod tidy`. This is a build-time tool dependency; no `api` source package imports it, so the apimachinery-only-at-runtime invariant (checked in Task 3) is about kit/apiserver imports, not code-generator.

- [ ] **Step 8: Repoint central's client-go/openapi generation to also read the moved platform group**

IMPORTANT ordering note: at this point `net` still lives in `central/apis/net` (it moves in Task 2). So central's client-go/openapi must cover BOTH the still-central `net` group AND the moved `api/platform` group. Do NOT repoint solely to `../api` yet — that happens in Task 2 once `net` has moved.

Edit `central/hack/update-codegen.sh`:
- Leave the top `gen_helpers "${PROJECT_DIR}/apis"` block as-is for now (it regenerates the still-central `net` helpers; harmless that platform is gone from there). `api/hack/update-codegen.sh` generates the platform helpers.
- On the `gen_openapi` call: change the `--extra-pkgs "github.com/trevex/ectobase/api/v1alpha1"` line to `--extra-pkgs "github.com/trevex/ectobase/api/platform/v1alpha1"` (net's external is still api/v1alpha1 → keep that extra-pkg too; add the platform one). Concretely the gen_openapi should carry BOTH `--extra-pkgs "github.com/trevex/ectobase/api/v1alpha1"` and `--extra-pkgs "github.com/trevex/ectobase/api/platform/v1alpha1"`, and its input dir stays `"${PROJECT_DIR}/apis"` (still holds net) PLUS add `"${PROJECT_DIR}/../api/platform"`.
- On the `gen_client` call: change the single input dir `"${PROJECT_DIR}/apis"` to two inputs: `"${PROJECT_DIR}/apis" "${PROJECT_DIR}/../api/platform"`.
- Keep the `use-local-modules.sh` chmod workaround block.

(Task 2 collapses these back to a single `"${PROJECT_DIR}/../api"` input and removes the central `gen_helpers` block once `net` has moved and `central/apis` is gone.)

- [ ] **Step 9: Generate — helpers (api) then client/openapi (central)**

Run:
```bash
nix develop --command bash -c 'cd api && ./hack/update-codegen.sh'
nix develop --command bash -c 'cd central && ./hack/update-codegen.sh'
```
Expected: both exit 0. `api/platform/**/zz_generated.*` regenerate in place; `central/client-go/**` + `central/client-go/openapi/zz_generated.openapi.go` regenerate for the new `api/platform` import paths. **Verify the pipeline works:** confirm `api/platform/v1alpha1/zz_generated.conversion.go` exists and references `platform "github.com/trevex/ectobase/api/platform"` (the new internal path), not the old central path:
```bash
grep -q 'trevex/ectobase/api/platform"' api/platform/v1alpha1/zz_generated.conversion.go && echo "OK conversion regenerated" || echo "!! conversion did not regenerate correctly"
```
Expected: `OK conversion regenerated`. If it prints the failure, STOP and report — the cross-module codegen recipe needs adjustment before continuing (do not hand-edit generated files).

- [ ] **Step 10: Update `central/cmd/apiserver/main.go` platform imports**

The import rewrite in Step 3 already changed `central/apis/platform` → `api/platform`. Confirm `main.go` still imports `install` (now `api/platform/install`) and registers `apiserver.Resource(&platform.ClusterPool{}, v1alpha1.SchemeGroupVersion)` with `platform` = `api/platform` and `v1alpha1` = `api/platform/v1alpha1`. No manual edit needed beyond Step 3; this step is a read-check.

- [ ] **Step 11: Build + envtest**

Run:
```bash
nix develop --command bash -c 'cd central && GOWORK=off go build ./... && GOWORK=off go test ./test/ -run TestClusterPool -count=1'
nix develop --command bash -c 'cd api && go build ./... && go test ./platform/...'
```
Expected: central build exit 0; `ok github.com/trevex/ectobase/central/test`; api build exit 0; `ok github.com/trevex/ectobase/api/platform/install` (roundtrip fuzz over generated conversions).

- [ ] **Step 12: Verify `api/platform` is apimachinery-only**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
nix develop --command bash -c 'cd api && go list -deps ./platform/... 2>/dev/null | grep -E "opendefense.cloud/kit|k8s.io/apiserver" && echo "!! api/platform pulls kit/apiserver" || echo "OK: api/platform apimachinery-only"'
```
Expected: `OK: api/platform apimachinery-only`.

- [ ] **Step 13: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add api central
git status --short | grep -E '\.go$|update-codegen|go.mod|go.sum' | head -40   # sanity review
git commit -m "$(cat <<'EOF'
refactor(api): move platform group into api/ with generated conversions (pilot)

Relocates central/apis/platform -> api/platform (internal + v1alpha1 external,
SolAr shape), drops the kit interface-assertions so api/platform is
apimachinery-only, and stands up api/hack/update-codegen.sh (gen_helpers) with
central's gen_openapi/gen_client repointed to read the api module. Proves the
api-module codegen pipeline before the net move. ClusterPool envtests green.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Move the `net` group — `api/v1alpha1` + `central/apis/net` → `api/net`, generate conversions

**Goal:** Apply the proven recipe to the 14-type `net` group AND delete the alias/hand-written-conversion tech debt. Today's real external structs (`api/v1alpha1`) become `api/net/v1alpha1`; the field-identical internal structs (`central/apis/net`) become `api/net`; `conversion-gen` now generates what `conversion.go` hand-wrote.

**Files:**
- Create: `api/net/` (from `central/apis/net/` internal), `api/net/v1alpha1/` (from `api/v1alpha1/`), `api/net/install/`, `api/net/fuzzer/`
- Delete: `api/v1alpha1/` (moved), `central/apis/net/` whole tree (incl. `v1alpha1/aliases.go`, `v1alpha1/conversion.go` [2210 lines], `v1alpha1/doc.go`)
- Modify: all consumers (`api/v1alpha1` → `api/net/v1alpha1`), root `Makefile` `generate` target, `central/cmd/apiserver/main.go`

- [ ] **Step 1: Baseline green** (already green from Task 1)

Run:
```bash
nix develop --command bash -c 'cd central && GOWORK=off go build ./...'
nix develop --command bash -c 'cd api && go build ./...'
```
Expected: both exit 0.

- [ ] **Step 2: Move the external wire structs `api/v1alpha1` → `api/net/v1alpha1`**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
mkdir -p api/net
git mv api/v1alpha1 api/net/v1alpha1
```
The package stays `package v1alpha1`; the group stays `net.ectobase.dev`. `roundtrip_test.go` and `vpcpeering_test.go` move with it.

- [ ] **Step 3: Move the internal structs `central/apis/net` → `api/net`**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
for f in central/apis/net/*.go; do git mv "$f" "api/net/$(basename "$f")"; done
git mv central/apis/net/fuzzer  api/net/fuzzer
git mv central/apis/net/install api/net/install
# central/apis/net/v1alpha1 is the ALIAS package — DELETE it, do not move:
git rm -r central/apis/net/v1alpha1
rmdir central/apis/net 2>/dev/null || true
rmdir central/apis 2>/dev/null || true
```

- [ ] **Step 4: Drop kit interface-assertions from every `api/net/*_rest.go`**

Each `*_rest.go` under `api/net/` has the same four-line assertion block + two kit imports as platform's did. Remove them from all of them. Run this to find every file, then edit each to delete the two kit import lines and the `var ( _ resource... )` assertion block:
```bash
cd /home/nik/Development/ironcore-net-xdp
grep -rl 'go.opendefense.cloud/kit' api/net/*.go
```
For each listed file: delete the import lines `"go.opendefense.cloud/kit/apiserver/resource"` and `kitrest "go.opendefense.cloud/kit/apiserver/rest"`, and delete the `var (` block containing the `_ resource.Object = &X{}` / `_ resource.ObjectWithStatusSubResource` / `_ kitrest.SelectableFieldsProvider` / `_ kitrest.SupportedFieldSelectorsProvider` assertions. Some types are scaffold-only and may only have `_ resource.Object` — delete whatever kit assertions are present and the now-unused kit imports. Keep every method. Verify none remain:
```bash
grep -rn 'go.opendefense.cloud/kit' api/net/ && echo "!! kit refs remain in api/net" || echo "OK: api/net kit-free"
```
Expected: `OK: api/net kit-free`.

- [ ] **Step 5: Convert `api/net/v1alpha1/doc.go` to a real (non-alias) versioned package with conversion-gen**

Replace the entire alias-explaining doc.go (moved from `api/v1alpha1/doc.go`) so it carries the full generator marker set matching platform's. Set `api/net/v1alpha1/doc.go` to:
```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// +k8s:openapi-gen=true
// +k8s:deepcopy-gen=package
// +k8s:conversion-gen=github.com/trevex/ectobase/api/net
// +k8s:defaulter-gen=TypeMeta
// +k8s:prerelease-lifecycle-gen=true
// +groupName=net.ectobase.dev
// +k8s:openapi-model-package=dev.ectobase.net.v1alpha1

// Package v1alpha1 is the v1alpha1 version of the net.ectobase.dev API group:
// the user-facing overlay networking model plus the compiled objects, served by
// the aggregated apiserver and consumed as CRDs by the netplane control plane.
package v1alpha1
```

- [ ] **Step 6: Give `api/net/v1alpha1/register.go` the localSchemeBuilder shape (so generated conversions/defaults register)**

The moved `register.go` (from `api/v1alpha1`) uses a plain `SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)`. The generated `zz_generated.conversion.go` and `zz_generated.defaults.go` register via `localSchemeBuilder.Register(...)` in their `init()`, so `register.go` must expose `localSchemeBuilder` and register `addKnownTypes` + `addDefaultingFuncs` in an `init()` (mirroring `api/platform/v1alpha1/register.go`). Replace the `var (...)` builder block and add an `init()` so it reads:
```go
var (
	// SchemeBuilder collects scheme init functions (known types + generated
	// conversion/defaults registered from the zz_generated files).
	SchemeBuilder      runtime.SchemeBuilder
	localSchemeBuilder = &SchemeBuilder
	// AddToScheme registers the group/version and its known types with a scheme.
	AddToScheme = localSchemeBuilder.AddToScheme
)

func init() {
	localSchemeBuilder.Register(addKnownTypes, addDefaultingFuncs)
}
```
Keep `GroupName`, `SchemeGroupVersion`, `Resource`, `Kind`, and `addKnownTypes` (all 14 types). Add a `defaults.go` if one is required by the defaulter marker — see Step 7.

- [ ] **Step 7: Add `api/net/v1alpha1/defaults.go`**

The `+k8s:defaulter-gen=TypeMeta` marker and the `addDefaultingFuncs` reference need a defaults.go that wires `RegisterDefaults` (generated into `zz_generated.defaults.go`). Create `api/net/v1alpha1/defaults.go`:
```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// addDefaultingFuncs registers the generated defaulters (RegisterDefaults lives
// in zz_generated.defaults.go).
func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}
```

- [ ] **Step 8: Ensure `api/net` (internal) register.go + doc.go match platform's internal shape**

The moved `central/apis/net/register.go` already uses `SchemeGroupVersion{Group: net.ectobase.dev, Version: runtime.APIVersionInternal}` + `addKnownTypes`. Confirm `api/net/doc.go` carries `// +k8s:deepcopy-gen=package` and `// +groupName=net.ectobase.dev` (it does, moved verbatim). Confirm `api/net/install/install.go` imports `api/net` + `api/net/v1alpha1` (the import rewrite in Step 11 handles the path change). No new file needed here; this is a read-check.

- [ ] **Step 9: Delete the hand-written conversion tech debt (already removed in Step 3)**

Confirm the alias package and hand-written conversion are gone:
```bash
cd /home/nik/Development/ironcore-net-xdp
test ! -e central/apis/net/v1alpha1/conversion.go && test ! -e central/apis/net/v1alpha1/aliases.go && echo "OK: alias+handwritten conversion deleted" || echo "!! leftovers"
```
Expected: `OK: alias+handwritten conversion deleted`.

- [ ] **Step 10: Rewrite all `net` import paths across the repo**

Two path families change. Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
# external wire types: api/v1alpha1 -> api/net/v1alpha1  (netplane, cni, central/pkg, central/test, central/cmd)
grep -rlZ 'trevex/ectobase/api/v1alpha1' --include='*.go' . \
  | xargs -0 sed -i 's#trevex/ectobase/api/v1alpha1#trevex/ectobase/api/net/v1alpha1#g'
# internal + install: central/apis/net -> api/net
grep -rlZ 'trevex/ectobase/central/apis/net' --include='*.go' . \
  | xargs -0 sed -i 's#trevex/ectobase/central/apis/net#trevex/ectobase/api/net#g'
grep -rn 'ectobase/api/v1alpha1\|central/apis/net' --include='*.go' . || echo "OK: no stale net imports remain"
```
Expected: `OK: no stale net imports remain`.

- [ ] **Step 11a: Collapse central's codegen to read the whole api module**

Now that `net` has moved to `api/net` and `central/apis` is gone, edit `central/hack/update-codegen.sh`:
- DELETE the top `kube::codegen::gen_helpers ... "${PROJECT_DIR}/apis"` block entirely (all helpers — deepcopy/conversion/defaults — are generated by `api/hack/update-codegen.sh` now).
- On `gen_openapi`: replace the two `--extra-pkgs` net/platform lines with a single input that reads the whole api module. Its positional input dir becomes `"${PROJECT_DIR}/../api"`; keep `--extra-pkgs "k8s.io/api/core/v1"`. Remove the `--extra-pkgs` lines that pointed at `api/v1alpha1` and `api/platform/v1alpha1` (they are now primary inputs under `../api`).
- On `gen_client`: replace the two inputs from Step 8 with the single `"${PROJECT_DIR}/../api"`.
Keep the `use-local-modules.sh` chmod workaround block.

- [ ] **Step 11b: Repoint the root `Makefile` `generate` target**

The deepcopy + CRD source moves from `api/v1alpha1` to `api/net/v1alpha1`, and deepcopy is now produced by `api/hack/update-codegen.sh` (gen_helpers) rather than `controller-gen object`. Edit the `generate:` target in the root `Makefile` to:
```makefile
generate: ## Regenerate deepcopy/conversion (kube::codegen) + CRD manifests (controller-gen)
	cd api && ./hack/update-codegen.sh
	cd central && ./hack/update-codegen.sh
	cd api && controller-gen crd paths=./net/v1alpha1/... paths=./platform/v1alpha1/... output:crd:artifacts:config=../config/crd/bases
	./hack/sync-chart-crds.sh
```
(Groups are unchanged, so the emitted `config/crd/bases/net.ectobase.dev_*.yaml` filenames + contents stay stable; the `platform.ectobase.dev_*` CRDs now also emit here, which is fine — they are not chart-synced unless already listed. Verify `sync-chart-crds.sh` still selects only the intended net CRDs.)

- [ ] **Step 12: Generate everything**

Run:
```bash
nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp && make generate'
```
Expected: exit 0. Verify the net conversions are now GENERATED (not hand-written):
```bash
cd /home/nik/Development/ironcore-net-xdp
test -f api/net/v1alpha1/zz_generated.conversion.go && grep -q 'net "github.com/trevex/ectobase/api/net"' api/net/v1alpha1/zz_generated.conversion.go && echo "OK: net conversions generated" || echo "!! net conversion missing"
```
Expected: `OK: net conversions generated`. If missing, STOP and report (do not hand-write conversions — the whole point is to eliminate them).

- [ ] **Step 13: Build all modules**

Run:
```bash
nix develop --command bash -c 'cd api && go build ./... && go test ./net/... ./platform/...'
nix develop --command bash -c 'cd central && GOWORK=off go build ./...'
nix develop --command bash -c 'cd netplane && go build ./...'
nix develop --command bash -c 'cd cni && go build ./...'
```
Expected: all exit 0; `ok github.com/trevex/ectobase/api/net/install` (roundtrip fuzz over generated conversions passes — this is the proof the generated conversions are field-complete).

- [ ] **Step 14: Envtests (central real apiserver + netplane controllers)**

Run:
```bash
nix develop --command bash -c 'cd central && GOWORK=off go test ./test/ -run "TestClusterPool|TestCompiledNIC|TestBroker|TestScheduler" -count=1'
nix develop --command bash -c 'cd netplane && go test ./controllers/... -count=1'
```
Expected: `ok` for both. The `TestCompiledNIC_SpecClusterNameSelector` (real apiserver field selector) passing confirms the served net group + its generated conversions work end to end.

- [ ] **Step 15: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add api central netplane cni config Makefile
git status --short | head -60   # review: central/apis gone, api/net present, no stale files
git commit -m "$(cat <<'EOF'
refactor(api): move net group into api/net with generated conversions

Moves the external wire structs (api/v1alpha1 -> api/net/v1alpha1) and the
field-identical internal structs (central/apis/net -> api/net) into the api
module under the SolAr shape, drops the alias hack + the 2210-line hand-written
conversion.go (conversion-gen now generates them) + the kit interface-assertions
(api/net is apimachinery-only). Repoints all consumers, the apiserver, and the
Makefile generate target. central/apis is gone. Roundtrip fuzz + field-selector
envtests green.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: CI invariant + cleanup verification

**Goal:** Lock in the "api/ imports no apiserver-kit / k8s.io/apiserver" invariant with an automated check, and verify the round left no debris.

**Files:**
- Create: `api/deps_invariant_test.go`
- Verify: `central/apis` gone; chart CRDs + goldens unchanged (groups didn't move)

- [ ] **Step 1: Add the dependency-invariant test in the api module**

Create `api/deps_invariant_test.go`:
```go
// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAPIModuleIsApimachineryOnly asserts the shared api module never pulls the
// aggregated-apiserver framework (apiserver-kit) or k8s.io/apiserver into any of
// its packages. Those belong exclusively to the central apiserver binary; the
// api module must stay importable by netplane/cni/broker without them. The
// compile-time resource.Object proof lives at central/cmd/apiserver's
// apiserver.Resource(...) calls, not here.
func TestAPIModuleIsApimachineryOnly(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./...: %v\n%s", err, out)
	}
	for _, banned := range []string{
		"go.opendefense.cloud/kit",
		"k8s.io/apiserver",
	} {
		if strings.Contains(string(out), banned) {
			t.Errorf("api module transitively imports %q — it must stay apimachinery-only (move the offending import into central)", banned)
		}
	}
}
```

- [ ] **Step 2: Run the invariant test**

Run:
```bash
nix develop --command bash -c 'cd api && go test -run TestAPIModuleIsApimachineryOnly ./...'
```
Expected: PASS. (If it fails, an api package imports kit/apiserver — find it with `go list -deps ./... | grep -E "kit|apiserver"` and move that code to central.)

- [ ] **Step 3: Verify no debris**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
test ! -e central/apis && echo "OK: central/apis gone" || echo "!! central/apis remains"
grep -rn 'central/apis/' --include='*.go' . || echo "OK: no central/apis imports"
git diff --stat HEAD~2 -- config/crd/bases | tail -5   # net CRDs should be unchanged (group didn't move)
```
Expected: `OK: central/apis gone`, `OK: no central/apis imports`, and the `config/crd/bases/net.ectobase.dev_*.yaml` show no content change (only possibly reordering).

- [ ] **Step 4: Chart render test (goldens stable — groups unchanged)**

Run:
```bash
nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp && bash deploy/charts/ectobase/tests/render.sh' | tail -20
```
Expected: all PASS (14 CRDs, RBAC unchanged — no group moved in R2, so `apiGroups` and CRD names are identical to before).

- [ ] **Step 5: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add api
git commit -m "$(cat <<'EOF'
test(api): assert api module stays apimachinery-only (no kit/apiserver)

Guards the R2 invariant: the shared api module must never transitively import
apiserver-kit or k8s.io/apiserver, so netplane/cni/broker keep importing it
framework-free. central remains the sole apiserver-kit importer.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## R2 Done Criteria

- `central/apis/` no longer exists; all API types live under `api/{net,platform}/(v1alpha1/)`.
- `api/v1alpha1` is gone (moved to `api/net/v1alpha1`); the alias `aliases.go` + the 2210-line hand-written `conversion.go` are deleted; net conversions are generated (`api/net/v1alpha1/zz_generated.conversion.go`).
- `api/` imports no apiserver-kit / k8s.io/apiserver (`TestAPIModuleIsApimachineryOnly` green); `central` is the sole kit importer.
- `api`, `central`, `netplane`, `cni` all build; roundtrip fuzz + central real-apiserver field-selector envtests + netplane controller envtests pass.
- Chart CRDs + RBAC goldens unchanged (groups did not move — that is R3).
- Three commits on `feat/api-restructure`. Ready for R3 (group split).
