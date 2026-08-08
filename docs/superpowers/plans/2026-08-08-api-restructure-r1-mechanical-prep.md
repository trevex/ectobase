# API Restructure — R1 (Mechanical Prep) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the two low-risk, no-behavior-change preparation steps of the API restructure: move `central/internal/*` to `central/pkg/*`, and delete the dead `CompiledWorkload` type (regenerating client-go/openapi/CRD).

**Architecture:** Pure refactor. Task 1 is a package relocation within the `central` Go module — package names are unchanged, only import *paths* (`.../central/internal/X` → `.../central/pkg/X`) change. Task 2 removes a type that has no production consumer; its only test (`TestCompiledWorkload_SpecClusterNameSelector`) is redundant with the per-type field-selector envtests in `net_envtest_test.go`. Correctness is verified by the existing `central` build + test suite staying green (there is no new behavior to test-drive).

**Tech Stack:** Go (module `github.com/trevex/ectobase/central`, builds with `GOWORK=off`), k8s.io/code-generator (`central/hack/update-codegen.sh`), controller-gen (`central/hack/update-crd.sh`), the nix devShell (`nix develop`, provides `KUBEBUILDER_ASSETS` for envtest).

**Branch:** Continue on `feat/api-restructure` (the spec is already committed there at b7c41de).

**Conventions (from the repo):**
- Run Go tooling inside the devShell: `nix develop --command bash -c '<cmd>'`.
- The `central` module builds and tests with workspace mode off: prefix Go commands with `GOWORK=off`.
- NEVER `git add -A`; stage explicit paths.
- Pre-commit hooks run Rust clippy/rustfmt only — they will skip on a Go-only change; verify Go build/tests yourself.

---

## File Structure

**Task 1 — relocate packages (no content change beyond import paths):**
- Move `central/internal/broker/` → `central/pkg/broker/`
- Move `central/internal/clusterpool/` → `central/pkg/clusterpool/`
- Move `central/internal/clusterrestriction/` → `central/pkg/clusterrestriction/`
- Move `central/internal/failover/` → `central/pkg/failover/`
- Move `central/internal/fence/` → `central/pkg/fence/`
- Move `central/internal/scheduler/` → `central/pkg/scheduler/`
- Rewrite the import path `github.com/trevex/ectobase/central/internal/` → `github.com/trevex/ectobase/central/pkg/` in every `.go` file under `central/` (importers: `cmd/{apiserver,broker,controller}/main.go`, the moved packages' own cross-imports, and `central/test/*_test.go`).

**Task 2 — delete `CompiledWorkload`:**
- Delete: `central/apis/platform/compiledworkload_types.go`
- Delete: `central/apis/platform/compiledworkload_rest.go`
- Delete: `central/apis/platform/v1alpha1/compiledworkload_types.go`
- Delete: `central/config/crd/platform.ectobase.dev_compiledworkloads.yaml`
- Modify: `central/apis/platform/register.go` (remove `&CompiledWorkload{}`, `&CompiledWorkloadList{}`)
- Modify: `central/apis/platform/v1alpha1/register.go` (remove `&CompiledWorkload{}`, `&CompiledWorkloadList{}`)
- Modify: `central/cmd/apiserver/main.go` (remove the `apiserver.Resource(&platform.CompiledWorkload{}, ...)` line)
- Modify: `central/pkg/clusterrestriction/plugin.go` (the moved file — fix a stale doc comment)
- Modify: `central/test/envtest_test.go` (delete the `TestCompiledWorkload_SpecClusterNameSelector` block)
- Regenerated (do not hand-edit — produced by the codegen scripts): `central/apis/platform/**/zz_generated.{deepcopy,conversion,defaults,model_name}.go`, `central/client-go/**` (clientset/listers/informers/applyconfigurations for compiledworkload removed), `central/client-go/openapi/zz_generated.openapi.go`.

---

## Task 1: Relocate `central/internal/*` → `central/pkg/*`

**Files:** as listed above (relocate 6 packages + rewrite import paths across `central/`).

- [ ] **Step 1: Establish the green baseline**

Confirm the module builds and tests pass *before* touching anything, so any later failure is attributable to this task.

Run:
```bash
nix develop --command bash -c 'cd central && GOWORK=off go build ./...'
```
Expected: exit 0, no output.

- [ ] **Step 2: Move the six packages with `git mv`**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp/central
mkdir -p pkg
for d in broker clusterpool clusterrestriction failover fence scheduler; do
  git mv "internal/$d" "pkg/$d"
done
rmdir internal 2>/dev/null || true
git status --short | head -40
```
Expected: `git status` shows the files renamed `internal/<d>/... -> pkg/<d>/...`; the `internal/` directory is gone.

- [ ] **Step 3: Rewrite import paths across the `central` module**

Package names are unchanged (e.g. `package broker`); only the import path string changes. Rewrite it in every `.go` file under `central/`.

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp/central
grep -rlZ 'trevex/ectobase/central/internal/' --include='*.go' . \
  | xargs -0 sed -i 's#trevex/ectobase/central/internal/#trevex/ectobase/central/pkg/#g'
# Verify none remain:
grep -rn 'central/internal/' --include='*.go' . || echo "OK: no internal/ imports remain"
```
Expected: final line prints `OK: no internal/ imports remain`.

- [ ] **Step 4: Build to verify the relocation compiles**

Run:
```bash
nix develop --command bash -c 'cd central && GOWORK=off go build ./...'
```
Expected: exit 0, no output. (A non-zero exit here means an import path was missed — re-run the Step 3 grep.)

- [ ] **Step 5: `go vet` + unit tests (non-envtest) pass**

Run:
```bash
nix develop --command bash -c 'cd central && GOWORK=off go vet ./... && GOWORK=off go test ./pkg/...'
```
Expected: `ok` for each `central/pkg/...` package that has tests (broker, failover, scheduler, clusterpool have `_test.go`); no build failures.

- [ ] **Step 6: envtest suite still green (real apiserver)**

The `central/test` package builds and boots the aggregated apiserver; it imports the moved packages. Run the fast, non-Ceph envtests to confirm the relocation didn't break wiring.

Run:
```bash
nix develop --command bash -c 'cd central && GOWORK=off go test ./test/ -run "TestClusterPool|TestScheduler|TestBroker" -count=1'
```
Expected: `ok  github.com/trevex/ectobase/central/test`. (These exercise the scheduler/broker packages under their new paths.)

- [ ] **Step 7: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/pkg central/cmd central/test
git commit -m "$(cat <<'EOF'
refactor(central): move internal/* to pkg/* (SolAr convention, no behavior change)

Relocates broker/clusterpool/clusterrestriction/failover/fence/scheduler from
central/internal/ to central/pkg/ per the API-restructure spec (avoid internal/
packages). Package names unchanged; only import paths updated. Build + vet +
unit + envtest green.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```
Expected: commit succeeds; pre-commit Rust hooks report "no files to check / Skipped".

---

## Task 2: Delete the dead `CompiledWorkload` type

**Context for the implementer:** `CompiledWorkload` (group `platform.ectobase.dev`) has no controller, broker sync, scheduler, or netplane use. Its sole test proves the generic `spec.clusterName` field-selector, which is already proven against the real apiserver by `TestCompiledNIC/VM/VolumeAttachment_SpecClusterNameSelector` in `central/test/net_envtest_test.go` and by the real broker↔apiserver sync in `central/test/phase1b_e2e_test.go`. Removing it loses no coverage.

**Files:** as listed in the File Structure section.

- [ ] **Step 1: Delete the hand-written type, REST, and CRD files**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
git rm central/apis/platform/compiledworkload_types.go \
       central/apis/platform/compiledworkload_rest.go \
       central/apis/platform/v1alpha1/compiledworkload_types.go \
       central/config/crd/platform.ectobase.dev_compiledworkloads.yaml
```
Expected: `rm '...'` printed for each of the four files.

- [ ] **Step 2: Remove the scheme registrations (internal + external)**

Edit `central/apis/platform/register.go` — delete these two lines from the `AddKnownTypes` call:
```go
		&CompiledWorkload{},
		&CompiledWorkloadList{},
```
Edit `central/apis/platform/v1alpha1/register.go` — delete the identical two lines from its `AddKnownTypes` call:
```go
		&CompiledWorkload{},
		&CompiledWorkloadList{},
```

- [ ] **Step 3: Remove the apiserver resource registration**

Edit `central/cmd/apiserver/main.go` — delete this line (currently line 59):
```go
		With(apiserver.Resource(&platform.CompiledWorkload{}, v1alpha1.SchemeGroupVersion)).
```
Leave the surrounding `.With(apiserver.Resource(&platform.ClusterPool{}, ...))` and the net resources intact.

- [ ] **Step 4: Fix the stale clusterrestriction comment**

Edit `central/pkg/clusterrestriction/plugin.go` (moved in Task 1). The comment at line ~55 currently reads:
```go
// VirtualMachine, CompiledNIC and CompiledWorkload. Objects without such a field
```
Change it to drop the removed type:
```go
// VirtualMachine and CompiledNIC. Objects without such a field
```

- [ ] **Step 5: Delete the redundant envtest**

Edit `central/test/envtest_test.go` — delete the entire `TestCompiledWorkload_SpecClusterNameSelector` block: from its doc comment (the line starting `// TestCompiledWorkload_SpecClusterNameSelector proves the selectable`, currently line 224) through the closing `}` at end of file (currently line 303). This is the last function in the file. Do NOT remove any `import` — the surviving `TestClusterPool_*` tests use every imported symbol (`v1alpha1.ClusterPool*`, `install`, `apiregistrationv1`, `metav1`, `runtime`, `client`, `kitenvtest`, `os`, `filepath`, `time`).

- [ ] **Step 6: Regenerate deepcopy/conversion/openapi/client-go**

Run the codegen scripts so the generated `zz_generated.*` + `client-go/**` drop all `CompiledWorkload` artifacts.

Run:
```bash
nix develop --command bash -c 'cd central && ./hack/update-codegen.sh'
nix develop --command bash -c 'cd central && ./hack/update-crd.sh'
```
Expected: both scripts exit 0. `git status` should now show modified `central/apis/platform/**/zz_generated.*.go`, deleted/modified files under `central/client-go/**` (compiledworkload clientset/listers/informers/applyconfigurations gone), and modified `central/client-go/openapi/zz_generated.openapi.go`.

- [ ] **Step 7: Verify no `CompiledWorkload` references remain**

Run:
```bash
cd /home/nik/Development/ironcore-net-xdp
grep -rniI 'compiledworkload' central/ && echo "!! references remain (investigate)" || echo "OK: no CompiledWorkload references"
```
Expected: `OK: no CompiledWorkload references`. (If the codegen left an orphaned generated file the regen didn't overwrite — e.g. an applyconfiguration — `git rm` it explicitly, then re-run this grep.)

- [ ] **Step 8: Build + envtest green**

Run:
```bash
nix develop --command bash -c 'cd central && GOWORK=off go build ./... && GOWORK=off go test ./test/ -run "TestClusterPool" -count=1'
```
Expected: build exit 0; `ok  github.com/trevex/ectobase/central/test` (the `TestClusterPool_*` envtests still serve the `platform.` group correctly with `CompiledWorkload` gone).

- [ ] **Step 9: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add central/apis central/cmd central/test central/pkg central/config central/client-go
git commit -m "$(cat <<'EOF'
refactor(central): drop dead CompiledWorkload type

CompiledWorkload (platform.ectobase.dev) had no controller/broker/scheduler/
netplane consumer; its only test duplicated the spec.clusterName field-selector
coverage already proven against the real apiserver by the CompiledNIC/VM/
VolumeAttachment selector envtests + phase1b broker sync. Removes the types,
REST, registrations, CRD, redundant envtest, and regenerated client-go/openapi.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```
Expected: commit succeeds.

---

## R1 Done Criteria

- `central/internal/` no longer exists; all six packages live under `central/pkg/` and are imported via `.../central/pkg/*`.
- `CompiledWorkload` is gone from types, REST, registrations, CRD, tests, and generated code (`grep -rniI compiledworkload central/` is empty).
- `GOWORK=off go build ./...` and the `TestClusterPool_*` / scheduler / broker envtests pass in the `central` module.
- Two commits on `feat/api-restructure`, no behavior change. Ready for R2 (unify + generate).
