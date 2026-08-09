# `central` → `hub` Rename Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the fleet control-plane component from `central` to `hub` across the Go module + directory, the three container images, the Kubernetes object names, the code identifiers, and the fabric kind cluster.

**Architecture:** A large but mechanical rename executed as five green-gated tasks. The `central` module is a **leaf** — nothing else `require`s it (only `go.work` + its own internal imports), so the module rename is contained to `central/` + `go.work`. The remaining layers (images, k8s names, identifiers, fabric cluster) are string renames verified by build + envtest + render + a final live clab sweep — the R3 group-split proved that image/SA/cluster/kubeconfig naming drift only surfaces on a real fabric.

**Tech Stack:** Go (`go.work` + `replace` dirs), Docker, Helm chart, the `test/lab` fabric CLI, nix devShell. `hub` builds `GOWORK=off`.

**Branch:** `feat/rename-central-to-hub` (spec already committed at `755d01b`).

**Conventions:** Go tooling in the nix devShell (`nix develop --command bash -c '...'`); `hub` (ex-`central`) builds `GOWORK=off`. NEVER `git add -A`. Pre-commit runs Rust hooks only ("Skipped" for Go/YAML). The live sweep needs sudo + `hack/r3-live-sweep.sh`.

**Facts established during planning:**
- `go.work` lists `./central`; `central/go.mod` module is `github.com/trevex/ectobase/central` and `require`s `api` + `netplane` (relative `replace`s `../api`, `../netplane` that still resolve from `hub/`), plus a local apiserver-kit replace and `./bin/.modules` k8s replaces (all relative, move with the dir).
- No other module `require`s `central` (no external `replace` to update).
- Code identifiers to rename live in 11 files: `central/cmd/broker/main.go`, `netplane/cmd/controller/main.go`, `test/lab/internal/deploy/ectobase.go`, `test/lab/topology/fabric.go`, `test/lab/livetest/{overlay,pod,tier2,vpcpeering}_test.go`, and chart `templates/{broker,rbac}.yaml` + `values.yaml`.
- Images `ghcr.io/trevex/ectobase/central-{apiserver,controller,broker}` are referenced ~131× (Dockerfiles, `hub/hack/smoke.sh`, `test/lab/lab.yaml` push list, chart values, `config/deploy`, `hack/r3-live-sweep.sh`).
- The fabric kind cluster `central` appears in `test/lab/lab.yaml` (`clusters:`), `test/lab/internal/config/derive_test.go`, and derives the node name `central-control-plane`, kubeconfig `build/ectobase/central.kubeconfig`, and an IPv6 prefix — all from the single cluster name.

---

## Task 1: Go module + directory rename

**Files:** `central/` → `hub/` (whole tree), `go.work`, every `.go` importing `.../central/...`.

- [ ] **Step 1: Baseline green**
Run: `nix develop --command bash -c 'cd central && GOWORK=off go build ./...'` → exit 0.

- [ ] **Step 2: Move the directory**
```bash
cd /home/nik/Development/ironcore-net-xdp
git mv central hub
```

- [ ] **Step 3: Rename the module path + all import paths**
```bash
cd /home/nik/Development/ironcore-net-xdp
# module line + every internal import
grep -rlZ 'github.com/trevex/ectobase/central' --include='*.go' hub | xargs -0 sed -i 's#github.com/trevex/ectobase/central#github.com/trevex/ectobase/hub#g'
sed -i 's#module github.com/trevex/ectobase/central#module github.com/trevex/ectobase/hub#' hub/go.mod
# go.work
sed -i 's#\./central#./hub#' go.work
# any other module importing central (should be none, but sweep all modules)
grep -rlZ 'github.com/trevex/ectobase/central' --include='*.go' api netplane cni test 2>/dev/null | xargs -0 -r sed -i 's#github.com/trevex/ectobase/central#github.com/trevex/ectobase/hub#g'
grep -rn 'ectobase/central' --include='*.go' --include='go.mod' --include='go.work' . 2>/dev/null | grep -v '/bin/.modules/' || echo "OK: no ectobase/central refs remain"
```
Expected: `OK: no ectobase/central refs remain`.

- [ ] **Step 4: Build all modules**
```bash
nix develop --command bash -c 'cd hub && GOWORK=off go build ./... && echo hub_OK'
nix develop --command bash -c 'cd netplane && go build ./... && echo netplane_OK'
nix develop --command bash -c 'cd cni && go build ./... && echo cni_OK'
nix develop --command bash -c 'cd test/lab && go build ./... 2>&1 | grep -v "permission denied" | tail -3; echo lab_built'
```
Expected: hub_OK / netplane_OK / cni_OK, and test/lab builds (ignore any pre-existing root-owned `build/` permission noise).

- [ ] **Step 5: hub envtests + unit tests**
```bash
nix develop --command bash -c 'cd hub && GOWORK=off go test ./pkg/... -count=1 2>&1 | tail -8'
nix develop --command bash -c 'cd hub && GOWORK=off go test ./test/ -run "TestClusterPool|TestVPC_CRUD|TestCompiledNIC" -count=1 2>&1 | tail -3'
```
Expected: hub pkg tests ok; `ok github.com/trevex/ectobase/hub/test`.

- [ ] **Step 6: Commit**
```bash
cd /home/nik/Development/ironcore-net-xdp
git add -u; git add hub go.work
git commit -m "$(cat <<'EOF'
refactor(hub): rename central module+dir to hub (module path + imports)

git mv central->hub; module github.com/trevex/ectobase/central->.../hub; all
internal imports + go.work updated. Nothing else require'd central (leaf), so no
external replace changes. Build + hub envtests green.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```
(Use `git add -u` to stage the tracked renames/edits + `git add hub` for any new-path files; verify `git status` shows no stray `central/`.)

## Task 2: Container images + Kubernetes object names + broker identity

**Files:** `hub/Dockerfile.*`, `hub/hack/smoke.sh`, `test/lab/lab.yaml`, `hack/r3-live-sweep.sh`, `hub/config/*.yaml`, `deploy/charts/ectobase/templates/{broker,rbac,apiserver,controller,reflector}.yaml` (whichever exist) + `values.yaml`, `config/deploy/*.yaml`, `test/lab/internal/deploy/ectobase.go`.

- [ ] **Step 1: Rename the three images everywhere**
```bash
cd /home/nik/Development/ironcore-net-xdp
grep -rlZ 'ectobase/central-' --include='*.sh' --include='*.yaml' --include='*.go' --include='Dockerfile*' . 2>/dev/null \
  | grep -zv '/bin/.modules/' \
  | xargs -0 -r sed -i 's#ectobase/central-apiserver#ectobase/hub-apiserver#g; s#ectobase/central-controller#ectobase/hub-controller#g; s#ectobase/central-broker#ectobase/hub-broker#g'
grep -rn 'ectobase/central-' . 2>/dev/null | grep -v '/bin/.modules/' || echo "OK: no central- image refs remain"
```
Expected: `OK: no central- image refs remain`.

- [ ] **Step 2: Rename the k8s object names + SA/deployment/role names**
The Deployments/ServiceAccounts/ClusterRoles/Bindings + smoke.sh binary names `central-apiserver|central-controller|central-broker` → `hub-*`. Rename the bare tokens (careful: this is the k8s `name:` + Go references, not just images — the image sed above already handled `ectobase/central-*`).
```bash
cd /home/nik/Development/ironcore-net-xdp
grep -rlZ 'central-apiserver\|central-controller\|central-broker' --include='*.yaml' --include='*.go' --include='*.sh' hub deploy config test/lab 2>/dev/null \
  | xargs -0 -r sed -i 's#central-apiserver#hub-apiserver#g; s#central-controller#hub-controller#g; s#central-broker#hub-broker#g'
```

- [ ] **Step 3: Consolidate the broker central-side identity `ectobase-broker` → `hub-broker`**
The lab-minted central-side identity (SA/ClusterRole/Binding named `ectobase-broker` in `test/lab/internal/deploy/ectobase.go`) becomes `hub-broker` to match the downstream SA. Rename it there:
```bash
cd /home/nik/Development/ironcore-net-xdp
sed -i 's#ectobase-broker#hub-broker#g' test/lab/internal/deploy/ectobase.go
grep -rn 'ectobase-broker' test/lab/ hub/ deploy/ config/ 2>/dev/null || echo "OK: broker identity consolidated to hub-broker"
```
Expected: `OK: broker identity consolidated to hub-broker`. (If the downstream chart SA and this central-side identity now collide in a way the broker wiring depends on, they are still distinct objects on distinct clusters — same name is fine.)

- [ ] **Step 4: Fix `central/` PATH references in scripts/build contexts**
`git mv central hub` broke any path referencing `central/` (Dockerfile contexts, `CENTRAL_DIR`, `cd central`, docker `-f central/Dockerfile.*`, build-image steps).
```bash
cd /home/nik/Development/ironcore-net-xdp
grep -rlZ '\bcentral/\|CENTRAL_DIR\|cd central\b\|/central "\|hack/r3-live-sweep\|central/hack\|central/Dockerfile\|central/cmd' --include='*.sh' --include='*.go' --include='Makefile' --include='Dockerfile*' . 2>/dev/null \
  | grep -zv '/bin/.modules/' | xargs -0 -r sed -i 's#\bcentral/#hub/#g; s#CENTRAL_DIR#HUB_DIR#g; s#cd central\b#cd hub#g'
# The r3-live-sweep.sh central image build block: `cd central` + Dockerfile paths + image tags
grep -rn '\bcentral/\|cd central\b\|CENTRAL_DIR' hack/ Makefile hub/hack/ test/lab/ 2>/dev/null | grep -v '/bin/.modules/' || echo "OK: no central/ path refs remain"
```
Expected: `OK: no central/ path refs remain`. Manually sanity-check `hack/r3-live-sweep.sh` and `hub/hack/smoke.sh` build the `hub-*` images from `hub/Dockerfile.*` in the `hub` dir.

- [ ] **Step 5: Build + render + envtest**
```bash
nix develop --command bash -c 'cd hub && GOWORK=off go build ./... && echo hub_OK'
nix develop --command bash -c 'cd test/lab && go build ./... 2>&1 | grep -v "permission denied" | tail -2; echo lab_OK'
nix develop --command bash -c 'bash deploy/charts/ectobase/tests/render.sh 2>&1 | grep -E "FAIL|installCRDs|PASS: ebpf render (rbac|broker)"'
```
Expected: builds OK; render.sh no FAIL (the chart object-name goldens in `config/deploy` were renamed in lockstep by Step 2, so `ebpf render rbac == config/deploy/rbac.yaml` still passes). If a golden now mismatches because only one side was renamed, re-sync it via the render harness incantation (see `deploy/charts/ectobase/tests/render.sh`).

- [ ] **Step 6: Commit**
```bash
git add -u
git commit -m "refactor(hub): rename central-* images + k8s object names + broker identity to hub-*

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

## Task 3: Code identifiers + comments/logs

**Files:** `hub/cmd/broker/main.go`, `netplane/cmd/controller/main.go`, `test/lab/internal/deploy/ectobase.go`, `test/lab/topology/fabric.go`, `test/lab/livetest/{overlay,pod,tier2,vpcpeering}_test.go`, chart `values.yaml` + `templates/broker.yaml`.

- [ ] **Step 1: Rename the identifiers**
```bash
cd /home/nik/Development/ironcore-net-xdp
FILES=$(grep -rlI 'CentralIdentity\|central-kubeconfig\|applyCentral\|centralKubeconfigSecret\|centralKubeconfig' --include='*.go' --include='*.yaml' . 2>/dev/null | grep -v '/bin/.modules/')
for f in $FILES; do
  sed -i 's#CentralIdentity#HubIdentity#g; s#central-kubeconfig#hub-kubeconfig#g; s#applyCentral#applyHub#g; s#centralKubeconfigSecret#hubKubeconfigSecret#g; s#centralKubeconfig#hubKubeconfig#g' "$f"
done
grep -rn 'CentralIdentity\|central-kubeconfig\|applyCentral\|centralKubeconfigSecret' --include='*.go' --include='*.yaml' . 2>/dev/null | grep -v '/bin/.modules/' || echo "OK: identifiers renamed"
```
Expected: `OK: identifiers renamed`. Note: the `--central-kubeconfig` CLI flag string is now `--hub-kubeconfig`; the chart value `broker.centralKubeconfigSecret` is now `broker.hubKubeconfigSecret` — the chart's `broker.yaml` template reference changes in lockstep (same sed pass), and `test/lab` passes the flag via the deploy code (also renamed).

- [ ] **Step 2: Rename component "central" mentions in log/comment strings (scoped, not blanket)**
Only rename strings that name the component. Review and edit the log lines / comments in `hub/cmd/*/main.go`, `netplane/cmd/controller/main.go`, `test/lab/internal/deploy/ectobase.go` that say "central apiserver"/"central cluster"/"central identity" → "hub ...". Do NOT touch unrelated English uses. Verify the deploy still refers to the hub cluster consistently.

- [ ] **Step 3: Build + envtests**
```bash
nix develop --command bash -c 'cd hub && GOWORK=off go build ./... && GOWORK=off go test ./pkg/... -count=1 2>&1 | tail -6'
nix develop --command bash -c 'cd netplane && go build ./... && echo netplane_OK'
nix develop --command bash -c 'cd test/lab && go build ./... 2>&1 | grep -v "permission denied" | tail -2; echo lab_OK'
```
Expected: hub builds + pkg tests ok; netplane_OK; lab_OK.

- [ ] **Step 4: Commit**
```bash
git add -u
git commit -m "refactor(hub): rename central code identifiers (CentralIdentity, --central-kubeconfig, applyCentral) to hub

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

## Task 4: Fabric kind cluster `central` → `hub`

**Files:** `test/lab/lab.yaml`, `test/lab/internal/config/derive_test.go`, `test/lab/topology/fabric.go`, `test/lab/internal/deploy/ectobase.go`, any golden fixtures under `test/lab/internal/**/testdata` referencing cluster `central`.

- [ ] **Step 1: Rename the cluster in config + derived references**
```bash
cd /home/nik/Development/ironcore-net-xdp
# the cluster entry name + any hardcoded "central" cluster reference / node / kubeconfig
grep -rln '\bcentral\b' test/lab/lab.yaml test/lab/topology/ test/lab/internal/ 2>/dev/null | grep -v '/bin/.modules/'
```
Review each hit and rename the CLUSTER name `central` → `hub` (the `clusters:` entry in `lab.yaml`, the `"central"` cluster lookups, `central-control-plane` node name, `central.kubeconfig` filename, and the `applyHub`/deploy targeting of the hub cluster). Apply:
```bash
cd /home/nik/Development/ironcore-net-xdp
sed -i 's#name: central#name: hub#' test/lab/lab.yaml
# code + fixture references to the cluster name / derived artifacts
grep -rlZ '"central"\|central-control-plane\|central\.kubeconfig\|Clusters\["central"\]' test/lab 2>/dev/null \
  | xargs -0 -r sed -i 's#"central"#"hub"#g; s#central-control-plane#hub-control-plane#g; s#central\.kubeconfig#hub.kubeconfig#g; s#Clusters\["central"\]#Clusters["hub"]#g'
```

- [ ] **Step 2: Update `derive_test.go` golden**
`test/lab/internal/config/derive_test.go` hardcodes `clusters: [{name: central, ...}]` and asserts on `Clusters["central"]`. Rename those to `hub` (name in the YAML fixtures + the map-key assertions). Run it:
```bash
nix develop --command bash -c 'cd test/lab && go test ./internal/config/ -run TestDerive -count=1 2>&1 | tail -5'
```
Expected: PASS (the derived IPv6 prefix / API VIP now derive from `hub`, internally consistent).

- [ ] **Step 3: Full test/lab unit tests + render**
```bash
nix develop --command bash -c 'cd test/lab && go test ./internal/... ./topology/... -count=1 2>&1 | grep -vE "permission denied|^ok.*build" | tail -15'
nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp && go run ./test/lab render 2>&1 | tail -3'
```
Expected: unit tests pass; `lab render` succeeds (renders the fabric with the `hub` cluster). If a topology golden under `test/lab/internal/render/testdata` references `central`, update it.

- [ ] **Step 4: Verify no residual `central` component/cluster references**
```bash
cd /home/nik/Development/ironcore-net-xdp
grep -rniI 'central' --include='*.go' --include='*.yaml' --include='*.sh' --include='Dockerfile*' . 2>/dev/null \
  | grep -v '/bin/.modules/' | grep -viE 'docs/|# |central england|decentral' | head -30
```
Review the remaining hits: each should be either an unrelated English word or a historical doc reference — NOT a component/image/cluster/identifier. Fix any real stragglers.

- [ ] **Step 5: Commit**
```bash
git add -u
git commit -m "refactor(hub): rename fabric kind cluster central->hub (+derived node/kubeconfig/prefix)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

## Task 5: Live clab sweep (the gate)

**Goal:** Prove the rename holds end-to-end on a real fabric — the deploy must come up with `hub-*` images, the `hub` cluster, and the `hub-broker` identity, and the full live suite (21/21) must pass.

- [ ] **Step 1: Static preflight**
```bash
nix develop --command bash -c 'cd hub && GOWORK=off go build ./...' && \
nix develop --command bash -c 'bash deploy/charts/ectobase/tests/render.sh 2>&1 | grep -E "FAIL|installCRDs"'
```
Expected: build ok, no render FAIL, 14 CRDs.

- [ ] **Step 2: Run the full live sweep**
```bash
cd /home/nik/Development/ironcore-net-xdp
sudo -E env "PATH=$PATH" make lab-down 2>&1 | tail -2
nix develop --command bash -c 'bash hack/r3-live-sweep.sh > /tmp/hub-rename-sweep.log 2>&1'; echo "sweep exit: $?"
grep -nE '\[r3-sweep|--- FAIL|^FAIL|R3 LIVE SWEEP PASSED|lab-(up|ceph|tier2-up|test) FAILED' /tmp/hub-rename-sweep.log | tail -20
```
Expected: `R3 LIVE SWEEP PASSED` (or the lab-test tail showing `ok test/lab/livetest` with 0 FAIL). If a deploy step fails with a `central`-named image/SA/cluster/kubeconfig not found, that is a missed rename — grep it, fix, rebuild the affected image, and re-run.

- [ ] **Step 3: Commit any sweep-caught fixes** (if needed)
```bash
git add -u
git commit -m "fix(hub): rename straggler caught by the live sweep

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Done Criteria

- `central/` is gone; `hub/` holds the module `github.com/trevex/ectobase/hub`; `grep -rn 'ectobase/central' --include='*.go'` empty.
- Images are `hub-{apiserver,controller,broker}`; no `central-*` image or k8s object name remains; broker identity is `hub-broker`.
- Code identifiers are `HubIdentity` / `--hub-kubeconfig` / `applyHub` / `hubKubeconfigSecret`.
- The fabric kind cluster is `hub` (node `hub-control-plane`, `hub.kubeconfig`); `derive_test.go` + topology goldens pass.
- All modules build; `hub` + netplane envtests + `test/lab` unit tests + render pass; **live clab sweep 21/21 green**.
- Commits on `feat/rename-central-to-hub`. Ready to finish/merge. Effort 2 (charts top-level + generated CRDs/RBAC) follows.
