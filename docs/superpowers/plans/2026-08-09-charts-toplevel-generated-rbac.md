# Top-level charts + generated CRDs/RBAC (hub + pool) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the single hand-maintained Helm chart into two top-level generated charts (`charts/ectobase-hub`, `charts/ectobase-pool`), generating CRDs and RBAC into them from `//+kubebuilder:rbac` markers, and delete `config/`, `hub/config/`, and the sync-chart-crds indirection.

**Architecture:** RBAC becomes controller-gen output (one `ClusterRole` rules file per component under each chart's `files/`, injected by the template via `.Files.Get | fromYaml`). CRDs become controller-gen output written directly into `charts/ectobase-pool/crd-bases` (net + compiled) and `test/crds` (compute/storage/platform, envtest-only; hub serves all groups aggregated so ships no CRDs). The lab deploys the two charts via `helm install` exactly as a user would, with credentials/pools as Go fixtures. `render.sh` golden-diffs are replaced by helm-unittest.

**Tech Stack:** Helm 3, helm-unittest plugin, controller-gen (`kubernetes-controller-tools`), Go (controller-runtime, client-go, envtest), Nix devShell, containerlab/kind live fabric.

**Spec:** `docs/superpowers/specs/2026-08-09-charts-toplevel-generated-rbac-design.md`

**Conventions for every task:**
- Go tooling runs inside the flake: `nix develop --command bash -c '...'`. The `hub` module builds with `GOWORK=off` (it is outside `go.work`).
- **NEVER `git add -A`.** Stage explicit paths only.
- Pre-commit runs Rust hooks only (they Skip when no Rust changed) — Go/Helm correctness is your responsibility to verify with the commands in each task.
- Commit only what the task lists. Do not push.
- If you are a review subagent, inspect with `git show`/`git diff`/`git log` — **never `git checkout`/`git switch`/`git worktree`** (it detaches HEAD for the shared repo and orphans later commits).

---

## File Structure

**New:**
- `charts/ectobase-hub/` — Chart.yaml, values.yaml, values.schema.json, `files/<role>/role.yaml` (generated), `templates/*`, `tests/*`.
- `charts/ectobase-pool/` — same shape plus `crd-bases/*.yaml` (generated).
- `test/crds/` — generated compute/storage/platform CRDs for envtest.
- `netplane/cmd/{controller,agent,vm-materializer,pod-materializer}/rbac.go` — marker-only doc files.
- `cni/rbac.go` (or `cni/plugin/rbac.go`, wherever `package main` for the plugin lives) — marker-only doc file.
- `hub/cmd/controller/rbac.go` — marker-only doc file.
- `hub/cmd/broker/rbac/hubside/doc.go`, `hub/cmd/broker/rbac/poolside/doc.go` — marker-only doc packages.

**Deleted (Task 8):** `deploy/charts/`, `config/`, `hub/config/`, `hack/sync-chart-crds.sh`, `deploy/charts/ectobase/tests/{render.sh,lib.sh}` (moved under `charts/`), `hub/config/crd/platform.ectobase.dev_clusterpools.yaml` (orphan).

**Modified:** `Makefile` (generate/chart-test targets), `flake.nix` (helm-unittest plugin), `test/lab/internal/deploy/ectobase.go`, `test/lab/topology/fabric.go`, `hub/hack/smoke.sh`, envtest CRD-path constants in `hub/test/*` and `netplane` envtests, docs/README references.

---

## Task 1: Add `//+kubebuilder:rbac` marker files (no behavior change)

Add marker-only Go files so controller-gen can generate each role. Rules are transcribed verbatim from the current working RBAC (cited per component). **The generated rules must equal today's rules exactly** — the live sweep is the only thing that catches a missing rule.

**Files:**
- Create: `netplane/cmd/controller/rbac.go`
- Create: `netplane/cmd/agent/rbac.go`
- Create: `netplane/cmd/vm-materializer/rbac.go`
- Create: `netplane/cmd/pod-materializer/rbac.go`
- Create: `cni/rbac.go` (place in the same `package main` as the CNI plugin entrypoint — confirm the package dir with `grep -rl "package main" cni/plugin cni/cmd 2>/dev/null | head`; the investigation found the entrypoint at `cni/plugin/main.go`, so `cni/plugin/rbac.go` unless a `cni/cmd` exists)
- Create: `hub/cmd/controller/rbac.go`
- Create: `hub/cmd/broker/rbac/hubside/doc.go`
- Create: `hub/cmd/broker/rbac/poolside/doc.go`

- [ ] **Step 1: netplane-controller markers** — transcribe from `config/deploy/rbac.yaml:64-132` (the `netplane-controller` ClusterRole).

`netplane/cmd/controller/rbac.go`:
```go
package main

// RBAC for the netplane compiler (netplane-controller). Rules generated into
// charts/ectobase-hub/files/netplane-controller/role.yaml by `make generate`
// (controller-gen rbac). Keep in sync with the reconcilers in netplane/controllers.

//+kubebuilder:rbac:groups=net.ectobase.dev,resources=natgateways,verbs=get;list;watch;update
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=natgateways/status,verbs=get;update
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=networkinterfaces,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=firewallpolicies;loadbalancers,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcs,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcpeerings,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcpeerings/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=virtualmachines,verbs=get;list;watch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=virtualmachines/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=containers,verbs=get;list;watch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=containers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=storage.ectobase.dev,resources=volumes,verbs=get;list;watch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compiledvms;compiledvolumeattachments;compiledcontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics/status;compiledvms/status;compiledvolumeattachments/status;compiledcontainers/status,verbs=get;update;patch
```

- [ ] **Step 2: netplane-agent markers** — transcribe from `config/deploy/rbac.yaml:26-59` (the `netplane-agent` ClusterRole; keep the full current grant set to avoid a live regression).

`netplane/cmd/agent/rbac.go`:
```go
package main

// RBAC for the netplane node agent. Rules generated into
// charts/ectobase-pool/files/netplane-agent/role.yaml by `make generate`.

//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcs;vpcs/status;networkinterfaces;networkinterfaces/status;natgateways;natgateways/status;loadbalancers;loadbalancers/status,verbs=get;list;watch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compilednics/status,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=networkinterfaces/status,verbs=update;patch
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch;patch
```

- [ ] **Step 3: vm-materializer markers** — transcribe from `config/deploy/vm-materializer.yaml:16-34`.

`netplane/cmd/vm-materializer/rbac.go`:
```go
package main

// RBAC for the vm-materializer. Rules generated into
// charts/ectobase-pool/files/vm-materializer/role.yaml by `make generate`.

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvms;compiledvolumeattachments,verbs=get;list;watch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvms/status;compiledvolumeattachments/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachines,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachineinstances,verbs=get;list;watch
//+kubebuilder:rbac:groups=cdi.kubevirt.io,resources=datavolumes,verbs=get;list;watch;create;update;patch;delete
```

- [ ] **Step 4: pod-materializer markers** — transcribe from `config/deploy/pod-materializer.yaml:18-27`.

`netplane/cmd/pod-materializer/rbac.go`:
```go
package main

// RBAC for the pod-materializer. Rules generated into
// charts/ectobase-pool/files/pod-materializer/role.yaml by `make generate`.

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledcontainers,verbs=get;list;watch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledcontainers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
```

- [ ] **Step 5: flowplane-cni markers** — transcribe from `deploy/charts/ectobase/templates/cni.yaml` (the `flowplane-cni` ClusterRole rules). First confirm the exact rules: `sed -n '/kind: ClusterRole/,/^---/p' deploy/charts/ectobase/templates/cni.yaml`. The investigation found: `pods[get]` (core) + `compilednics[get]` (compiled). Use exactly what the file shows.

`cni/plugin/rbac.go` (adjust dir to the plugin's `package main`):
```go
package main

// RBAC for the flowplane CNI plugin. Rules generated into
// charts/ectobase-pool/files/flowplane-cni/role.yaml by `make generate`.

//+kubebuilder:rbac:groups="",resources=pods,verbs=get
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics,verbs=get
```

- [ ] **Step 6: hub-controller markers** — transcribe from `hub/config/controller.yaml` (the `hub-controller` ClusterRole). Confirm exact rules: `sed -n '/kind: ClusterRole/,/^---/p' hub/config/controller.yaml`.

`hub/cmd/controller/rbac.go`:
```go
package main

// RBAC for the hub controller (clusterpool + scheduler + failover/fence).
// Rules generated into charts/ectobase-hub/files/hub-controller/role.yaml.

//+kubebuilder:rbac:groups=platform.ectobase.dev,resources=clusterpools,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=platform.ectobase.dev,resources=clusterpools/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=virtualmachines,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=virtualmachines/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvms;compilednics;compiledvolumeattachments,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvms/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=storage.ectobase.dev,resources=volumes,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=csiaddons.openshift.io,resources=networkfences,verbs=get;list;watch;create;update;patch;delete
```
(If the `sed` output differs from the above — e.g. extra verbs — the file is authoritative; match it.)

- [ ] **Step 7: hub-broker two marker-only sub-packages** — hub-side from the inline `brokerRBACManifest` const in `test/lab/internal/deploy/ectobase.go:428-462`; pool-side from `deploy/charts/ectobase/templates/rbac.yaml:177-191`.

`hub/cmd/broker/rbac/hubside/doc.go`:
```go
// Package hubside carries the hub-broker HUB-SIDE RBAC markers (the credential the
// broker uses against the hub aggregated apiserver). It holds only //+kubebuilder:rbac
// comments; controller-gen reads it by path (paths=./cmd/broker/rbac/hubside/...). It is
// imported nowhere. Split from poolside because controller-gen merges all markers under a
// package into one role, and the broker needs two distinct least-privilege roles.
package hubside

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compiledvms;compiledvolumeattachments;compiledcontainers,verbs=get;list;watch
//+kubebuilder:rbac:groups=platform.ectobase.dev,resources=clusterpools,verbs=get;list;watch;create;update;patch
//+kubebuilder:rbac:groups=platform.ectobase.dev,resources=clusterpools/status,verbs=get;update;patch
```

`hub/cmd/broker/rbac/poolside/doc.go`:
```go
// Package poolside carries the hub-broker POOL-SIDE (downstream, in-cluster) RBAC markers.
// Marker-only; read by controller-gen via paths=./cmd/broker/rbac/poolside/...; imported
// nowhere. See the hubside package for why the two roles are split.
package poolside

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compiledvms;compiledvolumeattachments;compiledcontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
//+kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachineinstances,verbs=get;list;watch
```

- [ ] **Step 8: Verify all modules still build** (marker files are valid Go).

Run:
```bash
nix develop --command bash -c 'go build ./netplane/... ./cni/... && cd hub && GOWORK=off go build ./...'
```
Expected: no output, exit 0. (The `hubside`/`poolside` packages compile as empty packages.)

- [ ] **Step 9: Commit**
```bash
git add netplane/cmd/controller/rbac.go netplane/cmd/agent/rbac.go \
  netplane/cmd/vm-materializer/rbac.go netplane/cmd/pod-materializer/rbac.go \
  cni/plugin/rbac.go hub/cmd/controller/rbac.go \
  hub/cmd/broker/rbac/hubside/doc.go hub/cmd/broker/rbac/poolside/doc.go
git commit -m "feat(rbac): add +kubebuilder:rbac markers per component for chart RBAC gen"
```

---

## Task 2: Rewire generation to emit CRDs + RBAC into the charts

Make `make generate` write CRDs and RBAC roles directly into the chart trees + `test/crds`; delete `sync-chart-crds.sh`. This runs before the charts have templates — the generated `files/` + `crd-bases/` land first so the templates written in Tasks 3-4 can `Files.Get` them.

**Files:**
- Modify: `Makefile` (the `generate` target lines 40-45; the `chart-sync-crds`/`chart-test` targets 233-240)
- Delete: `hack/sync-chart-crds.sh`
- Create (by running generate): `charts/ectobase-pool/crd-bases/*.yaml`, `test/crds/*.yaml`, `charts/ectobase-{hub,pool}/files/<role>/role.yaml`

- [ ] **Step 1: Rewrite the `generate` target.** Replace lines 40-45 of `Makefile` (the 5 `controller-gen crd` lines + the `sync-chart-crds.sh` call) with:

```make
	# CRDs: pool chart ships net + compiled; compute/storage/platform are hub-aggregated
	# (served by the hub apiserver, shipped in no chart) and generated to test/crds for envtest.
	cd api && controller-gen crd paths=./net/v1alpha1/... output:crd:artifacts:config=../charts/ectobase-pool/crd-bases
	cd api && controller-gen crd paths=./compiled/v1alpha1/... output:crd:artifacts:config=../charts/ectobase-pool/crd-bases
	cd api && controller-gen crd paths=./compute/v1alpha1/... output:crd:artifacts:config=../test/crds
	cd api && controller-gen crd paths=./storage/v1alpha1/... output:crd:artifacts:config=../test/crds
	cd api && controller-gen crd paths=./platform/v1alpha1/... output:crd:artifacts:config=../test/crds
	# RBAC: one ClusterRole rules file per component into each chart's files/<role>/.
	cd netplane && controller-gen rbac:roleName=netplane-controller paths=./cmd/controller/... output:rbac:artifacts:config=../charts/ectobase-hub/files/netplane-controller
	cd netplane && controller-gen rbac:roleName=netplane-agent paths=./cmd/agent/... output:rbac:artifacts:config=../charts/ectobase-pool/files/netplane-agent
	cd netplane && controller-gen rbac:roleName=vm-materializer paths=./cmd/vm-materializer/... output:rbac:artifacts:config=../charts/ectobase-pool/files/vm-materializer
	cd netplane && controller-gen rbac:roleName=pod-materializer paths=./cmd/pod-materializer/... output:rbac:artifacts:config=../charts/ectobase-pool/files/pod-materializer
	cd cni && controller-gen rbac:roleName=flowplane-cni paths=./... output:rbac:artifacts:config=../charts/ectobase-pool/files/flowplane-cni
	cd hub && controller-gen rbac:roleName=hub-controller paths=./cmd/controller/... output:rbac:artifacts:config=../charts/ectobase-hub/files/hub-controller
	cd hub && controller-gen rbac:roleName=hub-broker paths=./cmd/broker/rbac/hubside/... output:rbac:artifacts:config=../charts/ectobase-hub/files/hub-broker
	cd hub && controller-gen rbac:roleName=hub-broker paths=./cmd/broker/rbac/poolside/... output:rbac:artifacts:config=../charts/ectobase-pool/files/hub-broker
```
Keep the existing `cd api && ./hack/update-codegen.sh` and `cd hub && ./hack/update-codegen.sh` lines above (deepcopy/conversion unchanged). Remove the trailing `./hack/sync-chart-crds.sh`.

- [ ] **Step 2: Update the housekeeping targets.** Replace the `chart-sync-crds` target (lines 233-235) — delete it. Change `chart-test` (lines 237-239) to call helm-unittest (Task 5 wires the script; for now point it at both charts):
```make
.PHONY: chart-test
chart-test: ## Run the Helm chart unit tests (helm-unittest) for both charts.
	helm unittest charts/ectobase-hub charts/ectobase-pool
```

- [ ] **Step 3: Delete the sync script.**
```bash
git rm hack/sync-chart-crds.sh
```

- [ ] **Step 4: Run generate.**
```bash
nix develop --command bash -c 'make generate'
```
Expected: creates `charts/ectobase-pool/crd-bases/{net,compiled}.*.yaml` (11 files), `test/crds/{compute,storage,platform}.*.yaml` (4 files), and `charts/ectobase-{hub,pool}/files/<role>/role.yaml` (8 role files total). No errors.

- [ ] **Step 5: Verify generated RBAC matches the markers.** Spot-check one file:
```bash
cat charts/ectobase-pool/files/pod-materializer/role.yaml
```
Expected: a `ClusterRole` named `pod-materializer` whose `rules` list `compiledcontainers` (get/list/watch), `compiledcontainers/status` (get/update/patch), and core `pods` (all verbs). Confirm the two broker files differ:
```bash
diff charts/ectobase-hub/files/hub-broker/role.yaml charts/ectobase-pool/files/hub-broker/role.yaml
```
Expected: they differ (hub-side has clusterpools; pool-side has nodes + virtualmachineinstances + write verbs on compiled).

- [ ] **Step 6: Verify CRD counts.**
```bash
ls charts/ectobase-pool/crd-bases | wc -l   # expect 11 (net 7 + compiled 4)
ls test/crds | wc -l                        # expect 4 (compute 2 + storage 1 + platform 1)
```

- [ ] **Step 7: Commit generated artifacts + Makefile.**
```bash
git add Makefile charts/ectobase-hub/files charts/ectobase-pool/files \
  charts/ectobase-pool/crd-bases test/crds
git commit -m "feat(generate): emit CRDs + RBAC roles directly into charts + test/crds"
```

---

## Task 3: Author the `charts/ectobase-pool` chart

Port the pool-facing templates from `deploy/charts/ectobase`, dropping the vestigial hub-only bits, folding in the materializers, and wiring generated RBAC + CRDs.

**Files:**
- Create: `charts/ectobase-pool/Chart.yaml`, `values.yaml`, `values.schema.json`, `.helmignore`, `README.md`
- Create: `charts/ectobase-pool/templates/{namespace,crds,agent,agent-kubeconfig,broker,cni,dataplane-ebpf,dataplane-dpdk,kubevirt-binding,pod-materializer,vm-materializer,rbac}.yaml`, `templates/_helpers.tpl`, `templates/_validate.tpl`, `templates/tier1/*`
- Source of truth to port from: `deploy/charts/ectobase/` (templates, values.yaml, values.schema.json) + `config/deploy/{pod,vm}-materializer.yaml`

- [ ] **Step 1: Chart.yaml.**
```yaml
apiVersion: v2
name: ectobase-pool
description: ectobase compute-cluster ("pool") dataplane + per-cluster control-plane agents.
type: application
version: 0.1.0
appVersion: "dev"
```

- [ ] **Step 2: Copy the pool-facing templates verbatim, then edit.** Copy these from `deploy/charts/ectobase/templates/` into `charts/ectobase-pool/templates/`: `namespace.yaml`, `crds.yaml`, `agent.yaml`, `agent-kubeconfig.yaml`, `broker.yaml`, `cni.yaml`, `dataplane-ebpf.yaml`, `dataplane-dpdk.yaml`, `kubevirt-binding.yaml`, `_validate.tpl`, `tier1/*`. **Do NOT copy** `controller.yaml`, `reflector.yaml`, `crds.yaml` stays. Create a `_helpers.tpl` with `ectobase-pool.labels`/`ectobase-pool.name` helpers (mirror any existing `_helpers.tpl`; if the old chart has none, add a minimal one):
```yaml
{{- define "ectobase-pool.labels" -}}
app.kubernetes.io/part-of: ectobase
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
```

- [ ] **Step 3: Rewrite `templates/rbac.yaml`** to declare SA + ClusterRole shell + Binding per pool role, injecting generated rules. The pool roles are `netplane-agent`, `hub-broker` (pool-side), `flowplane-cni` lives in `cni.yaml` already (keep its SA/Deployment there but switch its ClusterRole to Files.Get), `vm-materializer`, `pod-materializer`. Pattern per role:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: netplane-agent
  namespace: {{ .Values.namespace }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: netplane-agent
  labels: {{- include "ectobase-pool.labels" . | nindent 4 }}
rules:
  {{- (.Files.Get "files/netplane-agent/role.yaml" | fromYaml).rules | toYaml | nindent 2 }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: netplane-agent
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: netplane-agent
subjects:
  - kind: ServiceAccount
    name: netplane-agent
    namespace: {{ .Values.namespace }}
```
Repeat for `hub-broker` (pool-side; drop the old `{{- if .Values.broker.enabled }}` gate — this chart always runs the broker), `vm-materializer` (gate the whole block `{{- if .Values.vmMaterializer.enabled }}`), `pod-materializer`. Keep the `netplane-reflector` SA **out** (reflector is hub-only now). Move the `flowplane-cni` ClusterRole rules in `cni.yaml` to `.Files.Get "files/flowplane-cni/role.yaml"` the same way.

- [ ] **Step 4: Add materializer Deployments.** Port the `Deployment` bodies from `config/deploy/pod-materializer.yaml:41-68` and `config/deploy/vm-materializer.yaml:48-76` into `templates/pod-materializer.yaml` and `templates/vm-materializer.yaml`. Template the image (`{{ .Values.images.netplane }}`) and pull policy; gate vm-materializer's Deployment with `{{- if .Values.vmMaterializer.enabled }}`. (The SA/RBAC for both live in `rbac.yaml` from Step 3.)

- [ ] **Step 5: values.yaml + values.schema.json.** Copy `deploy/charts/ectobase/values.yaml`, then: add `namespace: ectobase-system`; **remove** the `broker.enabled` gate concept (keep `broker.clusterName` + `broker.hubKubeconfigSecret`; the broker always runs); add `vmMaterializer: {enabled: false}`; remove hub-only keys that no longer apply (none of `reflectorAddress`/`apiserverAddress`/`uplink`/`underlayWithin` are hub-only — keep them). Copy `values.schema.json` and update it to match (drop `broker.enabled` required-ness, add `vmMaterializer`, add `namespace`). If schema edits are fiddly, run `helm template` (next step) which validates against the schema and reports the exact mismatch.

- [ ] **Step 6: Render + lint.**
```bash
nix develop --command bash -c '
  helm template ectobase-pool charts/ectobase-pool -n ectobase-system \
    --set broker.clusterName=k02 --set vmMaterializer.enabled=true >/tmp/pool.yaml &&
  helm lint charts/ectobase-pool &&
  grep -c "kind: ClusterRole" /tmp/pool.yaml'
```
Expected: template succeeds, lint passes, and the rendered output contains the generated rules (grep the file for e.g. `compiledcontainers` to confirm Files.Get injected them). Verify no `netplane-controller`/`reflector` objects rendered: `grep -E "name: (netplane-controller|reflector)" /tmp/pool.yaml` → no matches.

- [ ] **Step 7: Commit.**
```bash
git add charts/ectobase-pool
git commit -m "feat(charts): add ectobase-pool chart (generated RBAC + CRDs, materializers)"
```

---

## Task 4: Author the `charts/ectobase-hub` chart

Fold `hub/config` + the hub-only `config/deploy` manifests into a chart, with the reflector-admin address as a value and generated RBAC.

**Files:**
- Create: `charts/ectobase-hub/Chart.yaml`, `values.yaml`, `values.schema.json`, `.helmignore`, `README.md`
- Create: `charts/ectobase-hub/templates/{namespace,kine,apiserver,apiservice,hub-controller,compiler,reflector,rbac,broker-identity}.yaml`, `_helpers.tpl`
- Source: `hub/config/{namespace,kine,apiserver,apiservice,controller}.yaml`, `config/deploy/{controller,reflector}.yaml` (the netplane compiler + reflector), and `brokerRBACManifest` in `test/lab/internal/deploy/ectobase.go:428-462`.

- [ ] **Step 1: Chart.yaml.**
```yaml
apiVersion: v2
name: ectobase-hub
description: ectobase fleet control-plane ("hub") — aggregated apiserver, controller, compiler, reflector.
type: application
version: 0.1.0
appVersion: "dev"
```

- [ ] **Step 2: Port the hub infra templates verbatim, then parametrize.** Copy into `templates/`: `namespace.yaml`, `kine.yaml`, `apiserver.yaml` (+ its aggregation RBAC bindings), `apiservice.yaml`, `hub-controller.yaml` (from `hub/config/controller.yaml` — but replace its inline ClusterRole with the Files.Get pattern, Step 4), `compiler.yaml` (the netplane compiler Deployment from `config/deploy/controller.yaml`), `reflector.yaml` (from `config/deploy/reflector.yaml`). Set `namespace: {{ .Values.namespace }}` (default `system`) where these hardcode `system`/`ectobase-system` — **note the hub uses `system`** for hub-apiserver/controller/broker-identity but the compiler + reflector were applied to `ectobase-system` by the lab. Preserve each object's original namespace (hub infra → `system`; compiler/reflector/its SAs → `ectobase-system`); make both namespaces values (`namespace: system`, `agentNamespace: ectobase-system`) so nothing silently moves. Confirm original namespaces by reading each source file before porting.

- [ ] **Step 3: Template the reflector-admin address.** In `hub-controller.yaml`, replace the hardcoded `-reflector-admin=[fd00:db8:0:1::1]:1338` arg with `-reflector-admin={{ .Values.reflectorAdmin }}` (default `[fd00:db8:0:1::1]:1338`). This retires the lab's runtime `patchHubReflectorAdmin`.

- [ ] **Step 4: Generated RBAC for `netplane-controller`, `hub-controller`, `hub-broker` (hub-side).** In `templates/rbac.yaml` (compiler + hub-controller) and `templates/broker-identity.yaml` (hub-side broker SA in `system`), use the same SA + ClusterRole-shell + Binding + `.Files.Get "files/<role>/role.yaml"` pattern as Task 3 Step 3. The `netplane-controller` SA/binding go in `ectobase-system` (matches the compiler Deployment); `hub-controller` + `hub-broker` identity go in `system`. Keep the hub-apiserver aggregation RBAC (auth-delegator ClusterRoleBinding, extension-apiserver-authentication-reader RoleBinding in kube-system, dev cluster-admin binding) **hand-written** in `apiserver.yaml` exactly as in `hub/config/apiserver.yaml:22-69` (not generated).

- [ ] **Step 5: values.yaml + values.schema.json.** Include: `namespace: system`, `agentNamespace: ectobase-system`, `reflectorAdmin: "[fd00:db8:0:1::1]:1338"`, `images: {hubApiserver, hubController, hubBroker, netplane, ...}` (pull the image refs from the source manifests), `imagePullPolicy`. Add a minimal `values.schema.json`.

- [ ] **Step 6: Render + lint.**
```bash
nix develop --command bash -c '
  helm template ectobase-hub charts/ectobase-hub -n system >/tmp/hub.yaml &&
  helm lint charts/ectobase-hub &&
  grep -E "kind: (APIService|Deployment|ClusterRole)" /tmp/hub.yaml | sort | uniq -c'
```
Expected: renders 5 APIServices, the apiserver/controller/compiler/reflector Deployments, kine, and the generated ClusterRoles. Confirm `grep reflector-admin /tmp/hub.yaml` shows the templated default, and no `crd-bases`/CRD objects render (hub ships none).

- [ ] **Step 7: Commit.**
```bash
git add charts/ectobase-hub
git commit -m "feat(charts): add ectobase-hub chart (apiserver/controller/compiler/reflector, generated RBAC)"
```

---

## Task 5: helm-unittest wiring + tests (replace render.sh)

**Files:**
- Modify: `flake.nix` (wrap helm with the unittest plugin)
- Create: `charts/ectobase-hub/tests/*_test.yaml`, `charts/ectobase-pool/tests/*_test.yaml`, and their `__snapshot__/` (generated on first run)
- Modify: `Makefile` `chart-test` (done in Task 2; confirm)
- Delete (in Task 8): the old `deploy/charts/ectobase/tests/{render.sh,lib.sh,values/*}` — but port the value permutations into helm-unittest cases here.

- [ ] **Step 1: Add helm-unittest to the devShell.** In `flake.nix`, replace `pkgs.kubernetes-helm` (line ~125) with a plugin-wrapped helm:
```nix
(pkgs.kubernetes-helm.withPlugins (plugins: [ plugins.helm-unittest ]))
```
If `withPlugins` is not exposed on `kubernetes-helm` in this nixpkgs pin, use `pkgs.wrapHelm pkgs.kubernetes-helm { plugins = [ pkgs.kubernetes-helmPlugins.helm-unittest ]; }`.

- [ ] **Step 2: Verify the plugin loads.**
```bash
nix develop --command bash -c 'helm unittest --help >/dev/null && echo OK'
```
Expected: `OK`.

- [ ] **Step 3: Pool chart tests.** Create `charts/ectobase-pool/tests/rbac_test.yaml` asserting the generated rules landed (guards against a marker regression), plus a snapshot:
```yaml
suite: pool rbac + rendering
templates:
  - templates/rbac.yaml
tests:
  - it: netplane-agent ClusterRole carries the compiled read rule
    set:
      broker.clusterName: k02
    asserts:
      - contains:
          path: rules
          content:
            apiGroups: ["compiled.ectobase.dev"]
            resources: ["compilednics", "compilednics/status"]
            verbs: ["get", "list", "watch"]
        template: templates/rbac.yaml
        documentIndex: 1
```
Add `charts/ectobase-pool/tests/snapshot_test.yaml` doing `matchSnapshot` over the whole chart for the representative value sets that `deploy/charts/ectobase/tests/values/*.yaml` covered (ebpf-clab, ebpf-hw, dpdk-clab, dpdk-hw, tier1-on) plus `vmMaterializer.enabled=true`:
```yaml
suite: pool render snapshots
tests:
  - it: renders (ebpf clab)
    values: [../../../deploy/charts/ectobase/tests/values/ebpf-clab.yaml]  # inline the values here instead once the old chart is deleted
    asserts:
      - matchSnapshot: {}
```
**Note:** since the old `deploy/charts/.../tests/values/*` are deleted in Task 8, copy those value files into `charts/ectobase-pool/tests/values/` and reference the copies. Add a `failedTemplate` assert exercising a `_validate.tpl` guard (e.g. an invalid `dataplane`):
```yaml
  - it: rejects an unknown dataplane
    set: {dataplane: bogus}
    asserts:
      - failedTemplate: {}
```

- [ ] **Step 4: Hub chart tests.** Create `charts/ectobase-hub/tests/{rbac_test.yaml,snapshot_test.yaml}`: assert the `hub-broker` hub-side ClusterRole contains the `clusterpools` write rule and does NOT contain `virtualmachineinstances` (proving the two-package split produced distinct roles), assert the `reflector-admin` arg templates, and a whole-chart `matchSnapshot`.

- [ ] **Step 5: Generate + review snapshots.**
```bash
nix develop --command bash -c 'helm unittest charts/ectobase-hub charts/ectobase-pool'
```
Expected: first run writes `__snapshot__/*.snap` and passes. **Review the `.snap` files** (they are the goldens replacing config/deploy) before committing — confirm RBAC rules, images, namespaces look right.

- [ ] **Step 6: Commit.**
```bash
git add flake.nix charts/ectobase-hub/tests charts/ectobase-pool/tests
git commit -m "test(charts): helm-unittest suites + snapshots; wire helm-unittest into devShell"
```

---

## Task 6: Repoint envtest CRD paths

Envtests loaded CRDs from `config/crd/bases`; that dir is deleted in Task 8. Point them at `charts/ectobase-pool/crd-bases` + `test/crds`.

**Files:**
- Modify: whichever envtest setup files reference `config/crd/bases`. Find them: `grep -rn "config/crd/bases" --include='*.go' .`
- Likely: a shared `envtest` helper in `netplane/` and `hub/test/*` (`broker_test.go`, `ceph_e2e_test.go`, `phase4_e2e_test.go` reference it in comments; find the real `CRDDirectoryPaths`/`CRDInstallOptions.Paths` assignment).

- [ ] **Step 1: Locate the CRD path assignments.**
```bash
grep -rn -e 'config/crd/bases' -e 'CRDDirectoryPaths' -e 'CRDInstallOptions' --include='*.go' netplane hub
```

- [ ] **Step 2: Repoint each.** Replace the single `config/crd/bases` path with the two new dirs. For a repo-root-relative resolver, compute the paths as `charts/ectobase-pool/crd-bases` and `test/crds`. Example (adapt to the actual helper):
```go
CRDDirectoryPaths: []string{
    filepath.Join(repoRoot, "charts", "ectobase-pool", "crd-bases"),
    filepath.Join(repoRoot, "test", "crds"),
},
```
Envtests that only need `compiled`/`net` can use just the pool dir; those exercising VM/Volume/ClusterPool need `test/crds` too — add both everywhere to be safe (extra CRDs are harmless in envtest).

- [ ] **Step 3: Run the envtests.**
```bash
nix develop --command bash -c 'go test ./netplane/... 2>&1 | tail -30'
nix develop --command bash -c 'cd hub && GOWORK=off go test ./... 2>&1 | tail -30'
```
Expected: green (same pass set as before the change). If a test errors with "no matches for kind", it needs `test/crds` added to its paths.

- [ ] **Step 4: Commit.**
```bash
git add -- netplane hub   # only the modified *_test.go / envtest helper files — verify with git status first
git commit -m "test(envtest): load CRDs from charts/ectobase-pool/crd-bases + test/crds"
```

---

## Task 7: Rewire the lab to deploy the two charts

Replace the manifest-cherry-picking in the lab with two `helm install`s + Go fixtures.

**Files:**
- Modify: `test/lab/internal/deploy/ectobase.go` (the whole `Ectobase` flow + `helmInstallEctobase` + `brokerRBACManifest`/`patchHubReflectorAdmin` removal)
- Modify: `test/lab/topology/fabric.go` (`ChartPath` → two chart paths; the tier2 vm-materializer manifest apply → `--set vmMaterializer.enabled=true`)
- Modify: `hub/hack/smoke.sh` (`kubectl apply -k hub/config` → `helm install ectobase-hub`)

- [ ] **Step 1: Hub-side install.** In `Ectobase`, replace the `kubectlApplyKustomize(hub/config)` + `patchHubReflectorAdmin` + the `config/deploy/{namespace,rbac,reflector,controller}.yaml` applies + the `brokerRBACManifest` apply with a single `helm upgrade --install ectobase-hub <hubChartPath>` on the hub kubeconfig, passing `--set reflectorAdmin=[<HubIdentity>]:1338` and the image values. Keep `waitAggregatedAPI` after. Keep the PSA-privileged labeling of the hub namespaces (still needed on Talos) as a fixture step, or move the `pod-security...=privileged` label into the hub chart's `namespace.yaml`.

- [ ] **Step 2: Broker token + kubeconfig fixture (unchanged logic).** Keep `kubectl create token hub-broker -n system`, `mintKubeconfig`, and the ClusterPool pre-create — the hub-side `hub-broker` SA now comes from the hub chart (Step 1), so the token mint targets it. Keep `clusterPoolsManifest` as a fixture.

- [ ] **Step 3: Pool-side install.** Rewrite `helmInstallEctobase` to install `ectobase-pool`:
```go
args := []string{"upgrade", "--install", "ectobase-pool", chartPath,
    "--kubeconfig", kubeconfig,
    "--namespace", "ectobase-system", "--create-namespace",
    "--set", "broker.clusterName=" + clusterName,
    "--set", "apiserverAddress=https://127.0.0.1:6443",
    "--set", "reflectorAddress=[" + hubIdentity + "]:1338",
    "--set", "installCRDs=true",
    "--set", "dataplane=ebpf",
}
```
Remove the `broker.enabled=true` set (the pool chart always runs the broker). Drop the separate `config/deploy/pod-materializer.yaml` apply (`PodMaterializer` call) — pod-materializer ships in the pool chart now. For tier2, pass `--set vmMaterializer.enabled=true` (replace `fabric.go`'s `config/deploy/vm-materializer.yaml` apply).

- [ ] **Step 4: Update `EctobaseSpec`/`fabric.go` chart paths.** Change `ChartPath` to the pool chart, add a `HubChartPath` field, set both in `fabric.go` (`filepath.Join(root, "charts/ectobase-pool")` and `.../ectobase-hub`). Remove the now-dead `PodMaterializer`/`VMMaterializer` manifest-path plumbing (or repoint to `--set`).

- [ ] **Step 5: Build the lab + hub.**
```bash
nix develop --command bash -c 'go build ./test/lab/... && cd hub && GOWORK=off go build ./...'
```
Expected: exit 0. Run the deploy unit tests if any: `go test ./test/lab/internal/deploy/...`.

- [ ] **Step 6: Update `hub/hack/smoke.sh`** to `helm upgrade --install ectobase-hub charts/ectobase-hub -n system --create-namespace` instead of `kubectl apply -k hub/config` (or delete the script if the lab `up` fully covers it — check whether anything invokes it: `grep -rn smoke.sh .`). Keep its post-install assertion (`kubectl get clusterpools.platform.ectobase.dev`).

- [ ] **Step 7: Commit.**
```bash
git add test/lab/internal/deploy/ectobase.go test/lab/topology/fabric.go hub/hack/smoke.sh
git commit -m "feat(lab): deploy ectobase-hub + ectobase-pool charts via helm; retire config/deploy applies"
```

---

## Task 8: Delete the old trees + sweep dangling references

**Files:**
- Delete: `deploy/charts/`, `config/`, `hub/config/`
- Verify no references remain anywhere.

- [ ] **Step 1: Grep for every reference before deleting.**
```bash
grep -rn -e 'deploy/charts' -e 'config/deploy' -e 'config/crd' -e 'config/samples' \
  -e 'hub/config' -e 'sync-chart-crds' --include='*.go' --include='*.sh' \
  --include='*.md' --include='Makefile' --include='*.nix' . | grep -v '/target/'
```
Expected after Tasks 1-7: only hits in the spec/plan docs + this task's own deletions. Fix any live code/script/doc reference found (README, docs/book, any hack script).

- [ ] **Step 2: Delete the trees.**
```bash
git rm -r deploy/charts config hub/config
```

- [ ] **Step 3: Full static gate.**
```bash
nix develop --command bash -c '
  go build ./netplane/... ./cni/... ./test/lab/... &&
  cd hub && GOWORK=off go build ./... && cd .. &&
  go test ./netplane/... &&
  (cd hub && GOWORK=off go test ./...) &&
  make chart-test &&
  make generate && git diff --stat'
```
Expected: all builds/tests pass; `make chart-test` green; **`make generate` produces an empty git diff** (generation is idempotent and everything is committed). If `git diff` is non-empty, commit the regenerated output.

- [ ] **Step 4: Rust gate (pre-commit parity).**
```bash
nix develop --command bash -c 'cargo fmt --all -- --check && cargo clippy --all-targets 2>&1 | tail -5'
```
Expected: clean (this effort touches no Rust, so this should be a no-op pass).

- [ ] **Step 5: Commit.**
```bash
git add -- Makefile README.md docs   # whatever Step 1 fixed; verify with git status
git rm was already staged in Step 2
git commit -m "chore: delete deploy/charts, config/, hub/config; charts are the deploy artifact"
```

- [ ] **Step 6: Verify branch ref advanced** (guard against the detached-HEAD hazard):
```bash
git branch --show-current   # feat/charts-toplevel-generated-rbac
git log --oneline -9        # Tasks 1-8 commits present, linear
```

---

## Task 9: Live clab sweep (main loop drives this — not a subagent)

The live sweep is the real acceptance gate; envtests pass without RBAC so only this catches deploy-path role gaps. **Run from the main loop yourself**, not a subagent (git-sensitive + long-running + needs sudo).

- [ ] **Step 1: Ensure a clean fabric + safe.directory for root builds.**
```bash
sudo git config --system --add safe.directory "$(pwd)"
```

- [ ] **Step 2: Run the sweep.**
```bash
sudo -E env "PATH=$PATH" ./hack/r3-live-sweep.sh 2>&1 | tee /tmp/effort2-sweep.log | tail -40
```
Expected: `ok test/lab/livetest` with **21/21** (TestPodOverlayPing / VPCPeering / CrossClusterOverlayPing / Tier2Failover / DhcpLeaseSmoke / NatEgressSmoke / QoSGuestToGuest). Tier2Failover may need a fresh fabric (Ceph `MON_DISK_LOW` on an aged fabric is unrelated — a fresh `lab up` restores it).

- [ ] **Step 3: Triage any failure** with systematic-debugging. The likeliest failure mode is a generated role missing a rule a component needs at runtime (a marker that didn't reproduce the old rule) — compare the deployed ClusterRole against the pre-change YAML the markers were transcribed from. Fix the marker, `make generate`, redeploy, re-run.

- [ ] **Step 4: On green, update memory** (`central-to-hub-rename.md` Effort-2 section → DONE; or a new `charts-toplevel-generated-rbac.md`) and report. Do not merge until the user asks (finishing-a-development-branch).

---

## Self-review notes (author)

- **Spec coverage:** two charts (T3/T4), generated CRDs (T2) + RBAC (T1/T2), config+hub/config+sync-script deletion (T8), test/crds fixtures (T2/T6), helm-unittest (T5), lab rewiring to helm (T7), two-package broker roles (T1/T2), live sweep gate (T9). All spec sections mapped.
- **RBAC exactness** is the load-bearing risk; every marker step cites the exact source file+lines to transcribe from, and T5 asserts rules + T9 validates live.
- **Ordering:** markers → generation → charts (so `Files.Get` targets exist) → tests → envtest repoint → lab → deletion → live. Deletion is last so nothing references the old trees mid-flight.
- **Namespaces:** hub infra stays in `system`, compiler/reflector/pool in `ectobase-system` — T4 Step 2 calls this out explicitly to avoid a silent move.
