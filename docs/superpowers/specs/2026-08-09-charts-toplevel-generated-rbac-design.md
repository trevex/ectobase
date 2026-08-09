# Effort 2: top-level charts + generated CRDs/RBAC (hub + pool split)

**Date:** 2026-08-09
**Branch:** `feat/charts-toplevel-generated-rbac`
**Predecessors (merged to main, not pushed):** API restructure (5 groups in the shared `api/` module) and the `central`→`hub` rename. This is Effort 2 of the post-restructure layout work.

## Problem

The Helm chart at `deploy/charts/ectobase` is hand-maintained and drifts against the manifests the lab actually applies. RBAC in particular is duplicated across **five** places that fall out of sync (this caused the R3 "7 deploy-path RBAC bugs" saga):

- `deploy/charts/ectobase/templates/rbac.yaml` (netplane-agent + netplane-controller + conditional hub-broker)
- `config/deploy/rbac.yaml` (near-duplicate, applied to the hub cluster)
- an inline Go string const `brokerRBACManifest` in `test/lab/internal/deploy/ectobase.go` (the hub-side `hub-broker` identity)
- `config/deploy/{vm,pod}-materializer.yaml` (standalone materializer roles)
- `hub/config/controller.yaml` (hub-controller role)

The chart is also **one chart for two audiences**. The single chart renders a `netplane-controller` compiler Deployment and a `reflector` Deployment on **every compute cluster**, where both are vestigial — the real compiler and reflector run only on the hub. CRD generation flows through `config/crd/bases` → `hack/sync-chart-crds.sh` → chart, an indirection that goes stale (the R3 lesson: `crd-bases/` silently kept an old-group CRD).

## Goals

1. Move the chart to a **top-level `charts/`** dir and split it into two charts matching the two real install targets:
   - `charts/ectobase-hub` — the fleet control-plane ("hub") cluster.
   - `charts/ectobase-pool` — each compute ("pool"/`ClusterPool`) cluster.
2. Make the charts the **generated deploy artifact**: CRDs via `controller-gen crd` written directly into the chart, RBAC via `controller-gen rbac` from `//+kubebuilder:rbac` markers (SolAr pattern). No hand-maintained role YAML, no `sync-chart-crds.sh`.
3. **Eliminate `config/deploy/` and `hub/config/`** entirely. Helm is the product deploy surface (charts released as OCI in future). The lab deploys the same charts a user would; lab-only credentials/objects become fixtures.
4. Replace `render.sh` golden-diffs (which diffed chart output against `config/deploy`) with **helm-unittest** per chart.
5. Keep the live clab sweep (`hack/r3-live-sweep.sh`) **21/21 green** as the acceptance gate.

## Non-goals

- No datapath / control-plane behavior change. This is layout, generation, and deploy-wiring only.
- No change to the API groups/types (Effort done).
- Blue-green operator (thread C) stays deferred; its values stanza is carried unchanged.

## Target layout

```
charts/
  ectobase-hub/
    Chart.yaml
    files/
      netplane-controller/role.yaml   # GENERATED (controller-gen rbac)
      hub-controller/role.yaml        # GENERATED
      hub-broker/role.yaml            # GENERATED (hub-side)
    templates/
      namespace.yaml            # `system` ns (configurable)
      kine.yaml                 # kine + postgres (from hub/config/kine.yaml)
      apiserver.yaml            # hub-apiserver Deployment + Service (from hub/config/apiserver.yaml)
      apiservice.yaml           # 5 APIServices + aggregation RBAC (from hub/config/apiservice.yaml + apiserver.yaml auth bindings)
      hub-controller.yaml       # Deployment (from hub/config/controller.yaml), reflector-admin address templated
      compiler.yaml             # netplane-controller Deployment (from config/deploy/controller.yaml)
      reflector.yaml            # reflector Deployment + Service (from config/deploy/reflector.yaml)
      rbac.yaml                 # SA + ClusterRole shell + Binding per hub role; rules via Files.Get
      broker-identity.yaml      # hub-side hub-broker SA + ClusterRole shell + Binding (system ns)
      _helpers.tpl, _validate.tpl
    values.yaml, values.schema.json
    tests/
      *_test.yaml               # helm-unittest
      __snapshot__/
  ectobase-pool/
    Chart.yaml
    crd-bases/*.yaml            # GENERATED: net.* (7) + compiled.* (4) = 11
    files/
      netplane-agent/role.yaml       # GENERATED
      hub-broker/role.yaml           # GENERATED (pool-side)
      flowplane-cni/role.yaml        # GENERATED
      vm-materializer/role.yaml      # GENERATED
      pod-materializer/role.yaml     # GENERATED
    templates/
      namespace.yaml            # `ectobase-system` ns (configurable)
      crds.yaml                 # glob crd-bases/*.yaml under .Values.installCRDs
      agent.yaml, agent-kubeconfig.yaml
      broker.yaml               # pool-side broker (was gated broker.enabled; now unconditional in this chart)
      cni.yaml
      dataplane-ebpf.yaml, dataplane-dpdk.yaml
      kubevirt-binding.yaml     # NetworkAttachmentDefinition `flowplane`
      pod-materializer.yaml     # Deployment (from config/deploy/pod-materializer.yaml)
      vm-materializer.yaml      # Deployment, gated .Values.vmMaterializer.enabled
      tier1/*                   # gated .Values.tier1Failover.enabled
      rbac.yaml                 # SA + ClusterRole shell + Binding per pool role; rules via Files.Get
      _helpers.tpl, _validate.tpl
    values.yaml, values.schema.json
    tests/
test/crds/                      # GENERATED: compute.* (2) + storage.* (1) + platform.* (1); envtest-only fixtures
```

**Deleted:** `deploy/charts/` (whole tree), `config/` (whole tree: `config/deploy`, `config/crd`, `config/samples`), `hub/config/` (whole tree), `hack/sync-chart-crds.sh`.

## Component placement (from the investigation)

| Component | Chart | Notes |
|---|---|---|
| kine (+ postgres) | hub | from `hub/config/kine.yaml` |
| hub-apiserver + APIService + aggregation RBAC | hub | serves all 5 groups aggregated → **no CRDs on the hub** |
| hub-controller | hub | reflector-admin address becomes a value (retires `patchHubReflectorAdmin`) |
| netplane compiler (`netplane-controller`) | hub | was vestigial on pools; moves here |
| reflector | hub | was vestigial on pools; moves here |
| hub-side `hub-broker` identity (SA+role, `system` ns) | hub | was the inline `brokerRBACManifest` const |
| agent + agent-kubeconfig | pool | |
| pool-side broker | pool | unconditional in the pool chart (drops the `broker.enabled` gate) |
| cni | pool | |
| dataplane (ebpf / dpdk) | pool | selected by `.Values.dataplane` as today |
| kubevirt-binding NAD | pool | rendered unconditionally (KubeVirt CR references `ectobase-system/flowplane`) |
| pod-materializer | pool | base substrate, always on |
| vm-materializer | pool | gated `.Values.vmMaterializer.enabled` (lab sets it for tier2) |
| tier1 failover | pool | gated `.Values.tier1Failover.enabled` |

**CRDs:** hub chart ships **none** (aggregated apiserver). Pool chart ships **net.\* (7) + compiled.\* (4)** — the agent reads `net/{networkinterfaces,loadbalancers}` and the broker/materializers/cni read `compiled.*` from the pool-local apiserver; nothing on the pool reads `compute/storage/platform`. `compute.* + storage.* + platform.*` are generated into `test/crds/` for envtest only. The orphan `hub/config/crd/platform.ectobase.dev_clusterpools.yaml` is deleted (dead pre-aggregation file — `platform` is served aggregated; it was applied nowhere).

**Lab fixtures (stay in `test/lab` Go, not charts):** broker→hub token mint, the `broker-hub-kubeconfig` Secret, ClusterPool pre-create, and the Talos PSA-privileged namespace labeling glue.

## RBAC generation (SolAr pattern)

Each component gets an **aggregate `//+kubebuilder:rbac` marker block on a dedicated `rbac.go` doc file** next to its binary's `main.go` (uniform for controller-runtime, client-go-loop, and CNI-skel binaries; and it avoids the shared `netplane/controllers` package where compiler + materializer markers would otherwise merge into one role). The marker home is a `rbac.go` in `package main` holding only doc-comment markers — no logic.

Per-role generation (one invocation per role → `files/<role>/role.yaml`):

```
# from netplane/  (hub chart)
controller-gen rbac:roleName=netplane-controller paths=./cmd/controller/... \
  output:rbac:artifacts:config=../charts/ectobase-hub/files/netplane-controller
# from hub/  (hub chart)
controller-gen rbac:roleName=hub-controller paths=./cmd/controller/... \
  output:rbac:artifacts:config=../charts/ectobase-hub/files/hub-controller
controller-gen rbac:roleName=hub-broker paths=./cmd/broker/rbac/hubside/... \
  output:rbac:artifacts:config=../charts/ectobase-hub/files/hub-broker
# from netplane/  (pool chart)
controller-gen rbac:roleName=netplane-agent paths=./cmd/agent/... \
  output:rbac:artifacts:config=../charts/ectobase-pool/files/netplane-agent
controller-gen rbac:roleName=vm-materializer paths=./cmd/vm-materializer/... \
  output:rbac:artifacts:config=../charts/ectobase-pool/files/vm-materializer
controller-gen rbac:roleName=pod-materializer paths=./cmd/pod-materializer/... \
  output:rbac:artifacts:config=../charts/ectobase-pool/files/pod-materializer
# from hub/  (pool chart)
controller-gen rbac:roleName=hub-broker paths=./cmd/broker/rbac/poolside/... \
  output:rbac:artifacts:config=../charts/ectobase-pool/files/hub-broker
# from cni/  (pool chart)
controller-gen rbac:roleName=flowplane-cni paths=./... \
  output:rbac:artifacts:config=../charts/ectobase-pool/files/flowplane-cni
```

`controller-gen rbac` writes exactly `role.yaml` per `output` dir (fixed filename), so per-component sub-dirs give one role each. The chart template owns the ClusterRole shell (chart-scoped name/labels), SA, and Binding, and injects only the generated rules:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: netplane-controller
  labels: {{- include "ectobase-hub.labels" . | nindent 4 }}
rules:
  {{- (.Files.Get "files/netplane-controller/role.yaml" | fromYaml).rules | toYaml | nindent 2 }}
```

**hub-broker two-role handling (decided):** the broker binary needs different least-privilege roles on the hub (read `compiled.*`, read/write `clusterpools` + status) vs the pool (read/write `compiled.*`, read `nodes`, read `kubevirt/virtualmachineinstances`). Because controller-gen merges all markers found under `paths=`, the two role definitions live in **two marker-only sub-packages**: `hub/cmd/broker/rbac/hubside/doc.go` and `hub/cmd/broker/rbac/poolside/doc.go` (pure `//+kubebuilder:rbac` comments, imported nowhere; controller-gen reads them by path). Hub-side role → hub chart; pool-side → pool chart.

**Not generated (hand-written chart YAML, as SolAr does for its apiserver/leader-election RBAC):**
- hub-apiserver aggregation RBAC: `ClusterRoleBinding` to `system:auth-delegator`, `RoleBinding` to `extension-apiserver-authentication-reader` in `kube-system`, and the dev-only `cluster-admin` binding.
- No-rules `ServiceAccount`s (reflector).
- Any leader-election namespaced `Role`s the controllers need (verify per binary during implementation; add hand-written if present).

Rule content per generated role is transcribed from the existing YAML the investigation catalogued (`config/deploy/rbac.yaml`, chart `rbac.yaml`, `config/deploy/{vm,pod}-materializer.yaml`, `hub/config/controller.yaml`, chart `cni.yaml`, and the inline `brokerRBACManifest`), so the generated output is rule-equivalent to today's working deploy — **the markers must reproduce the current rules exactly** (verified by the live sweep, which is the only thing that catches deploy-path RBAC gaps).

## CRD generation

`make generate` replaces the `config/crd/bases` + `sync-chart-crds.sh` flow with direct output:

```
# from api/
controller-gen crd paths=./net/v1alpha1/...      output:crd:artifacts:config=../charts/ectobase-pool/crd-bases
controller-gen crd paths=./compiled/v1alpha1/...  output:crd:artifacts:config=../charts/ectobase-pool/crd-bases
controller-gen crd paths=./compute/v1alpha1/...   output:crd:artifacts:config=../test/crds
controller-gen crd paths=./storage/v1alpha1/...   output:crd:artifacts:config=../test/crds
controller-gen crd paths=./platform/v1alpha1/...  output:crd:artifacts:config=../test/crds
```

Pool chart installs its `crd-bases/*.yaml` via `templates/crds.yaml` (glob) gated on `.Values.installCRDs` (keeps helm-upgrade-managed CRDs, as today). Envtests set `CRDDirectoryPaths` to `charts/ectobase-pool/crd-bases` + `test/crds`.

## Chart tests (helm-unittest)

`deploy/charts/ectobase/tests/render.sh` + `lib.sh` are removed. Each chart gets `tests/*_test.yaml` run by the **helm-unittest** plugin (`kubernetes-helmPlugins.helm-unittest`, wired into the flake devShell via `helm.withPlugins`). Coverage:
- `matchSnapshot` goldens under `tests/__snapshot__/` (replace the `config/deploy` golden-diffs) across the representative value sets (ebpf-clab, ebpf-hw, dpdk-clab, dpdk-hw, tier1-on, broker on/off equivalents, vm-materializer on).
- asserts on load-bearing fields: container images, the generated RBAC `rules` (guards against a marker regression silently dropping a rule), and `failedTemplate` for the `_validate.tpl` invalid-value guards.
- `helm lint` per chart.

A `make chart-test` target runs helm-unittest over both charts.

## Lab deploy rewiring

`test/lab/internal/deploy/ectobase.go` stops cherry-picking manifests and runs Helm the way a user would:
- Hub cluster: `helm install ectobase-hub charts/ectobase-hub` on the hub kubeconfig, with values for the hub identity, images, and the reflector-admin address (retires `patchHubReflectorAdmin` + `kubectlApplyKustomize(hub/config)` + the `config/deploy/*` applies + the inline `brokerRBACManifest`).
- Each compute cluster: `helm install ectobase-pool charts/ectobase-pool` (retires the old `helmInstallEctobase` chart path + the `config/deploy/{pod,vm}-materializer.yaml` applies). vm-materializer via `--set vmMaterializer.enabled=true` under `lab tier2`.
- Retained as Go fixtures around the installs: broker token mint, `broker-hub-kubeconfig` Secret creation, ClusterPool pre-create, PSA-privileged labeling, NAD-CRD pre-apply (still needed before the pool chart's NAD renders), Multus install.
- `test/lab/topology/fabric.go` `ChartPath` and the tier2 `vm-materializer` manifest path are updated to the new charts.
- `hub/hack/smoke.sh` (applies `-k hub/config`) is updated to `helm install ectobase-hub` or removed if redundant with the lab.

## Reference path updates (sweep)

`ChartPath` / CHART constants and manifest references in: `test/lab/internal/deploy/ectobase.go`, `test/lab/topology/fabric.go`, `hub/hack/smoke.sh`, the Makefile (`generate`, `chart-sync-crds`→removed, `chart-test`), envtest CRD-load paths in `hub/test/*` and `netplane` envtests (`config/crd/bases` → new dirs), any `README`/docs mentioning `deploy/charts` or `config/deploy`.

## Risks / verification

- **RBAC rule-equivalence is the load-bearing risk.** Envtests pass without RBAC; only the live sweep exercises the deployed roles. Every generated role must reproduce the current working rules. Mitigation: transcribe from the catalogued YAML, assert rules in helm-unittest, and treat the 21/21 live sweep as the gate.
- **Pool CRD trim (14→11).** Dropping compute/storage/platform from the pool is safe per the read-audit (nothing pool-local reads them), but the live sweep confirms. If a "no matching kind" surfaces, the fallback is to add the missing group's CRDs back to the pool chart.
- **helm-unittest snapshots** are new goldens; first run generates them — review before committing.
- **Two-package broker markers** are an unusual layout; a `doc.go` comment explains why.

## Acceptance

- `make generate` produces the CRDs + RBAC into the charts/`test/crds` with a clean git diff on re-run.
- `make chart-test` (helm-unittest + lint) green for both charts.
- All Rust + Go unit/envtests green (`nix develop` / `GOWORK=off` for hub).
- `hack/r3-live-sweep.sh` **21/21** on a fresh fabric.
- `config/`, `hub/config/`, `deploy/charts/`, `hack/sync-chart-crds.sh` gone; no dangling references.
