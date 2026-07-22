# Helm Chart Migration (Thread A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the flat `config/deploy/` kustomize base with a Helm chart that reproduces today's eBPF deployment byte-for-byte (`dataplane: ebpf`), can render a DPDK datapath (`dataplane: dpdk`), and rejects misconfiguration with clear errors.

**Architecture:** One application chart `deploy/charts/ectobase`. The non-datapath stack (namespace, RBAC, reflector, controller, agent, CNI, KubeVirt NAD) renders unconditionally; a whole-cluster `dataplane` value gates which single datapath DaemonSet renders. A `values.schema.json` (draft-07) plus template `fail`-guards validate input. CRDs are bundled verbatim from `config/crd/bases` (kept authoritative via `make generate`) and emitted by one `Files.Glob` template gated on `installCRDs`.

**Tech Stack:** Helm 3 (v3.19.1), Go templating, JSON Schema draft-07, bash + `diff` golden tests. No `yq`/`kubeconform` (not in devShell) — tests use `helm template --show-only` + `diff` only.

**Testing note (important):** Helm renders resources **sorted by Kind**, so a multi-document template's concatenation order differs from the source file even when every resource is byte-identical. The equivalence guarantee is therefore **per-resource identical, order-independent** — not byte-identical concatenation. The `tests/lib.sh` helper `assert_docs_equal <template> <values> <source>` implements this (splits both sides into documents, hashes each normalized doc, compares the sorted sets). Use it for every render-vs-source check; `normalize` remains for single-document content-level diffs when debugging. `lib.sh` resolves `REPO`/`CHART` from the git top-level, so tests run from any CWD.

**Scope note:** This is thread A of the umbrella spec `docs/superpowers/specs/2026-07-22-dpdk-dataplane-helm-blue-green-design.md`. It does NOT build `flowplane-dpdk` (thread B) or the blue-green operator (thread C). The `dataplane: dpdk` DaemonSet it renders references an image that does not exist yet — that is expected; the chart only needs to *render and validate*, not run, for DPDK until thread B lands. `config/deploy/` is NOT deleted here (blocked on a live clab smoke — see Task 9).

---

## File Structure

Created under `deploy/charts/ectobase/`:

- `Chart.yaml` — chart metadata.
- `.helmignore` — exclude `tests/` from packaged chart.
- `values.yaml` — full value surface (dataplane, env, images, uplink, dpdk knobs, installCRDs, blueGreen).
- `values.schema.json` — draft-07 schema: enums, `required`, `additionalProperties: false`.
- `templates/_validate.tpl` — `define "ectobase.validate"`: cross-field `fail`-guards.
- `templates/namespace.yaml` — Namespace + the single validation invocation.
- `templates/rbac.yaml`, `templates/agent-kubeconfig.yaml`, `templates/kubevirt-binding.yaml` — verbatim copies (no templating).
- `templates/reflector.yaml`, `templates/controller.yaml`, `templates/agent.yaml`, `templates/cni.yaml` — image/value-templated copies.
- `templates/dataplane-ebpf.yaml` — eBPF DaemonSet, gated `{{ if eq .Values.dataplane "ebpf" }}`.
- `templates/dataplane-dpdk.yaml` — DPDK DaemonSet, gated `{{ if eq .Values.dataplane "dpdk" }}`.
- `templates/crds.yaml` — emits `crd-bases/*.yaml` when `installCRDs`.
- `crd-bases/*.yaml` — verbatim copies of `config/crd/bases/*.yaml` (synced by script).
- `tests/lib.sh` — `normalize` + `render_show_only` helpers.
- `tests/values/{ebpf-clab,dpdk-clab,dpdk-hw}.yaml` — case value files.
- `tests/render.sh` — aggregate golden + negative suite.

Other files:

- `hack/sync-chart-crds.sh` — copies `config/crd/bases/*.yaml` → `deploy/charts/ectobase/crd-bases/`.
- `Makefile` — add `chart-sync-crds` and `chart-test` targets; wire `chart-sync-crds` into `generate`.
- `hack/clab/README.md` — document the `helm upgrade --install` path.

---

## Task 1: Chart scaffold + values + schema

**Files:**
- Create: `deploy/charts/ectobase/Chart.yaml`
- Create: `deploy/charts/ectobase/.helmignore`
- Create: `deploy/charts/ectobase/values.yaml`
- Create: `deploy/charts/ectobase/values.schema.json`
- Create: `deploy/charts/ectobase/templates/namespace.yaml`
- Create: `deploy/charts/ectobase/tests/lib.sh`
- Create: `deploy/charts/ectobase/tests/values/ebpf-clab.yaml`
- Create: `deploy/charts/ectobase/tests/values/dpdk-clab.yaml`
- Create: `deploy/charts/ectobase/tests/values/dpdk-hw.yaml`

- [ ] **Step 1: Write the failing test**

Create `deploy/charts/ectobase/tests/lib.sh`:

```bash
#!/usr/bin/env bash
# Shared helpers for the ectobase chart golden tests. Source this file.
set -euo pipefail
CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$CHART/../../.." && pwd)"
export CHART REPO

# Strip helm's "# Source:" lines, leading "---"/blank lines, and trailing whitespace,
# so a --show-only render can be diffed against the raw source manifest.
normalize() {
  grep -v '^# Source: ' \
    | awk 'BEGIN{s=0} { if (s==0 && ($0=="---" || $0=="")) next; s=1; print }' \
    | sed -e 's/[[:space:]]*$//'
}

# render_show_only <template-rel-path> <values-file>
render_show_only() {
  helm template ectobase "$CHART" --namespace ectobase-system -f "$2" --show-only "$1"
}
```

Create `deploy/charts/ectobase/tests/values/ebpf-clab.yaml`:

```yaml
dataplane: ebpf
env: clab
```

Create `deploy/charts/ectobase/tests/values/dpdk-clab.yaml`:

```yaml
dataplane: dpdk
env: clab
dpdk:
  lcores: "0"
  hugepages: false
```

Create `deploy/charts/ectobase/tests/values/dpdk-hw.yaml`:

```yaml
dataplane: dpdk
env: hw
dpdk:
  lcores: "0-3"
  hugepages: true
  vfioDevices:
    - name: intel.com/intel_sriov_netdevice
      count: 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `helm lint deploy/charts/ectobase`
Expected: FAIL — `Error: ... no Chart.yaml exists` (chart not created yet).

- [ ] **Step 3: Write minimal implementation**

Create `deploy/charts/ectobase/Chart.yaml`:

```yaml
apiVersion: v2
name: ectobase
description: ectobase netplane control plane + flowplane datapath (eBPF or DPDK)
type: application
version: 0.1.0
appVersion: "dev"
```

Create `deploy/charts/ectobase/.helmignore`:

```
tests/
*.md
.git
```

Create `deploy/charts/ectobase/values.yaml`:

```yaml
# Datapath backend for the WHOLE cluster (whole-cluster toggle; no mixed clusters).
dataplane: ebpf            # ebpf | dpdk
# Deployment environment; drives datapath-specific knobs (hugepages, vfio, lcores).
env: clab                  # clab | hw

images:
  flowplane: ghcr.io/trevex/ectobase/flowplane:dev
  flowplaneDpdk: ghcr.io/trevex/ectobase/flowplane-dpdk:dev
  netplane: ghcr.io/trevex/ectobase/netplane:dev
  cni: ghcr.io/trevex/ectobase/cni:dev
imagePullPolicy: IfNotPresent

# Overlay uplink interface (used by the DPDK datapath; the eBPF wrapper defaults to eth1).
uplink: eth1
# Fabric reflector address the agent dials.
reflectorAddress: "[fd00:db8:0:1::1]:1338"

# DPDK-only knobs (dataplane: dpdk).
dpdk:
  lcores: "0"              # EAL -l value. clab MUST be a single lcore (shared host).
  hugepages: false         # clab: false (--no-huge); hw: true.
  hugepageSize: 1Gi
  hugepageLimit: 2Gi
  vfioDevices: []          # hw: [{name: <resource>, count: <n>}] device-plugin requests.

# Install the net.ectobase.dev CRDs with the chart (managed on helm upgrade).
installCRDs: true

# Blue-green operator (thread C). Off until it lands; requires dataplane: dpdk.
blueGreen:
  enabled: false
```

Create `deploy/charts/ectobase/values.schema.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "additionalProperties": false,
  "required": ["dataplane", "env", "images", "uplink", "installCRDs"],
  "properties": {
    "dataplane": { "type": "string", "enum": ["ebpf", "dpdk"] },
    "env": { "type": "string", "enum": ["clab", "hw"] },
    "imagePullPolicy": { "type": "string", "enum": ["Always", "IfNotPresent", "Never"] },
    "uplink": { "type": "string", "minLength": 1 },
    "reflectorAddress": { "type": "string", "minLength": 1 },
    "installCRDs": { "type": "boolean" },
    "images": {
      "type": "object",
      "additionalProperties": false,
      "required": ["flowplane", "flowplaneDpdk", "netplane", "cni"],
      "properties": {
        "flowplane": { "type": "string", "minLength": 1 },
        "flowplaneDpdk": { "type": "string", "minLength": 1 },
        "netplane": { "type": "string", "minLength": 1 },
        "cni": { "type": "string", "minLength": 1 }
      }
    },
    "dpdk": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "lcores": { "type": "string", "minLength": 1 },
        "hugepages": { "type": "boolean" },
        "hugepageSize": { "type": "string", "minLength": 1 },
        "hugepageLimit": { "type": "string", "minLength": 1 },
        "vfioDevices": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["name", "count"],
            "properties": {
              "name": { "type": "string", "minLength": 1 },
              "count": { "type": "integer", "minimum": 1 }
            }
          }
        }
      }
    },
    "blueGreen": {
      "type": "object",
      "additionalProperties": false,
      "properties": { "enabled": { "type": "boolean" } }
    }
  }
}
```

Create `deploy/charts/ectobase/templates/namespace.yaml`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ectobase-system
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `helm lint deploy/charts/ectobase`
Expected: PASS — `1 chart(s) linted, 0 chart(s) failed`.

Run: `helm template ectobase deploy/charts/ectobase --namespace ectobase-system --set bogusKey=1`
Expected: FAIL — schema error mentioning `bogusKey` / `Additional property bogusKey is not allowed`.

Run: `helm template ectobase deploy/charts/ectobase --namespace ectobase-system --set dataplane=bogus`
Expected: FAIL — schema error mentioning `dataplane` / `enum`.

- [ ] **Step 5: Commit**

```bash
git add deploy/charts/ectobase/Chart.yaml deploy/charts/ectobase/.helmignore \
  deploy/charts/ectobase/values.yaml deploy/charts/ectobase/values.schema.json \
  deploy/charts/ectobase/templates/namespace.yaml deploy/charts/ectobase/tests/
git commit -m "feat(chart): scaffold ectobase Helm chart + values schema"
```

---

## Task 2: Cross-field validation guards

**Files:**
- Create: `deploy/charts/ectobase/templates/_validate.tpl`
- Modify: `deploy/charts/ectobase/templates/namespace.yaml`

- [ ] **Step 1: Write the failing test**

Run (this is the behavior we want; it currently does NOT fail as it should):
`helm template ectobase deploy/charts/ectobase --namespace ectobase-system --set blueGreen.enabled=true`
Expected right now: PASS (renders the namespace) — WRONG, we want it to fail because blue-green requires DPDK.

- [ ] **Step 2: Confirm the gap**

Run: `helm template ectobase deploy/charts/ectobase --namespace ectobase-system --set dataplane=dpdk,env=clab,dpdk.lcores=0-3`
Expected right now: PASS — WRONG, clab must be single-lcore.

- [ ] **Step 3: Write minimal implementation**

Create `deploy/charts/ectobase/templates/_validate.tpl`:

```
{{- define "ectobase.validate" -}}
{{- if and (eq .Values.dataplane "dpdk") (eq .Values.env "hw") -}}
  {{- if not .Values.dpdk.hugepages -}}
    {{- fail "invalid values: dpdk.hugepages must be true when dataplane=dpdk and env=hw (a DPDK HW node needs hugepages to boot). Set dpdk.hugepages: true." -}}
  {{- end -}}
  {{- if not .Values.dpdk.vfioDevices -}}
    {{- fail "invalid values: dpdk.vfioDevices must list at least one device when dataplane=dpdk and env=hw. Set dpdk.vfioDevices: [{name: <resource>, count: <n>}]." -}}
  {{- end -}}
{{- end -}}
{{- if and (eq .Values.dataplane "dpdk") (eq .Values.env "clab") -}}
  {{- if ne .Values.dpdk.lcores "0" -}}
    {{- fail "invalid values: dpdk.lcores must be \"0\" when dataplane=dpdk and env=clab (a single lcore, to avoid pinning busy poll-mode cores per node on the shared clab host). Set dpdk.lcores: \"0\"." -}}
  {{- end -}}
{{- end -}}
{{- if .Values.blueGreen.enabled -}}
  {{- if ne .Values.dataplane "dpdk" -}}
    {{- fail "invalid values: blueGreen.enabled=true requires dataplane=dpdk (blue-green is DPDK-only; eBPF hot-swaps in place). Set dataplane: dpdk or blueGreen.enabled: false." -}}
  {{- end -}}
{{- end -}}
{{- end -}}
```

Modify `deploy/charts/ectobase/templates/namespace.yaml` — prepend the non-emitting validation invocation (dash-trims keep output byte-identical):

```yaml
{{- include "ectobase.validate" . -}}
apiVersion: v1
kind: Namespace
metadata:
  name: ectobase-system
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `helm template ectobase deploy/charts/ectobase --namespace ectobase-system --set blueGreen.enabled=true`
Expected: FAIL — message contains `blueGreen.enabled=true requires dataplane=dpdk`.

Run: `helm template ectobase deploy/charts/ectobase --namespace ectobase-system --set dataplane=dpdk,env=clab,dpdk.lcores=0-3`
Expected: FAIL — message contains `dpdk.lcores must be "0"`.

Run: `helm template ectobase deploy/charts/ectobase --namespace ectobase-system --set dataplane=dpdk,env=hw,dpdk.hugepages=false`
Expected: FAIL — message contains `dpdk.hugepages must be true`.

Run: `helm template ectobase deploy/charts/ectobase --namespace ectobase-system --set dataplane=dpdk,env=hw,dpdk.hugepages=true,dpdk.vfioDevices[0].name=intel.com/x,dpdk.vfioDevices[0].count=1`
Expected: PASS — renders the namespace (valid dpdk+hw config).

Run: `bash -c 'source deploy/charts/ectobase/tests/lib.sh && diff <(render_show_only templates/namespace.yaml tests/values/ebpf-clab.yaml | normalize) <(normalize < config/deploy/namespace.yaml)'`
Expected: PASS — no output (namespace render still byte-identical to the original).

- [ ] **Step 5: Commit**

```bash
git add deploy/charts/ectobase/templates/_validate.tpl deploy/charts/ectobase/templates/namespace.yaml
git commit -m "feat(chart): cross-field values validation guards"
```

---

## Task 3: Verbatim (untemplated) manifests

**Files:**
- Create: `deploy/charts/ectobase/templates/rbac.yaml` (copy of `config/deploy/rbac.yaml`)
- Create: `deploy/charts/ectobase/templates/agent-kubeconfig.yaml` (copy of `config/deploy/agent-kubeconfig.yaml`)
- Create: `deploy/charts/ectobase/templates/kubevirt-binding.yaml` (copy of `config/deploy/kubevirt-binding.yaml`)

- [ ] **Step 1: Write the failing test**

Run: `bash -c 'source deploy/charts/ectobase/tests/lib.sh && for f in rbac agent-kubeconfig kubevirt-binding; do diff <(render_show_only templates/$f.yaml tests/values/ebpf-clab.yaml | normalize) <(normalize < config/deploy/$f.yaml) && echo "$f OK"; done'`
Expected: FAIL — `Error: could not find template templates/rbac.yaml` (not created yet).

- [ ] **Step 2: Copy the manifests verbatim**

These three files contain no image references and no environment-specific values, so they are exact copies. Run:

```bash
cp config/deploy/rbac.yaml deploy/charts/ectobase/templates/rbac.yaml
cp config/deploy/agent-kubeconfig.yaml deploy/charts/ectobase/templates/agent-kubeconfig.yaml
cp config/deploy/kubevirt-binding.yaml deploy/charts/ectobase/templates/kubevirt-binding.yaml
```

Do NOT edit them.

- [ ] **Step 3: Run tests to verify they pass**

Run: `bash -c 'source deploy/charts/ectobase/tests/lib.sh && for f in rbac agent-kubeconfig kubevirt-binding; do diff <(render_show_only templates/$f.yaml tests/values/ebpf-clab.yaml | normalize) <(normalize < config/deploy/$f.yaml) && echo "$f OK"; done'`
Expected: PASS — prints `rbac OK`, `agent-kubeconfig OK`, `kubevirt-binding OK` with no diff output.

- [ ] **Step 4: Commit**

```bash
git add deploy/charts/ectobase/templates/rbac.yaml \
  deploy/charts/ectobase/templates/agent-kubeconfig.yaml \
  deploy/charts/ectobase/templates/kubevirt-binding.yaml
git commit -m "feat(chart): verbatim rbac, agent-kubeconfig, kubevirt-binding templates"
```

---

## Task 4: Templated control-plane + CNI manifests

**Files:**
- Create: `deploy/charts/ectobase/templates/reflector.yaml`
- Create: `deploy/charts/ectobase/templates/controller.yaml`
- Create: `deploy/charts/ectobase/templates/agent.yaml`
- Create: `deploy/charts/ectobase/templates/cni.yaml`

- [ ] **Step 1: Write the failing test**

Run: `bash -c 'source deploy/charts/ectobase/tests/lib.sh && for f in reflector controller agent cni; do assert_docs_equal templates/$f.yaml tests/values/ebpf-clab.yaml config/deploy/$f.yaml && echo "$f OK"; done'`
Expected: FAIL — `could not find template templates/reflector.yaml`.

- [ ] **Step 2: Copy then templatize the image + reflector fields**

Copy all four:

```bash
cp config/deploy/reflector.yaml deploy/charts/ectobase/templates/reflector.yaml
cp config/deploy/controller.yaml deploy/charts/ectobase/templates/controller.yaml
cp config/deploy/agent.yaml deploy/charts/ectobase/templates/agent.yaml
cp config/deploy/cni.yaml deploy/charts/ectobase/templates/cni.yaml
```

In `deploy/charts/ectobase/templates/reflector.yaml`, replace:

```yaml
          image: ghcr.io/trevex/ectobase/netplane:dev
          imagePullPolicy: IfNotPresent
```

with:

```yaml
          image: {{ .Values.images.netplane }}
          imagePullPolicy: {{ .Values.imagePullPolicy }}
```

In `deploy/charts/ectobase/templates/controller.yaml`, replace the same two lines with the same templated pair (`.Values.images.netplane` / `.Values.imagePullPolicy`).

In `deploy/charts/ectobase/templates/agent.yaml`, replace:

```yaml
          image: ghcr.io/trevex/ectobase/netplane:dev
          imagePullPolicy: IfNotPresent
```

with:

```yaml
          image: {{ .Values.images.netplane }}
          imagePullPolicy: {{ .Values.imagePullPolicy }}
```

and replace:

```yaml
            - "--reflector=[fd00:db8:0:1::1]:1338"
```

with:

```yaml
            - "--reflector={{ .Values.reflectorAddress }}"
```

In `deploy/charts/ectobase/templates/cni.yaml`, replace:

```yaml
          image: ghcr.io/trevex/ectobase/cni:dev
          imagePullPolicy: IfNotPresent
```

with:

```yaml
          image: {{ .Values.images.cni }}
          imagePullPolicy: {{ .Values.imagePullPolicy }}
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `bash -c 'source deploy/charts/ectobase/tests/lib.sh && for f in reflector controller agent cni; do assert_docs_equal templates/$f.yaml tests/values/ebpf-clab.yaml config/deploy/$f.yaml && echo "$f OK"; done'`
Expected: PASS — `reflector OK`, `controller OK`, `agent OK`, `cni OK`, no diffs. (Defaults `images.netplane`, `images.cni`, `imagePullPolicy`, `reflectorAddress` reproduce the original literals.)

- [ ] **Step 4: Commit**

```bash
git add deploy/charts/ectobase/templates/reflector.yaml \
  deploy/charts/ectobase/templates/controller.yaml \
  deploy/charts/ectobase/templates/agent.yaml \
  deploy/charts/ectobase/templates/cni.yaml
git commit -m "feat(chart): templated reflector, controller, agent, cni"
```

---

## Task 5: eBPF datapath template (byte-identical, gated)

**Files:**
- Create: `deploy/charts/ectobase/templates/dataplane-ebpf.yaml`

- [ ] **Step 1: Write the failing test**

Run: `bash -c 'source deploy/charts/ectobase/tests/lib.sh && assert_docs_equal templates/dataplane-ebpf.yaml tests/values/ebpf-clab.yaml config/deploy/flowplane.yaml && echo OK'`
Expected: FAIL — `could not find template templates/dataplane-ebpf.yaml`.

- [ ] **Step 2: Create the gated, minimally-templated copy**

```bash
cp config/deploy/flowplane.yaml deploy/charts/ectobase/templates/dataplane-ebpf.yaml
```

Edit `deploy/charts/ectobase/templates/dataplane-ebpf.yaml`:

1. Prepend a guard on the first line and append the matching `{{- end }}` on a new last line. The file must now start with:

```yaml
{{- if eq .Values.dataplane "ebpf" }}
apiVersion: apps/v1
kind: DaemonSet
```

and end with (after the final `type: DirectoryOrCreate` line of the last volume):

```yaml
            type: DirectoryOrCreate
{{- end }}
```

2. Replace:

```yaml
          image: ghcr.io/trevex/ectobase/flowplane:dev
          imagePullPolicy: IfNotPresent
```

with:

```yaml
          image: {{ .Values.images.flowplane }}
          imagePullPolicy: {{ .Values.imagePullPolicy }}
```

3. Replace the SKB env block (env is clab-only; on `env: hw` native XDP works, so omit it):

```yaml
          env:
            # Compute nodes MUST run generic/SKB XDP on clab. uplink_rx delivers to guests by
            # XDP-redirecting into the guest veth (GUEST_DEV devmap). On containerlab veths a NATIVE
            # XDP redirect into a veth fails with -95/EOPNOTSUPP (the veth ndo_xdp_xmit peer
            # requirement) — only the generic/SKB path delivers. Nodes never do XDP_PASS-to-stack, so
            # they gain nothing from native. (The WAN edge is the opposite: it needs NATIVE for its
            # decap+XDP_PASS local-deliver and does no guest-veth redirect — see edge-xdp-wrapper.sh.)
            # On real hardware native works for both; this generic pin is a clab-veth constraint.
            - name: FLOWPLANE_SKB_MODE
              value: "1"
```

with:

```yaml
          env:
{{- if eq .Values.env "clab" }}
            # Compute nodes MUST run generic/SKB XDP on clab. uplink_rx delivers to guests by
            # XDP-redirecting into the guest veth (GUEST_DEV devmap). On containerlab veths a NATIVE
            # XDP redirect into a veth fails with -95/EOPNOTSUPP (the veth ndo_xdp_xmit peer
            # requirement) — only the generic/SKB path delivers. Nodes never do XDP_PASS-to-stack, so
            # they gain nothing from native. (The WAN edge is the opposite: it needs NATIVE for its
            # decap+XDP_PASS local-deliver and does no guest-veth redirect — see edge-xdp-wrapper.sh.)
            # On real hardware native works for both; this generic pin is a clab-veth constraint.
            - name: FLOWPLANE_SKB_MODE
              value: "1"
{{- end }}
```

Leave everything else (the wrapper script, probes, mounts, volumes) byte-for-byte unchanged.

- [ ] **Step 3: Run tests to verify they pass**

Run: `bash -c 'source deploy/charts/ectobase/tests/lib.sh && assert_docs_equal templates/dataplane-ebpf.yaml tests/values/ebpf-clab.yaml config/deploy/flowplane.yaml && echo OK'`
Expected: PASS — prints `OK`, no diff (ebpf+clab reproduces `flowplane.yaml` exactly).

Run: `bash -c 'source deploy/charts/ectobase/tests/lib.sh && render_show_only templates/dataplane-ebpf.yaml tests/values/dpdk-clab.yaml >/dev/null 2>&1 && echo "UNEXPECTED RENDER" || echo "NO_RENDER_OK"'`
Expected: PASS — prints `NO_RENDER_OK` (the eBPF DaemonSet produces no output under `dataplane: dpdk`, so `--show-only` exits non-zero).

- [ ] **Step 4: Commit**

```bash
git add deploy/charts/ectobase/templates/dataplane-ebpf.yaml
git commit -m "feat(chart): gated eBPF datapath template (byte-identical to flowplane.yaml)"
```

---

## Task 6: DPDK datapath template (env-driven)

**Files:**
- Create: `deploy/charts/ectobase/templates/dataplane-dpdk.yaml`

**Note:** This renders a first-cut DPDK DaemonSet. The exact `flowplane-dpdk serve` CLI is finalized in thread B when the binary exists; this template's job is to render a valid, env-appropriate DaemonSet and pass validation. The wrapper reuses the eBPF gateway-MAC discovery (works on the AF_XDP clab veth path).

- [ ] **Step 1: Write the failing test**

Run: `bash -c 'source deploy/charts/ectobase/tests/lib.sh && render_show_only templates/dataplane-dpdk.yaml tests/values/dpdk-clab.yaml | grep -q "flowplane-dpdk" && echo OK'`
Expected: FAIL — `could not find template templates/dataplane-dpdk.yaml`.

- [ ] **Step 2: Create the template**

Create `deploy/charts/ectobase/templates/dataplane-dpdk.yaml`:

```yaml
{{- if eq .Values.dataplane "dpdk" }}
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: flowplane-dpdk
  namespace: ectobase-system
  labels:
    app.kubernetes.io/name: flowplane
    app.kubernetes.io/part-of: netplane
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: flowplane
  template:
    metadata:
      labels:
        app.kubernetes.io/name: flowplane
        app.kubernetes.io/part-of: netplane
    spec:
      # Same host-integration posture as the eBPF datapath: it programs the node datapath
      # and serves the DataplaneNode gRPC on 127.0.0.1:1337, so the agent (dataplane-agnostic)
      # dials it identically.
      hostNetwork: true
      hostPID: true
      dnsPolicy: ClusterFirstWithHostNet
      tolerations:
        - operator: Exists
      containers:
        - name: flowplane-dpdk
          image: {{ .Values.images.flowplaneDpdk }}
          imagePullPolicy: {{ .Values.imagePullPolicy }}
          # Discover the fabric router MAC on the uplink (same as the eBPF wrapper); the AF_XDP
          # PMD binds the same kernel netdev, so kernel neighbour discovery still works on clab.
          command: ["/bin/sh", "-c"]
          args:
            - |
              set -e
              UPLINK="{{ .Values.uplink }}"
              for i in $(seq 1 30); do
                GW_MAC=$(ip -6 neigh show dev "$UPLINK" | grep -m1 router | grep -o 'lladdr [0-9a-f:]*' | cut -d' ' -f2 || true)
                [ -n "$GW_MAC" ] && break
                echo "waiting for fabric router neighbour on $UPLINK ($i)"; sleep 1
              done
              if [ -z "$GW_MAC" ]; then echo "FATAL: no fabric router neighbour on $UPLINK" >&2; exit 1; fi
              echo "flowplane-dpdk wrapper: uplink=$UPLINK gateway_mac=$GW_MAC"
              exec flowplane-dpdk serve \
                --addr 127.0.0.1:1337 \
                --uplink "$UPLINK" \
                --gateway 169.254.0.1 \
                --gateway-mac "$GW_MAC" \
                --lcores "{{ .Values.dpdk.lcores }}" \
{{- if eq .Values.env "clab" }}
                --backend af-xdp \
                --no-huge
{{- else }}
                --backend nic
{{- end }}
          readinessProbe:
            exec:
              command: ["/bin/sh", "-c", "ss -ltn | grep -q '127.0.0.1:1337'"]
            initialDelaySeconds: 2
            periodSeconds: 3
            timeoutSeconds: 2
            failureThreshold: 40
          livenessProbe:
            exec:
              command: ["/bin/sh", "-c", "ss -ltn | grep -q '127.0.0.1:1337'"]
            initialDelaySeconds: 90
            periodSeconds: 10
            timeoutSeconds: 2
            failureThreshold: 6
          securityContext:
            privileged: true
{{- if .Values.dpdk.hugepages }}
          resources:
            limits:
              hugepages-{{ .Values.dpdk.hugepageSize }}: {{ .Values.dpdk.hugepageLimit }}
              memory: {{ .Values.dpdk.hugepageLimit }}
{{- range .Values.dpdk.vfioDevices }}
              {{ .name }}: {{ .count }}
{{- end }}
{{- end }}
          volumeMounts:
            - name: sys
              mountPath: /sys
              readOnly: true
            - name: lib-modules
              mountPath: /lib/modules
              readOnly: true
            - name: netns
              mountPath: /var/run/netns
              mountPropagation: Bidirectional
{{- if eq .Values.env "hw" }}
            - name: vfio
              mountPath: /dev/vfio
            - name: hugepages
              mountPath: /dev/hugepages
{{- end }}
      volumes:
        - name: sys
          hostPath:
            path: /sys
            type: Directory
        - name: lib-modules
          hostPath:
            path: /lib/modules
            type: Directory
        - name: netns
          hostPath:
            path: /var/run/netns
            type: DirectoryOrCreate
{{- if eq .Values.env "hw" }}
        - name: vfio
          hostPath:
            path: /dev/vfio
            type: Directory
        - name: hugepages
          emptyDir:
            medium: HugePages
{{- end }}
{{- end }}
```

- [ ] **Step 3: Run tests to verify they pass**

Run (clab: single lcore, af-xdp, --no-huge, no hugepage/vfio resources):
```bash
bash -c 'source deploy/charts/ectobase/tests/lib.sh && r=$(render_show_only templates/dataplane-dpdk.yaml tests/values/dpdk-clab.yaml); echo "$r" | grep -q "flowplane-dpdk serve" && echo "$r" | grep -q -- "--backend af-xdp" && echo "$r" | grep -q -- "--no-huge" && ! echo "$r" | grep -q "hugepages-" && ! echo "$r" | grep -q "/dev/vfio" && echo CLAB_OK'
```
Expected: PASS — prints `CLAB_OK`.

Run (hw: nic backend, hugepages + vfio present):
```bash
bash -c 'source deploy/charts/ectobase/tests/lib.sh && r=$(render_show_only templates/dataplane-dpdk.yaml tests/values/dpdk-hw.yaml); echo "$r" | grep -q -- "--backend nic" && echo "$r" | grep -q "hugepages-1Gi: 2Gi" && echo "$r" | grep -q "intel.com/intel_sriov_netdevice: 1" && echo "$r" | grep -q "/dev/vfio" && echo HW_OK'
```
Expected: PASS — prints `HW_OK`.

Run (dpdk template does NOT render under ebpf): `bash -c 'source deploy/charts/ectobase/tests/lib.sh && render_show_only templates/dataplane-dpdk.yaml tests/values/ebpf-clab.yaml 2>&1 | grep -qi "could not find template\|^$" && echo NO_RENDER_OK'`
Expected: PASS — prints `NO_RENDER_OK` (empty/error = not rendered under `dataplane: ebpf`).

- [ ] **Step 4: Commit**

```bash
git add deploy/charts/ectobase/templates/dataplane-dpdk.yaml
git commit -m "feat(chart): env-driven DPDK datapath template (first cut; thread B finalizes serve CLI)"
```

---

## Task 7: CRD bundling

**Files:**
- Create: `hack/sync-chart-crds.sh`
- Create: `deploy/charts/ectobase/crd-bases/*.yaml` (via the sync script)
- Create: `deploy/charts/ectobase/templates/crds.yaml`
- Modify: `Makefile`

- [ ] **Step 1: Write the failing test**

Run: `bash -c 'source deploy/charts/ectobase/tests/lib.sh && render_show_only templates/crds.yaml tests/values/ebpf-clab.yaml | grep -c "kind: CustomResourceDefinition"'`
Expected: FAIL — `could not find template templates/crds.yaml`.

- [ ] **Step 2: Create the sync script and run it**

Create `hack/sync-chart-crds.sh`:

```bash
#!/usr/bin/env bash
# Copy the controller-gen-generated CRDs into the Helm chart. config/crd/bases stays the
# single source of truth (regenerated by `make generate`); the chart only vendors the output.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/config/crd/bases"
DST="$REPO/deploy/charts/ectobase/crd-bases"
rm -rf "$DST"
mkdir -p "$DST"
cp "$SRC"/net.ectobase.dev_*.yaml "$DST"/
echo "synced $(ls "$DST" | wc -l) CRD(s) -> deploy/charts/ectobase/crd-bases/"
```

Run:
```bash
chmod +x hack/sync-chart-crds.sh
./hack/sync-chart-crds.sh
```
Expected: `synced 8 CRD(s) -> deploy/charts/ectobase/crd-bases/`.

Create `deploy/charts/ectobase/templates/crds.yaml`:

```yaml
{{- if .Values.installCRDs }}
{{- range $path, $_ := .Files.Glob "crd-bases/*.yaml" }}
---
{{ $.Files.Get $path }}
{{- end }}
{{- end }}
```

- [ ] **Step 3: Wire the sync into `make generate`**

In `Makefile`, find the `generate` target (it runs `controller-gen`). Add a line at the END of its recipe:

```makefile
	./hack/sync-chart-crds.sh
```

Then add two standalone targets (place near other `chart`/`deploy` targets, or at the end of the file):

```makefile
.PHONY: chart-sync-crds
chart-sync-crds: ## Vendor generated CRDs into the Helm chart.
	./hack/sync-chart-crds.sh

.PHONY: chart-test
chart-test: ## Run the Helm chart golden + validation tests.
	./deploy/charts/ectobase/tests/render.sh
```

(`chart-test` is used in Task 8.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `bash -c 'source deploy/charts/ectobase/tests/lib.sh && render_show_only templates/crds.yaml tests/values/ebpf-clab.yaml | grep -c "kind: CustomResourceDefinition"'`
Expected: PASS — prints `8`.

Run: `helm template ectobase deploy/charts/ectobase --namespace ectobase-system -f deploy/charts/ectobase/tests/values/ebpf-clab.yaml --set installCRDs=false --show-only templates/crds.yaml >/dev/null 2>&1 && echo "UNEXPECTED CRDS" || echo NO_CRDS_OK`
Expected: PASS — prints `NO_CRDS_OK` (the `crds.yaml` template produces no output when `installCRDs=false`, so `--show-only` exits non-zero).

Run (synced copies match the source): `diff <(cat config/crd/bases/net.ectobase.dev_vpcs.yaml) <(cat deploy/charts/ectobase/crd-bases/net.ectobase.dev_vpcs.yaml) && echo SYNC_OK`
Expected: PASS — prints `SYNC_OK`.

- [ ] **Step 5: Commit**

```bash
git add hack/sync-chart-crds.sh deploy/charts/ectobase/crd-bases \
  deploy/charts/ectobase/templates/crds.yaml Makefile
git commit -m "feat(chart): bundle net.ectobase.dev CRDs (make generate keeps them authoritative)"
```

---

## Task 8: Aggregate golden + validation test suite

**Files:**
- Create: `deploy/charts/ectobase/tests/render.sh`

- [ ] **Step 1: Write the suite (it will fail if any prior task regressed)**

Create `deploy/charts/ectobase/tests/render.sh`:

```bash
#!/usr/bin/env bash
# Golden + validation suite for the ectobase chart. Exit non-zero on any failure.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/lib.sh"
cd "$REPO"

fail=0
ok()   { echo "PASS: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

# 1) eBPF render is byte-identical to the current kustomize manifests.
declare -A MAP=(
  [namespace]=namespace
  [rbac]=rbac
  [agent-kubeconfig]=agent-kubeconfig
  [kubevirt-binding]=kubevirt-binding
  [reflector]=reflector
  [controller]=controller
  [agent]=agent
  [cni]=cni
  [dataplane-ebpf]=flowplane
)
for tpl in "${!MAP[@]}"; do
  src="config/deploy/${MAP[$tpl]}.yaml"
  # Order-independent per-resource comparison: helm sorts resources by Kind, so multi-doc
  # templates (rbac, cni) render in a different order than the source file.
  if assert_docs_equal "templates/$tpl.yaml" "$DIR/values/ebpf-clab.yaml" "$src" >/dev/null; then
    ok "ebpf render $tpl == $src"
  else
    bad "ebpf render $tpl != $src"
  fi
done

# 2) CRDs: 8 with installCRDs, 0 without.
n=$(render_show_only templates/crds.yaml "$DIR/values/ebpf-clab.yaml" | grep -c "kind: CustomResourceDefinition")
[ "$n" = "8" ] && ok "installCRDs renders 8 CRDs" || bad "installCRDs rendered $n CRDs (want 8)"

# 3) DPDK renders under dpdk, not under ebpf.
render_show_only templates/dataplane-dpdk.yaml "$DIR/values/dpdk-clab.yaml" | grep -q "flowplane-dpdk serve" \
  && ok "dpdk datapath renders under dataplane=dpdk" || bad "dpdk datapath did not render"
render_show_only templates/dataplane-ebpf.yaml "$DIR/values/dpdk-clab.yaml" >/dev/null 2>&1 \
  && bad "ebpf datapath rendered under dataplane=dpdk" || ok "ebpf datapath absent under dataplane=dpdk"

# 4) Negative validation cases must FAIL helm template.
neg() {
  local desc="$1"; shift
  if helm template ectobase deploy/charts/ectobase --namespace ectobase-system "$@" >/dev/null 2>&1; then
    bad "expected rejection: $desc"
  else
    ok "rejected: $desc"
  fi
}
neg "unknown key"                  --set bogusKey=1
neg "bad dataplane enum"           --set dataplane=bogus
neg "bad env enum"                 --set env=bogus
neg "blueGreen without dpdk"       --set blueGreen.enabled=true
neg "dpdk+clab wide lcores"        --set dataplane=dpdk,env=clab,dpdk.lcores=0-3
neg "dpdk+hw no hugepages"         --set dataplane=dpdk,env=hw,dpdk.hugepages=false
neg "dpdk+hw no vfio"              --set dataplane=dpdk,env=hw,dpdk.hugepages=true

# 5) helm lint clean.
helm lint deploy/charts/ectobase >/dev/null 2>&1 && ok "helm lint" || bad "helm lint"

exit $fail
```

- [ ] **Step 2: Make it executable and run it**

Run:
```bash
chmod +x deploy/charts/ectobase/tests/render.sh
make chart-test
```
Expected: every line prints `PASS: ...` and the command exits 0.

- [ ] **Step 3: Fix any FAIL lines**

If any line prints `FAIL`, open the named template and reconcile it against the original `config/deploy/*.yaml` (whitespace/comment drift is the usual cause). Re-run `make chart-test` until all pass.

- [ ] **Step 4: Commit**

```bash
git add deploy/charts/ectobase/tests/render.sh
git commit -m "test(chart): aggregate golden + validation suite (make chart-test)"
```

---

## Task 9: Add the Helm install path (kustomize removal deferred)

**Files:**
- Modify: `hack/clab/README.md`

**Note:** Per the spec, `config/deploy/` is NOT deleted here and the e2e scripts are NOT switched yet — that flip is gated on a live clab smoke (`helm install` reproducing the eBPF regression sweep on a real fabric), which is a manual checkpoint outside this plan. This task only documents the install path and verifies the full render.

- [ ] **Step 1: Write the failing test**

Run: `grep -q 'helm upgrade --install ectobase deploy/charts/ectobase' hack/clab/README.md && echo OK`
Expected: FAIL — no output (line not present yet).

- [ ] **Step 2: Document the Helm path**

In `hack/clab/README.md`, find the line:

```
kubectl apply -k config/deploy            # (namespace ectobase-system)
```

Replace it with:

```
# Helm (preferred): renders the same stack; dataplane=ebpf reproduces the kustomize manifests.
helm upgrade --install ectobase deploy/charts/ectobase --namespace ectobase-system --create-namespace
# Legacy kustomize (kept until the Helm chart passes a live clab smoke):
kubectl apply -k config/deploy            # (namespace ectobase-system)
```

- [ ] **Step 3: Verify the full render + install path**

Run (full-stack render succeeds for all three cases):
```bash
for v in ebpf-clab dpdk-clab dpdk-hw; do
  helm template ectobase deploy/charts/ectobase --namespace ectobase-system \
    -f deploy/charts/ectobase/tests/values/$v.yaml >/dev/null \
    && echo "$v render OK" || { echo "$v render FAILED"; exit 1; }
done
```
Expected: `ebpf-clab render OK`, `dpdk-clab render OK`, `dpdk-hw render OK`.

Run: `grep -q 'helm upgrade --install ectobase deploy/charts/ectobase' hack/clab/README.md && echo OK`
Expected: PASS — prints `OK`.

Run the full suite once more: `make chart-test`
Expected: all `PASS`, exit 0.

- [ ] **Step 4: Commit**

```bash
git add hack/clab/README.md
git commit -m "docs(chart): document helm install path (kustomize kept pending live smoke)"
```

---

## Manual checkpoint (out of plan scope)

Before deleting `config/deploy/` and switching `hack/multicluster-e2e.sh` / `hack/kubevirt-vm-e2e.sh` to Helm, run a **live clab smoke**: `helm install` the chart on the kind fabric and re-run the eBPF regression sweep (cross-cluster ping, QoS, LB). Only after it passes should a follow-up PR flip the scripts and remove the kustomize base. This is deliberately not automated here.
