# Phase 5a — Tier-1 Autonomous Local Failover (medik8s) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each compute pool the capability to autonomously recover VMs after a node dies (cluster healthy, central unreachable) by wiring medik8s NodeHealthCheck + SelfNodeRemediation into the ectobase Helm chart, plus dev install/e2e scripts — no new Go controllers.

**Architecture:** Pool-local config only. The chart renders a `NodeHealthCheck` (cluster-scoped) + `SelfNodeRemediationTemplate` (`remediationStrategy: OutOfServiceTaint`, force-detaches RWO RBD) + optionally a `SelfNodeRemediationConfig` (only when a hardware watchdog is requested), all gated behind an opt-in `tier1Failover.enabled` value. KubeVirt `runStrategy: RerunOnFailure` (already set by the vm-materializer) restarts the VMI on a surviving node; the netplane agent re-announces its overlay route. No changes to `central/`, `api/`, or netplane Go.

**Tech Stack:** Helm 3/4 (templates + `values.schema.json` draft-07 + `ectobase.validate` helper), bash golden tests (`deploy/charts/ectobase/tests/render.sh`), `kubectl apply -k` remote kustomize for the medik8s operators, KubeVirt + Rook + kind for the best-effort live e2e.

**Spec:** `docs/superpowers/specs/2026-08-03-tier1-failover-medik8s-design.md`

**Branch:** `feat/tier1-failover-medik8s` (already exists; base `main` at merge-base of the design commits).

---

## Conventions for every task

- Run all tooling inside the nix devShell: wrap commands as `nix develop --command bash -c '...'`.
- The chart lives at `deploy/charts/ectobase`. The test suite is `deploy/charts/ectobase/tests/render.sh`, run via `make chart-test` (from repo root). It sources `tests/lib.sh` (helpers: `render_show_only <tpl-rel-path> <values-file>`, `ok "msg"`, `bad "msg"`, `neg "desc" --set ...`).
- Helm merges a `-f <file>` over the chart's `values.yaml` defaults, so test fixture files only need the `tier1Failover` overrides.
- Commit after each task with the shown message.

---

## File Structure

**Chart (all under `deploy/charts/ectobase/`):**
- `values.yaml` (modify) — add the `tier1Failover` block.
- `values.schema.json` (modify) — add the `tier1Failover` schema (draft-07, `additionalProperties: false`, `remediationStrategy` enum).
- `templates/_validate.tpl` (modify) — add the watchdog guard to the existing `ectobase.validate` helper.
- `templates/tier1/nodehealthcheck.yaml` (create) — the `NodeHealthCheck` CR, gated by `tier1Failover.enabled`.
- `templates/tier1/selfnoderemediation.yaml` (create) — `SelfNodeRemediationTemplate` (always when enabled) + `SelfNodeRemediationConfig` (only when `watchdog.enabled`).
- `tests/render.sh` (modify) — add the Tier-1 render + negative cases.
- `tests/values/tier1-on.yaml`, `tests/values/tier1-watchdog.yaml` (create) — fixtures.
- `README.md` (create) — a short operator note (medik8s prerequisite + the toggle + caveats).

**Dev scripts (under `hack/`):**
- `medik8s-up.sh` (create) — install NHC + SNR operators via remote kustomize (pinned tags).
- `install-stack.sh` (modify) — add an `INSTALL_MEDIK8S=1` guard.
- `tier1-failover-e2e.sh` (create) — best-effort live node-kill reschedule test.

---

## Task 1: Values surface + schema

Adds the `tier1Failover` values block and its JSON schema. Because the schema uses `additionalProperties: false`, values and schema must land together or `helm template` breaks. No templates yet, so this task's tests assert the block is *accepted* and *rejects* bad input.

**Files:**
- Modify: `deploy/charts/ectobase/values.yaml`
- Modify: `deploy/charts/ectobase/values.schema.json`
- Modify: `deploy/charts/ectobase/tests/render.sh`

- [ ] **Step 1: Add the failing test cases to `tests/render.sh`**

Insert this block immediately before the final `helm lint` check (the line `# 5) helm lint clean.`):

```bash
# 6) Tier-1 failover: schema accepts the block (default disabled renders + lints).
helm template ectobase deploy/charts/ectobase --namespace ectobase-system \
  --set tier1Failover.enabled=true >/dev/null 2>&1 \
  && ok "tier1Failover block accepted by schema" || bad "tier1Failover block rejected by schema"

# 6a) Negative schema cases must FAIL helm template.
neg "tier1 unknown key"           --set tier1Failover.enabled=true,tier1Failover.bogus=1
neg "tier1 bad remediationStrategy" --set tier1Failover.enabled=true,tier1Failover.remediationStrategy=Bogus
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `nix develop --command bash -c 'make chart-test'`
Expected: FAIL — `FAIL: tier1Failover block rejected by schema` (the block isn't in the schema yet, so top-level `additionalProperties: false` rejects `--set tier1Failover.enabled=true`). The two `neg` cases happen to PASS here for the wrong reason (the whole `tier1Failover` key is rejected), which is fine — the positive acceptance check is the failing signal. `make chart-test` exits non-zero.

- [ ] **Step 3: Add the `tier1Failover` block to `values.yaml`**

Append to `deploy/charts/ectobase/values.yaml`:

```yaml

# Tier-1 autonomous local failover (medik8s NHC + SNR). Pool-local capability;
# opt-in. When enabled, the chart renders a NodeHealthCheck + SelfNodeRemediationTemplate
# (and a SelfNodeRemediationConfig only when a hardware watchdog is requested).
tier1Failover:
  enabled: false                          # opt-in per pool; renders nothing when false
  snrNamespace: self-node-remediation     # where the SNR operator (+ our Template/Config) live
  nodeSelector:                           # LabelSelector of nodes NHC watches
    matchExpressions:
      - key: node-role.kubernetes.io/control-plane
        operator: DoesNotExist
  unhealthyThreshold: 60s                 # Node Ready=Unknown/False duration before remediation
  minHealthy: "51%"                       # NHC guard: never remediate below this healthy quorum
  remediationStrategy: OutOfServiceTaint  # SNR enum: Automatic | ResourceDeletion | OutOfServiceTaint
  watchdog:
    enabled: false                        # dev/kind: software reboot. prod true = hardware watchdog
    device: /dev/watchdog                 # watchdogFilePath on SelfNodeRemediationConfig (when enabled)
```

- [ ] **Step 4: Add the `tier1Failover` schema to `values.schema.json`**

In `deploy/charts/ectobase/values.schema.json`, add a `"tier1Failover"` key inside the top-level `"properties"` object (e.g. right after the `"blueGreen"` block, before the closing `}` of `properties`). Remember to add a comma after the preceding `blueGreen` block.

```json
    "tier1Failover": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "enabled": { "type": "boolean" },
        "snrNamespace": { "type": "string", "minLength": 1 },
        "nodeSelector": { "type": "object" },
        "unhealthyThreshold": { "type": "string", "minLength": 1 },
        "minHealthy": { "type": "string", "minLength": 1 },
        "remediationStrategy": {
          "type": "string",
          "enum": ["Automatic", "ResourceDeletion", "OutOfServiceTaint"]
        },
        "watchdog": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "enabled": { "type": "boolean" },
            "device": { "type": "string" }
          }
        }
      }
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop --command bash -c 'make chart-test'`
Expected: PASS — `tier1Failover block accepted by schema`, `rejected: tier1 unknown key`, `rejected: tier1 bad remediationStrategy`; all prior checks still PASS; `make chart-test` exits 0.

- [ ] **Step 6: Commit**

```bash
git add deploy/charts/ectobase/values.yaml deploy/charts/ectobase/values.schema.json deploy/charts/ectobase/tests/render.sh
git commit -m "feat(chart): tier1Failover values surface + schema"
```

---

## Task 2: NodeHealthCheck template

Renders the cluster-scoped `NodeHealthCheck` CR when `tier1Failover.enabled`, wiring `minHealthy`, the node selector, the `Ready` unhealthy conditions (duration from `unhealthyThreshold`), and the remediation-template reference.

**Files:**
- Create: `deploy/charts/ectobase/templates/tier1/nodehealthcheck.yaml`
- Create: `deploy/charts/ectobase/tests/values/tier1-on.yaml`
- Modify: `deploy/charts/ectobase/tests/render.sh`

- [ ] **Step 1: Create the test fixture**

Create `deploy/charts/ectobase/tests/values/tier1-on.yaml`:

```yaml
tier1Failover:
  enabled: true
```

- [ ] **Step 2: Add the failing tests to `tests/render.sh`**

Add after the Task-1 block (after the `neg "tier1 bad remediationStrategy"` line):

```bash
# 7) NodeHealthCheck: absent when disabled, present + wired when enabled.
render_show_only templates/tier1/nodehealthcheck.yaml "$DIR/values/ebpf-clab.yaml" >/dev/null 2>&1 \
  && bad "NodeHealthCheck rendered while tier1 disabled" || ok "NodeHealthCheck absent when disabled"

nhc=$(render_show_only templates/tier1/nodehealthcheck.yaml "$DIR/values/tier1-on.yaml")
echo "$nhc" | grep -q "kind: NodeHealthCheck"                       && ok "NHC kind" || bad "NHC kind"
echo "$nhc" | grep -q "apiVersion: remediation.medik8s.io/v1alpha1" && ok "NHC apiVersion" || bad "NHC apiVersion"
echo "$nhc" | grep -q 'minHealthy: "51%"'                           && ok "NHC minHealthy" || bad "NHC minHealthy"
echo "$nhc" | grep -q "duration: 60s"                               && ok "NHC threshold->duration" || bad "NHC threshold->duration"
echo "$nhc" | grep -q "kind: SelfNodeRemediationTemplate"           && ok "NHC remediationTemplate kind" || bad "NHC remediationTemplate kind"
echo "$nhc" | grep -q "namespace: self-node-remediation"            && ok "NHC remediationTemplate ns" || bad "NHC remediationTemplate ns"
```

- [ ] **Step 3: Run to verify they fail**

Run: `nix develop --command bash -c 'make chart-test'`
Expected: FAIL — `render_show_only` for a non-existent template errors, so `NodeHealthCheck absent when disabled` PASSES by accident but the `tier1-on.yaml` render yields nothing and every `NHC ...` check reports `bad`. `make chart-test` exits non-zero.

- [ ] **Step 4: Create the template**

Create `deploy/charts/ectobase/templates/tier1/nodehealthcheck.yaml`:

```yaml
{{- if .Values.tier1Failover.enabled }}
apiVersion: remediation.medik8s.io/v1alpha1
kind: NodeHealthCheck
metadata:
  name: ectobase-tier1
  labels:
    app.kubernetes.io/part-of: ectobase
spec:
  minHealthy: {{ .Values.tier1Failover.minHealthy | quote }}
  selector:
{{ toYaml .Values.tier1Failover.nodeSelector | indent 4 }}
  unhealthyConditions:
    - type: Ready
      status: "False"
      duration: {{ .Values.tier1Failover.unhealthyThreshold }}
    - type: Ready
      status: Unknown
      duration: {{ .Values.tier1Failover.unhealthyThreshold }}
  remediationTemplate:
    apiVersion: self-node-remediation.medik8s.io/v1alpha1
    kind: SelfNodeRemediationTemplate
    name: ectobase-tier1
    namespace: {{ .Values.tier1Failover.snrNamespace }}
{{- end }}
```

- [ ] **Step 5: Run to verify they pass**

Run: `nix develop --command bash -c 'make chart-test'`
Expected: PASS — all six `NHC ...` checks PASS, `NodeHealthCheck absent when disabled` PASSES, prior checks green, `make chart-test` exits 0.

- [ ] **Step 6: Commit**

```bash
git add deploy/charts/ectobase/templates/tier1/nodehealthcheck.yaml deploy/charts/ectobase/tests/values/tier1-on.yaml deploy/charts/ectobase/tests/render.sh
git commit -m "feat(chart): tier1 NodeHealthCheck template"
```

---

## Task 3: SelfNodeRemediation template + config + watchdog guard

Renders the `SelfNodeRemediationTemplate` (always, when enabled) with `remediationStrategy`, and a `SelfNodeRemediationConfig` **only** when `watchdog.enabled` (setting `watchdogFilePath`). Adds the `ectobase.validate` guard that `watchdog.enabled=true` requires a non-empty `watchdog.device`.

**Files:**
- Create: `deploy/charts/ectobase/templates/tier1/selfnoderemediation.yaml`
- Create: `deploy/charts/ectobase/tests/values/tier1-watchdog.yaml`
- Modify: `deploy/charts/ectobase/templates/_validate.tpl`
- Modify: `deploy/charts/ectobase/tests/render.sh`

- [ ] **Step 1: Create the watchdog fixture**

Create `deploy/charts/ectobase/tests/values/tier1-watchdog.yaml`:

```yaml
tier1Failover:
  enabled: true
  watchdog:
    enabled: true
    device: /dev/watchdog
```

- [ ] **Step 2: Add the failing tests to `tests/render.sh`**

Add after the Task-2 NHC block:

```bash
# 8) SelfNodeRemediationTemplate: strategy wired; Config only under watchdog.enabled.
snrt=$(render_show_only templates/tier1/selfnoderemediation.yaml "$DIR/values/tier1-on.yaml")
echo "$snrt" | grep -q "kind: SelfNodeRemediationTemplate"     && ok "SNRT kind" || bad "SNRT kind"
echo "$snrt" | grep -q "remediationStrategy: OutOfServiceTaint" && ok "SNRT strategy" || bad "SNRT strategy"
echo "$snrt" | grep -q "kind: SelfNodeRemediationConfig"        && bad "SNRConfig rendered without watchdog" || ok "SNRConfig absent without watchdog"

snrw=$(render_show_only templates/tier1/selfnoderemediation.yaml "$DIR/values/tier1-watchdog.yaml")
echo "$snrw" | grep -q "kind: SelfNodeRemediationConfig"        && ok "SNRConfig present with watchdog" || bad "SNRConfig present with watchdog"
echo "$snrw" | grep -q "watchdogFilePath: /dev/watchdog"        && ok "SNRConfig watchdogFilePath" || bad "SNRConfig watchdogFilePath"
echo "$snrw" | grep -q "name: self-node-remediation-config"     && ok "SNRConfig singleton name" || bad "SNRConfig singleton name"

# 8a) watchdog.enabled without a device must FAIL helm template.
neg "watchdog without device" --set tier1Failover.enabled=true,tier1Failover.watchdog.enabled=true,tier1Failover.watchdog.device=
```

- [ ] **Step 3: Run to verify they fail**

Run: `nix develop --command bash -c 'make chart-test'`
Expected: FAIL — the `selfnoderemediation.yaml` template does not exist yet so `SNRT ...` / `SNRConfig ...` checks report `bad`, and `neg "watchdog without device"` reports `FAIL: expected rejection` (no guard yet). Exits non-zero.

- [ ] **Step 4: Create the template**

Create `deploy/charts/ectobase/templates/tier1/selfnoderemediation.yaml`:

```yaml
{{- if .Values.tier1Failover.enabled }}
apiVersion: self-node-remediation.medik8s.io/v1alpha1
kind: SelfNodeRemediationTemplate
metadata:
  name: ectobase-tier1
  namespace: {{ .Values.tier1Failover.snrNamespace }}
  labels:
    app.kubernetes.io/part-of: ectobase
spec:
  template:
    spec:
      remediationStrategy: {{ .Values.tier1Failover.remediationStrategy }}
{{- if .Values.tier1Failover.watchdog.enabled }}
---
apiVersion: self-node-remediation.medik8s.io/v1alpha1
kind: SelfNodeRemediationConfig
metadata:
  name: self-node-remediation-config
  namespace: {{ .Values.tier1Failover.snrNamespace }}
  labels:
    app.kubernetes.io/part-of: ectobase
spec:
  watchdogFilePath: {{ .Values.tier1Failover.watchdog.device }}
{{- end }}
{{- end }}
```

- [ ] **Step 5: Add the watchdog guard to `_validate.tpl`**

In `deploy/charts/ectobase/templates/_validate.tpl`, insert this block immediately before the final `{{- end -}}` that closes the `ectobase.validate` define (i.e. after the `blueGreen` guard block):

```
{{- if .Values.tier1Failover.enabled -}}
  {{- if and .Values.tier1Failover.watchdog.enabled (not .Values.tier1Failover.watchdog.device) -}}
    {{- fail "invalid values: tier1Failover.watchdog.enabled=true requires tier1Failover.watchdog.device (e.g. /dev/watchdog). Set tier1Failover.watchdog.device or set watchdog.enabled: false." -}}
  {{- end -}}
{{- end -}}
```

- [ ] **Step 6: Run to verify they pass**

Run: `nix develop --command bash -c 'make chart-test'`
Expected: PASS — all `SNRT ...` / `SNRConfig ...` checks PASS, `rejected: watchdog without device` PASSES, prior checks green, exits 0.

- [ ] **Step 7: Commit**

```bash
git add deploy/charts/ectobase/templates/tier1/selfnoderemediation.yaml deploy/charts/ectobase/templates/_validate.tpl deploy/charts/ectobase/tests/values/tier1-watchdog.yaml deploy/charts/ectobase/tests/render.sh
git commit -m "feat(chart): tier1 SelfNodeRemediation template + config + watchdog guard"
```

---

## Task 4: medik8s operator install script + stack wiring

Adds a dev-only script that installs the NHC + SNR operators via remote kustomize at pinned tags, and wires it into `install-stack.sh` behind `INSTALL_MEDIK8S=1` (mirrors `INSTALL_ROOK`). Not unit-tested beyond a syntax check + `--help`; live behavior is validated in Task 5.

**Files:**
- Create: `hack/medik8s-up.sh`
- Modify: `hack/install-stack.sh`

- [ ] **Step 1: Create `hack/medik8s-up.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
# Install the medik8s NodeHealthCheck (NHC) + Self Node Remediation (SNR) operators for
# dev/kind — the Tier-1 autonomous local failover backend. NOT a production install.
#
# medik8s ships no plain install.yaml, so this applies each operator's kustomize base
# directly from GitHub at a pinned tag via `kubectl apply -k`. On kind (no hardware
# watchdog) SNR uses its software-reboot default; enable a hardware watchdog through the
# ectobase chart (tier1Failover.watchdog.enabled=true) on real hardware.
#
# Usage:
#   hack/medik8s-up.sh          # install NHC + SNR operators
#   hack/medik8s-up.sh --help   # show this help
#
# Env overrides:
#   SNR_VERSION   Self Node Remediation tag (default v0.13.0)
#   NHC_VERSION   Node Health Check tag     (default v0.12.0)
#   SNR_NAMESPACE SNR operator namespace     (default self-node-remediation)
#   NHC_NAMESPACE NHC operator namespace     (default nhc)
#
# Caveat: config/default pins the manager image inside each repo tag; if the applied
# Deployment lands with an unexpected image, override it with `kubectl -n <ns> set image`.

SNR_VERSION="${SNR_VERSION:-v0.13.0}"
NHC_VERSION="${NHC_VERSION:-v0.12.0}"
SNR_NAMESPACE="${SNR_NAMESPACE:-self-node-remediation}"
NHC_NAMESPACE="${NHC_NAMESPACE:-nhc}"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '3,27p' "$0"
  exit 0
fi

echo "== Self Node Remediation operator ${SNR_VERSION} =="
kubectl apply -k "github.com/medik8s/self-node-remediation/config/default?ref=${SNR_VERSION}"

echo "== Node Health Check operator ${NHC_VERSION} =="
kubectl apply -k "github.com/medik8s/node-healthcheck-operator/config/default?ref=${NHC_VERSION}"

echo "== waiting for operator deployments to become available =="
kubectl -n "${SNR_NAMESPACE}" rollout status deploy --timeout=5m || true
kubectl -n "${NHC_NAMESPACE}" rollout status deploy --timeout=5m || true

echo "== medik8s operators applied. Enable Tier-1 on a pool with:"
echo "   helm upgrade ectobase deploy/charts/ectobase --set tier1Failover.enabled=true"
```

- [ ] **Step 2: Make it executable and syntax-check it**

Run:
```bash
chmod +x hack/medik8s-up.sh
nix develop --command bash -c 'bash -n hack/medik8s-up.sh && hack/medik8s-up.sh --help'
```
Expected: `bash -n` prints nothing (valid syntax); `--help` prints the usage header (lines 3–27) and exits 0.

- [ ] **Step 3: Wire it into `install-stack.sh`**

In `hack/install-stack.sh`, append after the existing `INSTALL_ROOK` block (after its closing `fi`):

```bash

# Optional: medik8s NHC + SNR operators for Tier-1 autonomous local failover (dev only).
if [ "${INSTALL_MEDIK8S:-}" = "1" ]; then
  bash "$(dirname "$0")/medik8s-up.sh"
fi
```

- [ ] **Step 4: Syntax-check the modified stack script**

Run: `nix develop --command bash -c 'bash -n hack/install-stack.sh'`
Expected: prints nothing (valid syntax), exits 0.

- [ ] **Step 5: Commit**

```bash
git add hack/medik8s-up.sh hack/install-stack.sh
git commit -m "feat(hack): medik8s NHC+SNR install script + INSTALL_MEDIK8S stack wiring"
```

---

## Task 5: Best-effort live e2e script + chart README

Adds the documented, best-effort node-kill reschedule test (not CI-wired) and a chart README note describing the Tier-1 capability, its prerequisite, and its caveats.

**Files:**
- Create: `hack/tier1-failover-e2e.sh`
- Create: `deploy/charts/ectobase/README.md`

- [ ] **Step 1: Create `hack/tier1-failover-e2e.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
# BEST-EFFORT live validation of Tier-1 autonomous local failover on a dev kind cluster.
# NOT CI-wired: it needs a multi-node kind cluster with KubeVirt + CDI + Rook + medik8s.
# It boots a VM on an RWO RBD DataVolume, hard-kills the VM's node, and asserts the VMI
# reschedules onto a surviving node (medik8s fences the dead node via the out-of-service
# taint; ceph-csi reattaches the RBD; KubeVirt runStrategy=RerunOnFailure restarts it).
#
# Prerequisites (bring the stack up first):
#   INSTALL_ROOK=1 INSTALL_MEDIK8S=1 hack/install-stack.sh
#   helm upgrade --install ectobase deploy/charts/ectobase \
#     --namespace ectobase-system --create-namespace \
#     --set tier1Failover.enabled=true
#
# Usage:
#   hack/tier1-failover-e2e.sh          # run the node-kill reschedule test
#   hack/tier1-failover-e2e.sh --help   # show this help
#
# Env overrides:
#   NS         VM namespace (default default)
#   VM_NAME    VirtualMachine name (default tier1-vm)
#   TIMEOUT    reschedule wait, seconds (default 600)

NS="${NS:-default}"
VM_NAME="${VM_NAME:-tier1-vm}"
TIMEOUT="${TIMEOUT:-600}"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '3,25p' "$0"
  exit 0
fi

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== 1) wait for VMI ${VM_NAME} to be Running =="
kubectl -n "${NS}" wait "vmi/${VM_NAME}" --for=jsonpath='{.status.phase}'=Running --timeout="${TIMEOUT}s" \
  || fail "VMI ${VM_NAME} never reached Running (is the stack + a VM booted?)"

node="$(kubectl -n "${NS}" get vmi "${VM_NAME}" -o jsonpath='{.status.nodeName}')"
[ -n "${node}" ] || fail "could not read VMI node"
echo "   VMI is on node: ${node}"

echo "== 2) hard-kill the node (docker kill of the kind node container) =="
docker kill "${node}" || fail "failed to kill node ${node} (kind node container name == node name)"

echo "== 3) wait for the VMI to reschedule onto a DIFFERENT node =="
deadline=$(( $(date +%s) + TIMEOUT ))
while :; do
  cur="$(kubectl -n "${NS}" get vmi "${VM_NAME}" -o jsonpath='{.status.nodeName}' 2>/dev/null || true)"
  phase="$(kubectl -n "${NS}" get vmi "${VM_NAME}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ -n "${cur}" ] && [ "${cur}" != "${node}" ] && [ "${phase}" = "Running" ]; then
    echo "PASS: VMI rescheduled ${node} -> ${cur} and is Running"
    exit 0
  fi
  [ "$(date +%s)" -ge "${deadline}" ] && fail "VMI did not reschedule off ${node} within ${TIMEOUT}s (phase=${phase}, node=${cur})"
  sleep 10
done
```

- [ ] **Step 2: Make it executable and syntax-check it**

Run:
```bash
chmod +x hack/tier1-failover-e2e.sh
nix develop --command bash -c 'bash -n hack/tier1-failover-e2e.sh && hack/tier1-failover-e2e.sh --help'
```
Expected: `bash -n` prints nothing; `--help` prints the usage header and exits 0.

- [ ] **Step 3: Create the chart README**

Create `deploy/charts/ectobase/README.md`:

```markdown
# ectobase Helm chart

Deploys the netplane control plane + flowplane datapath (eBPF or DPDK) for one compute pool.

## Tier-1 autonomous local failover (`tier1Failover`)

Opt-in, pool-local capability: when a node dies but the cluster is healthy, medik8s
fences the dead node and KubeVirt (`runStrategy: RerunOnFailure`, set by the
vm-materializer) restarts the VM on a surviving node — all in-cluster, with central
unreachable. This chart owns only the *configuration*; the medik8s operators are a
prerequisite.

**Prerequisite:** install the medik8s NHC + SNR operators (dev: `hack/medik8s-up.sh`
or `INSTALL_MEDIK8S=1 hack/install-stack.sh`).

**Enable:**
```
helm upgrade --install ectobase deploy/charts/ectobase \
  --namespace ectobase-system --set tier1Failover.enabled=true
```

**Key values:**
- `remediationStrategy` (`Automatic|ResourceDeletion|OutOfServiceTaint`, default
  `OutOfServiceTaint`): `OutOfServiceTaint` applies the k8s `node.kubernetes.io/out-of-service`
  taint so pods are force-deleted and RWO volumes (Ceph RBD boot disks) force-detach and
  reattach on the surviving node. Requires Kubernetes ≥ 1.28.
- `watchdog.enabled` (default `false`): `false` uses SNR's software-reboot path (dev/kind,
  no `/dev/watchdog`); `true` arms the hardware watchdog for a hard split-brain guarantee
  (prod) and renders a `SelfNodeRemediationConfig` — install the operators first so it
  adopts the chart-provided singleton.
- `minHealthy` (default `"51%"`): NHC refuses to remediate below this healthy quorum,
  preventing a network blip from cascading into a pool-wide fence storm.

**Caveat:** with `watchdog.enabled=false`, remediation is timeout-based (not a hard fence);
`watchdog.enabled=true` is the hardening answer. Validate end-to-end with
`hack/tier1-failover-e2e.sh` on a dev fabric.
```

- [ ] **Step 4: Verify the chart still lints (README + scripts don't affect rendering)**

Run: `nix develop --command bash -c 'make chart-test'`
Expected: PASS — the full suite green (Tasks 1–3 checks + all prior), exits 0.

- [ ] **Step 5: Commit**

```bash
git add hack/tier1-failover-e2e.sh deploy/charts/ectobase/README.md
git commit -m "feat(hack): best-effort tier1 failover e2e script + chart README"
```

---

## Final verification (after all tasks)

- [ ] Run the full chart test suite: `nix develop --command bash -c 'make chart-test'` — all PASS, exit 0.
- [ ] Confirm no Go changed: `git diff --name-only main...HEAD | grep -E '\.go$'` — expect **no output**.
- [ ] Confirm the whole workspace still builds (no accidental breakage): `nix develop --command bash -c 'cd central && go build ./... && cd ../netplane && go build ./...'` — exits 0.
- [ ] Dispatch a final holistic review across `git diff main...HEAD`, then use `superpowers:finishing-a-development-branch`.
