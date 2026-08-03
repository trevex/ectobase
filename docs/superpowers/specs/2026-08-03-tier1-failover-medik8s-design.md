# Phase 5a — Tier-1 Autonomous Local Failover (medik8s) — Design

**Status:** Approved (brainstorm output) — ready for implementation planning.
**Date:** 2026-08-03
**Roadmap:** multi-cluster control plane §10 phase 5 (first half — Tier-1). See `2026-08-01-multicluster-control-plane-design.md` §4.5.

## 1. Goal

Give each compute pool the capability to autonomously recover VMs when a **node dies but the cluster is healthy** — with **central unreachable** — by assembling off-the-shelf components (KubeVirt `runStrategy` + medik8s node health/remediation + ceph-csi) and owning only the *configuration* that wires them together. No new controllers.

## 2. The coupling boundary (load-bearing principle)

Tier-1 answers **which node within a pool** — a pool-local capability, resolved entirely in-cluster, central-independent. Central owns **which pool** (the scheduler binds `spec.clusterName`; the Tier-2 failover controller re-binds it when a whole pool is lost). Phase 5a builds **only** the pool-local half and must not couple it to central state.

```
CENTRAL (multi-cluster / which-POOL)              — UNCHANGED
  scheduler: binds spec.clusterName
  Tier-2 failover: re-binds on pool loss
  ClusterPool: capacity/health via lease heartbeat
      │  (compiled objects down; lease up — existing paths only)
COMPUTE POOL (a cluster / which-NODE)             — NEW: config only
  KubeVirt runStrategy=RerunOnFailure   (already set by vm-materializer)
  medik8s NHC + SNR: detect dead node → fence → force-detach   (NEW config)
  ceph-csi: RWO RBD reattaches on a surviving node
  netplane agent: re-announces the overlay route on the new node (already works)
```

### 2.1 The recovery loop (all in-cluster, central-independent)

node dies → NHC detects (`Ready` = `Unknown`/`False` past threshold) → SNR fences (out-of-service taint or watchdog reboot) → k8s force-deletes the VMI **and** force-detaches its RBD → KubeVirt `RerunOnFailure` recreates the VMI on a surviving node → ceph-csi maps the RBD there → the netplane agent re-announces the overlay IP.

The VM keeps its overlay IP because that IP is bound to its `CompiledNIC`, not to the node — so **intra-pool IP stickiness is free** and pulls in **no** Phase-4 cross-cluster sticky-IP work.

### 2.2 Non-goals (to preserve loose coupling)

- **No** central `ClusterPool.fencingStrategy` field — the fencing choice is a per-pool *deployment* value (chart), not central state.
- **No** upward per-VM Tier-1 status ("informed when reachable" is deferred; central already learns the capacity change via the existing ClusterPool lease/capacity heartbeat).
- **No** Tier-2 / cross-cluster reschedule / real external-fence actuators (that is Phase 5b).
- **No** changes to `central/`, `api/`, or netplane Go controllers — `runStrategy` already defaults to `RerunOnFailure` in the vm-materializer.

## 3. Deliverable shape

Wiring + config + thin glue. Everything Phase 5a adds is a **pool-local deployment artifact** in the Helm chart plus dev scripts and tests. Zero new Go controllers.

## 4. Components & files

### 4.1 Helm chart (`deploy/charts/ectobase/`)

- `templates/tier1/nodehealthcheck.yaml` — a medik8s `NodeHealthCheck` CR selecting compute nodes (`.Values.tier1Failover.nodeSelector`), with unhealthy-condition rules (`Ready` in `{Unknown,False}` for `.Values.tier1Failover.unhealthyThreshold`) and `minHealthy` guard, pointing at the SNR remediation template.
- `templates/tier1/selfnoderemediation.yaml` — `SelfNodeRemediationConfig` (watchdog vs software reboot, from `.Values.tier1Failover.watchdog`) + `SelfNodeRemediationTemplate` (`remediationStrategy` from `.Values.tier1Failover.remediationStrategy`).
- Both files wrapped in `{{- if .Values.tier1Failover.enabled }}` so pools that don't opt in (or lack medik8s) render nothing.
- `templates/_validate.tpl` — extend the existing `ectobase.validate` helper with the Tier-1 guards (§6).
- `values.yaml` — new `tier1Failover` block (§5); `values.schema.json` (whatever enforces unknown-key rejection) extended to accept it.

### 4.2 Dev scripts (`hack/`)

- `hack/medik8s-up.sh` (new; mirrors `hack/rook-ceph-up.sh`) — installs the medik8s **NodeHealthCheck operator** + **SelfNodeRemediation operator** on a kind cluster at pinned versions. Dev-only header, `--help`, not auto-destructive. Wired into `hack/install-stack.sh` behind `INSTALL_MEDIK8S=1` (same idiom as `INSTALL_ROOK=1`).
- `hack/tier1-failover-e2e.sh` (new) — the best-effort live validation (§7.2). Dev-only header, `--help`.

### 4.3 Tests & docs

- Extend `deploy/charts/ectobase/tests/render.sh` with the Tier-1 golden + negative cases (§7.1).
- Chart README: a short operator note on the medik8s prerequisite, the toggle, and the `OutOfServiceTaint` timeout-safe-not-hard-fenced caveat.
- This spec + its plan under `docs/superpowers/`.

## 5. Values surface

medik8s models two **orthogonal** knobs, so the chart exposes two fields (not one fake enum). The `remediationStrategy` (workload cleanup, on `SelfNodeRemediationTemplate`) and the watchdog (reboot mechanism, on `SelfNodeRemediationConfig`) are independent.

```yaml
tier1Failover:
  enabled: false                       # opt-in per pool; renders nothing when false
  snrNamespace: self-node-remediation  # where the SNR operator (+ our Template/Config) live
  nodeSelector:                        # which nodes NHC watches (compute nodes)
    matchExpressions: []               # default: all worker nodes
  unhealthyThreshold: 60s              # Node Ready=Unknown/False duration before remediation
  minHealthy: "51%"                    # NHC guard: never remediate if too few nodes healthy
  remediationStrategy: OutOfServiceTaint  # real SNR enum: Automatic | ResourceDeletion | OutOfServiceTaint
  watchdog:
    enabled: false                     # dev/kind: software reboot. prod: true → hardware watchdog hard-fence
    device: /dev/watchdog              # watchdogFilePath on SelfNodeRemediationConfig (used when enabled)
```

- **`remediationStrategy`** → `SelfNodeRemediationTemplate.spec.template.spec.remediationStrategy`. Default **`OutOfServiceTaint`**: SNR places the k8s-native `node.kubernetes.io/out-of-service` taint on the fenced node → the kube-controller-manager **force-deletes the VMI and force-detaches its volumes** (RWO RBD reattaches on a surviving node without the ~6-minute detach timeout). `ResourceDeletion`/`Automatic` are accepted but `OutOfServiceTaint` is what the RWO-RBD boot-disk case needs. The Non-Graceful-Node-Shutdown taint is **GA in Kubernetes ≥1.28** (a documented prerequisite).
- **`watchdog.enabled`** → the `SelfNodeRemediationConfig` singleton is a per-operator object the SNR operator auto-creates with a software-reboot default. To avoid a Helm-vs-operator ownership fight, the chart renders a `SelfNodeRemediationConfig` (name `self-node-remediation-config`, namespace `snrNamespace`) **only when `watchdog.enabled=true`** — setting `watchdogFilePath: <device>`. When `false` (dev/kind default) the chart renders **no** Config and the operator's own software-reboot default stands (no `/dev/watchdog` needed). Every strategy still fences via this reboot mechanism; the watchdog only strengthens the guarantee. (Prod ordering caveat: install the operators first; the operator adopts the chart-provided singleton — the live e2e removes any auto-created one before applying.)

`minHealthy` is the pool-local fail-safe: NHC refuses to remediate when the pool would drop below the healthy quorum, so a network blip cannot cascade into a pool-wide fence storm.

## 6. Validation guards (chart-lint, `ectobase.validate` + `values.schema.json`)

- `remediationStrategy` must be one of `{Automatic, ResourceDeletion, OutOfServiceTaint}` — enforced by `values.schema.json` enum (the SNR CRD's own enum) and surfaced early.
- `watchdog.enabled=true` requires a non-empty `watchdog.device` — else `ectobase.validate` `fail`s with a clear message.
- (Schema) unknown keys under `tier1Failover` rejected via `additionalProperties: false`, consistent with the existing schema.

## 7. Testing

### 7.1 Always-green CI gate (`make chart-test` → `tests/render.sh`)

Deterministic, no cluster required — the merge gate:

1. `tier1Failover.enabled=false` → **zero** Tier-1 manifests (opt-in proven; grep for `kind: NodeHealthCheck` / `kind: SelfNodeRemediation*` yields 0).
2. `enabled=true` (defaults) → `NodeHealthCheck` + `SelfNodeRemediationConfig` + `SelfNodeRemediationTemplate` render; Template `remediationStrategy` == `OutOfServiceTaint`; NHC `minHealthy`/`unhealthyConditions[].duration`(from `unhealthyThreshold`)/`selector` wired through; NHC `remediationTemplate` references the Template by the right group/kind/name/namespace.
3. `enabled=true, watchdog.enabled=true` → a `SelfNodeRemediationConfig` renders with `spec.watchdogFilePath` == `watchdog.device` in `snrNamespace`; `watchdog.enabled=false` (default) → **no** `SelfNodeRemediationConfig` rendered (operator default stands).
4. Negative (`neg` helper): `watchdog.enabled=true` with empty `watchdog.device` → `helm template` fails; `remediationStrategy=Bogus` → fails (schema enum); unknown key under `tier1Failover` → fails.
5. `helm lint` stays clean.

### 7.2 Best-effort live script (`hack/tier1-failover-e2e.sh`)

The real proof, run manually on a dev fabric (not CI-wired):

1. kind (≥2 workers) + KubeVirt + Rook (`INSTALL_ROOK=1`) + medik8s (`hack/medik8s-up.sh`) + `helm install ectobase --set tier1Failover.enabled=true`.
2. Boot a VM on an RWO RBD DataVolume (reuses the Ceph phase); record its node.
3. Kill that node (`docker kill` the kind node / hard-stop kubelet).
4. **Assert:** NHC marks the node unhealthy → SNR applies the out-of-service taint → the VMI reschedules onto a surviving node → the RBD reattaches → the VM reaches `Running` and its overlay IP is re-announced.
5. Cleanup.

## 8. Success criteria

- `make chart-test` green in CI (the §7.1 gate).
- `hack/tier1-failover-e2e.sh` demonstrably reschedules a VM after node death on a dev fabric (best-effort).
- No diff to `central/`, `api/`, or netplane Go controllers.

## 9. Deferred / open

- Upward per-VM Tier-1 status propagation ("informed when reachable") — its own later phase.
- Watchdog on kind (softdog) is finicky; `watchdog.enabled=true` is validated via chart-render only until a HW/softdog-capable lab exists.
- `OutOfServiceTaint` split-brain caveat for RWO: timeout-based, not a hard fence — documented; `watchdog.enabled=true` is the hardening answer.
- medik8s ships no plain `install.yaml`; `hack/medik8s-up.sh` installs via remote kustomize (`kubectl apply -k github.com/medik8s/<op>/config/default?ref=<tag>`), pinned SNR **v0.13.0** / NHC **v0.12.0** (overridable via env). NHC group `remediation.medik8s.io/v1alpha1`; SNR group `self-node-remediation.medik8s.io/v1alpha1` (default namespace `self-node-remediation`).
