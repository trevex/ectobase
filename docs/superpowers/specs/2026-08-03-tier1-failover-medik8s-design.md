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
- `templates/tier1/selfnoderemediation.yaml` — `SelfNodeRemediationConfig` + `SelfNodeRemediationTemplate`, with `remediationStrategy` driven by `.Values.tier1Failover.fencingStrategy`.
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

```yaml
tier1Failover:
  enabled: false                      # opt-in per pool; renders nothing when false
  nodeSelector:                       # which nodes NHC watches (compute nodes)
    matchExpressions: []              # default: all worker nodes
  unhealthyThreshold: 60s             # Node Ready=Unknown/False duration before remediation
  minHealthy: "51%"                   # NHC guard: never remediate if too few nodes healthy
  fencingStrategy: OutOfServiceTaint  # dev default; or "WatchdogReboot" (PascalCase, k8s enum style)
  watchdog:
    device: /dev/watchdog             # only used when fencingStrategy=WatchdogReboot
```

The toggle maps to SNR's `remediationStrategy`:

- **`OutOfServiceTaint`** (dev default) → SNR applies the k8s-native `node.kubernetes.io/out-of-service` taint after the safe timeout → k8s force-deletes VMIs **and force-detaches volumes** (RWO RBD reattaches). No watchdog needed → works in kind. Timeout-based safety (no hard reboot guarantee).
- **`WatchdogReboot`** → SNR uses the hardware/softdog watchdog for a hard split-brain guarantee before reschedule. Prod-hardening path; the live e2e branches/skips when no watchdog device exists.

`minHealthy` is the pool-local fail-safe: NHC refuses to remediate when the pool would drop below the healthy quorum, so a network blip cannot cascade into a pool-wide fence storm.

## 6. Validation guards (chart-lint, `ectobase.validate`)

- `fencingStrategy` must be one of `{OutOfServiceTaint, WatchdogReboot}` — else `fail` with a clear message.
- `fencingStrategy=WatchdogReboot` requires `watchdog.device` — else `fail`.
- (Schema) unknown keys under `tier1Failover` rejected, consistent with the existing unknown-key rejection.

## 7. Testing

### 7.1 Always-green CI gate (`make chart-test` → `tests/render.sh`)

Deterministic, no cluster required — the merge gate:

1. `tier1Failover.enabled=false` → **zero** Tier-1 manifests (opt-in proven; grep for `kind: NodeHealthCheck` / `kind: SelfNodeRemediation*` yields 0).
2. `enabled=true, fencingStrategy=OutOfServiceTaint` → `NodeHealthCheck` + `SelfNodeRemediationConfig`/`Template` render; SNR `remediationStrategy` == `OutOfServiceTaint`; `unhealthyThreshold`/`minHealthy`/`nodeSelector` wired through.
3. `enabled=true, fencingStrategy=WatchdogReboot` → SNR strategy == watchdog; `watchdog.device` mounted.
4. Negative (`neg` helper): `WatchdogReboot` without `watchdog.device` → `helm template` fails; unknown `fencingStrategy` → fails.
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
- Watchdog on kind (softdog) is finicky; `WatchdogReboot` is validated via chart-render only until a HW/softdog-capable lab exists.
- `OutOfServiceTaint` split-brain caveat for RWO: timeout-based, not a hard fence — documented; `WatchdogReboot` is the hardening answer.
- Pinned medik8s operator versions in `hack/medik8s-up.sh` to be fixed at implementation time (latest stable NHC + SNR).
