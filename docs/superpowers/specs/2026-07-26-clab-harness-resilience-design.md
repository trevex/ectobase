# clab Harness Resilience + Portability Design

**Date:** 2026-07-26
**Status:** Approved (brainstorming)
**Context:** The clab e2e harness (`hack/clab-up.sh`, `hack/multicluster-e2e.sh`, `hack/clab/*`, `test/e2e/*.go`) works (re-validated 2026-07-26: cross-cluster overlay ping PASSES on current main) but has accreted resilience/portability debt — embedded YAML in scripts, sed-on-YAML templating, scattered constants, tooling not provided by the devShell, bare `sudo <tool>` that breaks on non-standard PATH, and divergent deploy logic between the shell scenarios and the Go e2e.

## Goal

Make the clab harness portable (works out of the box on a fresh dev machine) and resilient (single source of truth for manifests + constants, no brittle regex-on-YAML, PATH-robust), without changing what it validates.

## Current-state pain (grounded)

- **Embedded manifests in scripts:** `multicluster-e2e.sh` inlines the VPC + NetworkInterface CRs (`<<'EOF'`), the k02 kubeconfig ConfigMap (heredoc → `--dry-run|apply`), and builds the agent DS via `sed 's#--reflector=...#...#' config/deploy/agent.yaml` (regex-on-YAML). `kubevirt-vm-e2e.sh` inlines 2 VM manifests; `cni-install.sh` / `edge-agents-up.sh` `cat > tmp <<EOF`.
- **sed templating:** `clab-up.sh` does `sed "s#PREFIX_DIR#…" kind-cluster*.yaml > *.gen` (kind rejects relative extraMounts hostPaths).
- **Scattered constants:** fabric IPs (`fd00:db8:0:1::1`), overlay IPs (`10.0.0.1/.3`), VNI 100, ports (1337/1338), `:dev` image refs, cluster/node names, `CILIUM_VERSION` — duplicated across `clab-up.sh`, `multicluster-e2e.sh`, `ipv6-fabric.clab.yml`, kind configs, README.
- **Tooling not in devShell:** `kind`/`containerlab`/`helm` absent from the default `nix develop` (only bpftools/xdp-tools/kubectl/grpcurl present). The Go e2e `t.Skip`s without them.
- **Bare `sudo <tool>`:** `multicluster-e2e.sh` uses `sudo kind`/`sudo docker`; NixOS `secure_path` drops nix tools from root's PATH (required a `sudo`-passthrough shim during the last run).
- **Go e2e divergence:** `test/e2e/*.go` and the shell scenarios both orchestrate deploy/validate with overlapping inline logic.

## Design

### 1. Tooling in the default devShell
Add `kind`, `containerlab`, `kubernetes-helm` to the default `pkgs.mkShell` `buildInputs` in `flake.nix` (from the flake's already-pinned nixpkgs → reproducible). Do NOT add `cilium-cli` (unused). Result: `hack/clab-up.sh` and `go test ./test/e2e/...` work in a plain `nix develop`, no `nix shell nixpkgs#…`.

### 2. Cilium via the pinned helm chart (unchanged mechanism)
`cilium-up.sh` already installs via `helm upgrade --install cilium cilium/cilium --version "$CILIUM_VERSION" -f cilium-values.yaml`. Keep that (helm chart, not the CLI). Move `CILIUM_VERSION` into the central `env.sh` (§4) so the version is defined once.

### 3. All-kustomize fixtures (single source of truth)
Create `test/e2e/fixtures/` as a kustomize tree layered on the existing `config/` (which is already kustomize: `config/crd`, `config/deploy` with `kustomization.yaml`). Extract every embedded k8s manifest:
- **Scenario CRs** (VPC `blue`, NetworkInterface `nic-a`/`nic-c`) → `test/e2e/fixtures/multicluster/` base, applied with `kubectl apply -k`.
- **Agent `--reflector` override** → a kustomize *patch* overlay on `config/deploy/agent.yaml` (replaces the `sed 's#--reflector=…#…#'`). The reflector address comes from `env.sh` via a generated overlay (a tiny `kustomize edit set` / a patch rendered from the env var), NOT regex.
- **k02 kubeconfig ConfigMap** → reuse/param `config/deploy/agent-kubeconfig.yaml` (already exists) instead of the heredoc.
- **KubeVirt VM manifests** (`kubevirt-vm-e2e.sh`) → `test/e2e/fixtures/kubevirt/`.
- **cni-install / edge-agents generated configs** → fixture files (templated via env where dynamic).
Scripts switch from heredocs to `kubectl apply -k test/e2e/fixtures/<scenario>` (or `-f` for static). No inline manifests, no sed-on-YAML.

### 4. Central `hack/clab/env.sh`
One sourced file defining the constants duplicated today: `FABRIC_REFLECTOR6`, overlay IPs, `VNI`, dataplane/reflector ports, `IMAGE_FLOWPLANE`/`IMAGE_NETPLANE`/`IMAGE_KINDNODE` (`:dev`), cluster/node names, `CILIUM_VERSION`. Every script sources it (`. "$(dirname …)/clab/env.sh"`). Where a fixture needs a value (reflector addr), the script renders it into the kustomize overlay from `env.sh` (one place). The `.clab.yml` topology + kind configs reference the same values where feasible (or a comment cross-links `env.sh` as the source).

### 5. kind cluster config templating (non-kustomize)
kind cluster configs are kind config, not k8s resources, so kustomize doesn't apply. Replace the `sed "s#PREFIX_DIR#…"` with an explicit render step (still into gitignored `*.gen`) that resolves the absolute `extraMounts` hostPath — via `env.sh` + `envsubst`/`yq` with named vars rather than a bare `sed`. Keep the `.gen` files gitignored + regenerated each run.

### 6. sudo/PATH robustness
Resolve each external tool to an absolute path once at script start (`KIND="$(command -v kind)"`, `CLAB="$(command -v containerlab)"`, `HELM="$(command -v helm)"`, `DOCKER="$(command -v docker)"`), and invoke `sudo "$KIND" …`. This makes the harness work regardless of how the tools reached PATH (no `secure_path`/nix shim needed). Fail early with a clear message if a required tool is missing.

### 7. Resilience polish
- `multicluster-e2e.sh` (and the other scenario scripts): adopt `set -euo pipefail` with explicit `|| true` on genuinely-optional steps, and per-stage failure messages, so a mid-run failure aborts loudly instead of limping to a cryptic ping failure.
- **Image preflight:** verify the `:dev` images exist (from `env.sh`), and either build them (`make images`) or fail with a clear instruction — instead of assuming.
- Replace fixed `/tmp/busybox-musl` with `mktemp` (per-run, no collision), matching the existing mktemp-kubeconfig discipline.

### 8. Unify the Go e2e
Point `test/e2e/*.go` at the same `test/e2e/fixtures/` + `env.sh` values (via the existing `dataplane_client.go`/test helpers) so the Go tests and the shell scenarios share one source of truth. The Go e2e keeps calling the (refactored) `clab-up.sh`; its inline deploy/CR logic is replaced by applying the extracted fixtures.

## Testing / validation (from clean)

Prove portability + no regression by running the refactored harness FROM CLEAN:
1. `hack/clab-down.sh` (tear down the currently-up fabric).
2. Plain `nix develop` (no `nix shell`) → `hack/clab-up.sh` (fresh fabric, tooling from the extended devShell, PATH-robust sudo).
3. `hack/multicluster-e2e.sh` → cross-cluster overlay ping PASSES both directions (the same green result as the pre-refactor run).
4. `go test ./test/e2e/...` → the fixture-unified Go e2e passes (or skips cleanly only if a genuine prereq is absent).
Success = the whole flow works from a plain `nix develop` with zero manual tooling/PATH fixups, producing the same validation results as before. (N-S NAT-egress re-validation attempted if the refactor makes it easy; else documented as still-open.)

## Out of scope / risks

- **Not** changing the fabric topology, the dataplane, or what the e2e validates — pure harness refactor.
- **Risk:** breaking the working harness. Mitigation: the from-clean validation (§Testing) is the gate; refactor incrementally (devShell + env.sh + sudo-robustness first — low risk; then fixtures; then Go-e2e unify), re-running the e2e after the risky (fixtures) step.
- Vendoring/pinning the Cilium helm chart to a digest (vs the pinned version + live `helm repo add`) is a possible further hardening — out of scope here (keep the pinned-version + repo-add, centralized in `env.sh`).
