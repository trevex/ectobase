# clab Harness Resilience + Portability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (fresh subagent per task + two-stage review). Steps use `- [ ]` checkboxes.

**Goal:** Make the clab e2e harness portable (works from a plain `nix develop`) and resilient (single source of truth for manifests + constants, no regex-on-YAML, PATH-robust), without changing what it validates.

**Architecture:** Extend the default devShell with the fabric tooling; centralize constants in `hack/clab/env.sh`; make `sudo` PATH-robust; extract every embedded manifest/heredoc into an all-kustomize `test/e2e/fixtures/` tree layered on `config/`; replace sed-on-YAML with kustomize patches; unify the Go e2e onto the same fixtures. Incremental, low-risk-first; a from-clean fabric run is the final gate.

**Tech Stack:** nix flake devShell, bash, kustomize (`kubectl kustomize`/`apply -k`), kind/containerlab/helm, Cilium helm chart, Go e2e (`test/e2e/`).

**Spec:** `docs/superpowers/specs/2026-07-26-clab-harness-resilience-design.md`.

**Anchors (verify against current code):**
- `flake.nix`: `devShells.default = pkgs.mkShell { ... buildInputs = [ pkgs.rustup … pkgs.kubectl pkgs.grpcurl pkgs.bpftools … ]; }` (~line 72-108). `kind`/`containerlab`/`kubernetes-helm` are ABSENT.
- `hack/clab-up.sh`: `sed "s#PREFIX_DIR#${PREFIX_DIR}#g" kind-cluster*.yaml > *.gen` (~line 33); `docker image inspect ghcr.io/trevex/ectobase/kind-node-fabric:dev` (~28); calls `hack/clab/wan-up.sh`, `hack/clab/cilium-up.sh`.
- `hack/multicluster-e2e.sh`: `REFLECTOR6="fd00:db8:0:1::1"` (23), `XDP=…flowplane:dev` / `NETPLANE=…netplane:dev` (34-35), `sudo kind get kubeconfig` (40-41), `sudo kind load docker-image` (54-55), the k02 kubeconfig ConfigMap heredoc (~72-88), `sed -e 's#\(--reflector=\).*#…#' config/deploy/agent.yaml | apply` (90), the VPC+NIC CR heredoc `apply -f - <<'EOF'` (95-110), `attach_endpoint` (grpcurl/`sudo docker`), `/tmp/busybox-musl` fixed path (148), `sudo docker exec … ping` (153), `set -uo pipefail` (19, NO -e).
- `config/`: already kustomize — `config/crd/kustomization.yaml`, `config/deploy/kustomization.yaml` + `config/deploy/{agent.yaml,agent-kubeconfig.yaml,reflector.yaml,flowplane.yaml,namespace.yaml,rbac.yaml,…}`.
- `hack/clab/cilium-up.sh`: `helm upgrade --install cilium cilium/cilium --version "$CILIUM_VERSION" …` (~39); `CILIUM_VERSION="${CILIUM_VERSION:-1.20.0-rc.0}"` (19).
- `hack/kubevirt-vm-e2e.sh`: `k apply -f - <<EOF` ×2 (55, 87). `hack/cni-install.sh` / `hack/clab/edge-agents-up.sh`: `cat > tmp <<EOF`.
- `test/e2e/*.go`: `routebus_test.go` (TestCrossNodeOverlayPing), `fabric_test.go`, `smoke_datapath_test.go`, `smoke_lb_dhcp_test.go`, `dataplane_client.go`, `kind_test.go` — call `../../hack/clab-up.sh`, skip if kind/containerlab/docker absent.

**CRITICAL execution rule:** subagents must NOT bring up the fabric (it's a 15-min sudo op — timeouts/flakiness). Validate each task CHEAPLY: `kubectl kustomize <dir>` (render), `git diff`/`diff` render-equivalence vs the old output, `bash -n`/`shellcheck` (if present), `nix develop --command …`, `go build ./test/e2e/... && go vet`. The from-clean fabric run is **Task 9 (controller-run only)**. Commit trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. No merge/push per-task.

---

## Task 1: Extend the default devShell with fabric tooling

**Files:** `flake.nix`.

- [ ] **Step 1:** Add `pkgs.kind`, `pkgs.containerlab`, `pkgs.kubernetes-helm` to the `devShells.default` `buildInputs` list (near `pkgs.kubectl`). Do NOT add `cilium-cli` (unused — Cilium installs via the helm chart). Add a one-line comment: "clab fabric tooling — kind/containerlab/helm so hack/clab-up.sh + go test ./test/e2e/... work in a plain `nix develop` (Cilium via the pinned helm chart, no cilium-cli)."
- [ ] **Step 2: Verify** — `nix develop --command sh -c 'kind version && containerlab version && helm version --short && kubectl version --client 2>/dev/null | head -1'` → all resolve (kind ~0.30/0.31, containerlab ~0.71/0.76, helm v3). If the flake pins a specific nixpkgs, these come from it (reproducible). Report the versions.
- [ ] **Step 3: Commit** — `feat(clab): default devShell provides kind/containerlab/helm (fabric works from plain nix develop)`.

---

## Task 2: Central `hack/clab/env.sh` for shared constants

**Files:** Create `hack/clab/env.sh`; modify `hack/clab-up.sh`, `hack/multicluster-e2e.sh`, `hack/clab/cilium-up.sh` to source it.

- [ ] **Step 1: Create `hack/clab/env.sh`** — a sourceable file (`# shellcheck shell=bash`) exporting the constants currently duplicated. Grep the scripts + `hack/clab/ipv6-fabric.clab.yml` for the literals and centralize (keep `${VAR:-default}` so callers can override):
  ```bash
  # Central clab-fabric constants (sourced by hack/clab-up.sh, multicluster-e2e.sh, clab/*.sh).
  # Single source of truth for the topology + scenario — grep found these duplicated across scripts.
  export CLAB_FABRIC_REFLECTOR6="${CLAB_FABRIC_REFLECTOR6:-fd00:db8:0:1::1}"   # k01 CP fabric loopback (reflector + apiserver)
  export CLAB_REFLECTOR_PORT="${CLAB_REFLECTOR_PORT:-1338}"
  export CLAB_DATAPLANE_PORT="${CLAB_DATAPLANE_PORT:-1337}"
  export CLAB_VNI="${CLAB_VNI:-100}"
  export CLAB_OVERLAY_IP_A="${CLAB_OVERLAY_IP_A:-10.0.0.1}"   # nic-a on k01-control-plane
  export CLAB_OVERLAY_IP_C="${CLAB_OVERLAY_IP_C:-10.0.0.3}"   # nic-c on k02-control-plane
  export CLAB_IMAGE_FLOWPLANE="${CLAB_IMAGE_FLOWPLANE:-ghcr.io/trevex/ectobase/flowplane:dev}"
  export CLAB_IMAGE_NETPLANE="${CLAB_IMAGE_NETPLANE:-ghcr.io/trevex/ectobase/netplane:dev}"
  export CLAB_IMAGE_KINDNODE="${CLAB_IMAGE_KINDNODE:-ghcr.io/trevex/ectobase/kind-node-fabric:dev}"
  export CILIUM_VERSION="${CILIUM_VERSION:-1.20.0-rc.0}"
  # kind cluster + node names (used by kubeconfig fetch, image load, node exec).
  export CLAB_KIND_CENTRAL="${CLAB_KIND_CENTRAL:-k01}"
  export CLAB_KIND_COMPUTE="${CLAB_KIND_COMPUTE:-k02}"
  export CLAB_NODE_A="${CLAB_NODE_A:-k01-control-plane}"
  export CLAB_NODE_C="${CLAB_NODE_C:-k02-control-plane}"
  ```
  (Use the ACTUAL literals you find — verify the reflector port, VNI, IPs, image refs, cluster/node names against the scripts; do NOT invent.)
- [ ] **Step 2: Source it + replace literals** — at the top of `hack/clab-up.sh`, `hack/multicluster-e2e.sh`, `hack/clab/cilium-up.sh`: `. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/clab/env.sh"` (adjust the relative path per script location — env.sh is in `hack/clab/`). Replace the inline literals (`REFLECTOR6=…`, `XDP=…`, `NETPLANE=…`, `CILIUM_VERSION=…`, the `:dev` image in clab-up's `docker image inspect`, cluster/node names) with the `$CLAB_*` vars. BEHAVIOR-IDENTICAL — the defaults equal today's literals.
- [ ] **Step 3: Verify** — `bash -n hack/clab/env.sh hack/clab-up.sh hack/multicluster-e2e.sh hack/clab/cilium-up.sh` (syntax). `shellcheck` them if available (`command -v shellcheck && shellcheck …`, else skip). `sh -c '. hack/clab/env.sh; echo "$CLAB_FABRIC_REFLECTOR6 $CLAB_IMAGE_FLOWPLANE $CILIUM_VERSION"'` → prints today's values. Confirm no literal `fd00:db8:0:1::1` / `flowplane:dev` / `1338` remains in the three scripts (grep) except in env.sh.
- [ ] **Step 4: Commit** — `refactor(clab): centralize fabric constants in hack/clab/env.sh (sourced by the scripts)`.

---

## Task 3: PATH-robust sudo (resolve tools to absolute paths)

**Files:** `hack/multicluster-e2e.sh`, `hack/clab-up.sh`, `hack/clab/cilium-up.sh`, `hack/clab/wan-up.sh` (any script using `sudo <tool>` or bare tools that later run under sudo).

- [ ] **Step 1:** Near the top of each script (after sourcing env.sh), resolve the external tools once: `KIND="$(command -v kind)"; CLAB="$(command -v containerlab)"; HELM="$(command -v helm)"; DOCKER="$(command -v docker)"; KUBECTL="$(command -v kubectl)"` — with a guard that errors clearly if a REQUIRED one is missing (e.g. `: "${KIND:?kind not found on PATH — run inside 'nix develop'}"`). Only resolve the tools each script actually uses.
- [ ] **Step 2:** Replace bare `sudo kind …` → `sudo "$KIND" …`, `sudo docker …` → `sudo "$DOCKER" …`, and bare `kind`/`containerlab`/`helm`/`kubectl` → `"$KIND"`/`"$CLAB"`/`"$HELM"`/`"$KUBECTL"`. This makes the harness work regardless of how the tools reached PATH (fixes the NixOS `secure_path` gotcha — root resolves the ABSOLUTE path, no shim). Do NOT change the logic, only the invocation.
- [ ] **Step 3: Verify** — `bash -n` all touched scripts; `shellcheck` if available; grep confirms no bare `sudo kind`/`sudo docker`/`sudo containerlab` remains (all go through `sudo "$TOOL"`). Do NOT run the fabric.
- [ ] **Step 4: Commit** — `refactor(clab): resolve tools to absolute paths for PATH-robust sudo (no secure_path shim)`.

---

## Task 4: Kustomize fixtures — multicluster scenario (CRs + agent reflector overlay)

**Files:** Create `test/e2e/fixtures/multicluster/` (kustomize); modify `hack/multicluster-e2e.sh`.

- [ ] **Step 1: Extract the scenario CRs** from the `multicluster-e2e.sh` heredoc (VPC `blue` vni 100; NetworkInterface `nic-a` ips=[10.0.0.1] nodeName k01-control-plane; `nic-c` ips=[10.0.0.3] nodeName k02-control-plane) into `test/e2e/fixtures/multicluster/vpc-nics.yaml` (the exact same YAML) + a `kustomization.yaml` listing it. (Keep the values matching env.sh; if kustomize can't easily template the IPs, keep them literal here + a comment cross-linking env.sh — the CRs are static per scenario.)
- [ ] **Step 2: Agent reflector as a kustomize overlay** — replace the `sed 's#--reflector=…#[fd00:db8:0:1::1]:1338"#' config/deploy/agent.yaml` with a kustomize overlay `test/e2e/fixtures/multicluster/agent-overlay/` that has `resources: [../../../../config/deploy/agent.yaml]` (or bases the config/deploy agent) + a strategic-merge/JSON6902 patch setting the container arg `--reflector=[<reflector>]:<port>`. Since the reflector addr comes from env.sh, render the patch value at run time: a tiny `kustomize edit` or a patch file generated from `$CLAB_FABRIC_REFLECTOR6`/`$CLAB_REFLECTOR_PORT` (e.g. `envsubst` a `patch.yaml.tmpl` → gitignored `patch.yaml`, then `kubectl kustomize`). No regex-on-YAML.
- [ ] **Step 3: Prove render-equivalence** (the safety gate) — `kubectl kustomize test/e2e/fixtures/multicluster/` must produce the SAME resources the old heredoc/sed produced. Capture the old output first (`git stash` or read the pre-change script) and diff: the VPC/NIC CRs byte-identical; the agent DS identical modulo the `--reflector` arg (which must equal `[<reflector6>]:<port>` from env.sh). Assert `kubectl kustomize … | grep -- '--reflector=\[fd00:db8:0:1::1\]:1338'` (default env). Fix until equivalent.
- [ ] **Step 4: Switch the script** — in `multicluster-e2e.sh`, replace the CR heredoc with `"$KUBECTL" --kubeconfig "$K1" apply -k test/e2e/fixtures/multicluster/`, and the `sed … agent.yaml | apply` with applying the rendered agent overlay to k02. Reuse `config/deploy/agent-kubeconfig.yaml` for the k02 kubeconfig ConfigMap instead of the heredoc (param the kubeconfig data via a generated overlay or `kubectl create configmap --from-file --dry-run -o yaml | apply`, but from a fixture not an inline heredoc — keep the ConfigMap definition in a fixture). Remove the inline heredocs.
- [ ] **Step 5: Verify (no fabric)** — `kubectl kustomize test/e2e/fixtures/multicluster/` renders clean; `bash -n hack/multicluster-e2e.sh`; the render-equivalence diff from Step 3 is clean; grep confirms no `apply -f - <<` heredoc + no `sed …--reflector` remain in the script.
- [ ] **Step 6: Commit** — `refactor(clab): extract multicluster CRs + agent-reflector into kustomize fixtures (no heredoc/sed)`.

---

## Task 5: Kustomize fixtures — KubeVirt VMs + cni/edge generated configs

**Files:** Create `test/e2e/fixtures/kubevirt/` (+ any cni/edge fixture dir); modify `hack/kubevirt-vm-e2e.sh`, `hack/cni-install.sh`, `hack/clab/edge-agents-up.sh`.

- [ ] **Step 1: Extract the KubeVirt VM manifests** from `kubevirt-vm-e2e.sh`'s two `k apply -f - <<EOF` heredocs into `test/e2e/fixtures/kubevirt/*.yaml` + a `kustomization.yaml`. Where a heredoc interpolated a shell var, keep it templatable (an `envsubst` `*.tmpl` → gitignored rendered file, or a kustomize patch fed from env.sh). Switch the script to `apply -k`/`apply -f fixtures/…`.
- [ ] **Step 2: Extract cni-install.sh + edge-agents-up.sh generated configs** (`cat > tmp <<EOF`) into fixture files (`test/e2e/fixtures/cni/…`, `…/edge/…`), templated via env where they interpolate. Switch the scripts to render-from-fixture (envsubst the fixture → tmp) instead of inline heredocs.
- [ ] **Step 3: Verify (no fabric)** — `kubectl kustomize test/e2e/fixtures/kubevirt/` renders clean; the rendered cni/edge configs match the old heredoc output (diff, with the same env vars); `bash -n` the three scripts; grep confirms the heredocs are gone.
- [ ] **Step 4: Commit** — `refactor(clab): extract KubeVirt VM + cni/edge configs into fixtures (no heredocs)`.

---

## Task 6: kind cluster config templating (non-kustomize; absolute mounts)

**Files:** `hack/clab-up.sh`, `hack/clab/kind-cluster*.yaml`.

- [ ] **Step 1:** Replace the `sed "s#PREFIX_DIR#${PREFIX_DIR}#g" kind-cluster*.yaml > *.gen` with an explicit, named-variable render (kind configs are kind config, NOT k8s resources, so kustomize doesn't apply). Use `envsubst` with a single explicit var: change the templates to reference `${CLAB_PREFIX_DIR}` and render `envsubst '${CLAB_PREFIX_DIR}' < kind-cluster.yaml > kind-cluster.yaml.gen` (the single-var arg form so nothing else is accidentally expanded), OR a `yq`-based set of the `extraMounts[].hostPath`. `CLAB_PREFIX_DIR` is the absolute `${HERE}/clab/prefixes` (kind rejects relative hostPaths). Keep the `.gen` output gitignored (it already is) + regenerated each run.
- [ ] **Step 2: Prove render-equivalence** — the rendered `*.gen` must equal the old `sed` output for the same absolute PREFIX_DIR. Diff old-vs-new `.gen` (identical). 
- [ ] **Step 3: Verify** — `bash -n hack/clab-up.sh`; render the `.gen` files standalone and diff; confirm no bare `sed …PREFIX_DIR` remains.
- [ ] **Step 4: Commit** — `refactor(clab): render kind-cluster configs via envsubst named var (no bare sed)`.

---

## Task 7: Resilience polish (set -e, image preflight, mktemp)

**Files:** `hack/multicluster-e2e.sh` (+ other scenario scripts as applicable).

- [ ] **Step 1: `set -euo pipefail`** — change `multicluster-e2e.sh` from `set -uo pipefail` to `set -euo pipefail`, and add explicit `|| true` on the genuinely-optional steps (e.g. `ip netns add … 2>/dev/null || true`, repo-add). Ensure the happy path doesn't trip `-e` on expected non-zero (grep-for-route, warmup). Add `say`/echo stage markers so a failure aborts with a clear "stage X failed".
- [ ] **Step 2: Image preflight** — near the top (after env.sh), verify the `:dev` images exist: `for img in "$CLAB_IMAGE_FLOWPLANE" "$CLAB_IMAGE_NETPLANE"; do "$DOCKER" image inspect "$img" >/dev/null 2>&1 || { echo "missing image $img — run 'make images' (or the relevant build) first" >&2; exit 1; }; done`. (Do NOT auto-build here; fail with a clear instruction.)
- [ ] **Step 3: mktemp busybox** — replace the fixed `/tmp/busybox-musl` with `BUSYBOX=$(mktemp -t busybox-musl.XXXXXX)` (+ trap cleanup), matching the existing mktemp-kubeconfig discipline.
- [ ] **Step 4: Verify** — `bash -n`; `shellcheck` if available; confirm `set -euo pipefail` + the preflight + mktemp are present and no fixed `/tmp/busybox-musl` remains. Do NOT run the fabric.
- [ ] **Step 5: Commit** — `refactor(clab): multicluster-e2e set -e discipline + image preflight + mktemp busybox`.

---

## Task 8: Unify the Go e2e onto the fixtures + env

**Files:** `test/e2e/*.go` (`routebus_test.go`, `smoke_datapath_test.go`, `smoke_lb_dhcp_test.go`, `dataplane_client.go` as needed).

- [ ] **Step 1:** Point the Go e2e at the same fixtures/constants. Where a test inlines CR YAML or constants (overlay IPs, VNI, reflector, image refs), replace with either (a) `kubectl apply -k test/e2e/fixtures/<scenario>` via `exec.Command`, or (b) constants read from `hack/clab/env.sh` values (mirror them in a small `env.go` helper, or shell out to source env.sh — pick the cleaner; a Go `const`/var block that MUST match env.sh with a comment cross-linking is acceptable if the tests don't need runtime override). Keep the tests calling the refactored `../../hack/clab-up.sh` and the skip-if-tooling-absent guards. Goal: no divergent inline deploy logic between Go e2e and the shell scenarios — one fixtures source of truth.
- [ ] **Step 2: Verify (no fabric)** — `cd test/e2e && go build ./... && go vet ./...` clean; `go test ./... -run xxxNoSuchTest` (compiles + the skip-guards still fire without tooling — but tooling is now present via the devShell, so guard on docker-daemon/cluster instead — confirm the tests still SKIP cleanly when no fabric is up, i.e. they don't try to deploy without clab-up succeeding). Do NOT let it actually bring up the fabric here.
- [ ] **Step 3: Commit** — `refactor(clab): unify Go e2e onto the shared kustomize fixtures + env constants`.

---

## Task 9: From-clean fabric validation + README + finish  (CONTROLLER-RUN)

**This task is run by the controller, not a subagent (15-min sudo fabric bring-up).**

- [ ] **Step 1:** `hack/clab-down.sh` (tear down the currently-up fabric) — from a plain `nix develop`.
- [ ] **Step 2:** From a plain `nix develop` (NO `nix shell nixpkgs#…`, NO sudo-shim): `hack/clab-up.sh` → fabric up, all clusters Ready. Then `hack/multicluster-e2e.sh` → **cross-cluster overlay ping PASSES both directions** (same green as the pre-refactor run). This proves portability (tooling from the devShell) + PATH-robust sudo + the extracted fixtures + env.sh all work from clean.
- [ ] **Step 3:** `go test ./test/e2e/... -run TestCrossNodeOverlayPing -v` (the fixture-unified Go e2e) → PASS (or the smokes as feasible). (Attempt the N-S NAT-egress scenario if easy; else note it still-open.)
- [ ] **Step 4:** Update `hack/clab/README.md`: the harness now runs from a plain `nix develop` (tooling included); constants live in `env.sh`; manifests live in `test/e2e/fixtures/` (kustomize); no cilium-cli (helm chart). Remove any stale "install kind/containerlab first" instructions.
- [ ] **Step 5: Commit** the README + any final tweaks; then finish the branch (superpowers:finishing-a-development-branch) — merge to main + push per the usual pattern.

## Notes / risks
- **The from-clean fabric run (Task 9) is the real gate** — everything before it is validated cheaply (kustomize render-equivalence, shellcheck, nix develop, go build). Subagents must NOT run the fabric.
- **Render-equivalence diffs (Tasks 4/5/6) are the safety net** — prove the extracted fixtures/rendered configs produce the SAME YAML the heredocs/sed did, so behavior is preserved without a cluster.
- Incremental low-risk-first ordering: devShell (1) → env.sh (2) → sudo-robust (3) → fixtures (4/5/6) → resilience (7) → Go-e2e (8) → fabric gate (9). If Task 9 reveals a break, it's isolated to the last fixture/script change.
- Do NOT change the fabric topology, dataplane, or what the e2e validates — pure harness refactor.
