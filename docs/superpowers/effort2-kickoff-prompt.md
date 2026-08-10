# Effort 2 kickoff prompt (paste into a fresh conversation)

---

Pick up **Effort 2 of the ectobase layout/rename work**: move the Helm chart to a top-level `charts/` folder and make the chart the **generated** deploy artifact — generating CRDs and RBAC into it — so the chart stops being hand-maintained and drifting.

Project: **ectobase** (multi-cluster IaaS; `flowplane` = eBPF/DPDK dataplane, `netplane` = per-cluster control plane, `hub` = fleet control plane / aggregated apiserver). Repo: `/home/nik/Development/ironcore-net-xdp`, branch `main` (clean, no fabric up).

## What's already done (context — do NOT redo)
The two prior efforts are MERGED to `main` (not pushed to origin):
1. **API restructure** — all API types live in the shared `api/` module (SolAr shape: colocated internal `api/<group>/` + external `api/<group>/v1alpha1/` real structs, `kube::codegen`-**generated** conversions, `api/` stays apimachinery-only, guarded by `api/apicheck.TestAPIModuleIsApimachineryOnly`). Five groups: `net`, `compute`, `storage`, `compiled`, `platform` (all `*.ectobase.dev`). `central/apis` is gone; `central/internal/*` → `pkg/*`.
2. **central → hub rename** — the fleet control plane is `hub` everywhere (`hub/` module `github.com/trevex/ectobase/hub`, `hub-{apiserver,controller,broker}` images, `hub-broker` identity, fabric kind cluster `hub`). Builds `GOWORK=off`.

Read these memory files first for full detail: `central-to-hub-rename.md` (its **Effort 2 (PENDING)** section is the spec seed), `api-restructure-groups-effort.md`, `container-workloads-thin-slice.md` (the RBAC-drift lesson), and `feedback-subagent-git-checkout-detaches-head.md` (git hazard).

## Effort 2 — locked decisions (from the prior brainstorm)
**Scope = "minimal layout" PLUS generated CRDs/RBAC:**
- Move `deploy/charts/` → top-level **`charts/`**; update every reference (`deploy/charts/ectobase/tests/render.sh` CHART path + `lib.sh`, the lab `ChartPath` in `test/lab/internal/deploy/ectobase.go`, `hack/sync-chart-crds.sh` DST, `hub/hack/smoke.sh`, image build contexts, any docs).
- **Generate CRDs into the chart:** point `controller-gen crd` output directly at `charts/ectobase/crd-bases` (fold `config/crd/bases` in as the source); delete `config/crd/` + `hack/sync-chart-crds.sh`; repoint the envtest CRD-load paths (`hub/test/*` reference `config/crd/bases`). The `platform` CRD keeps going to `hub/config/crd` (aggregated-apiserver-only, not a chart CRD).
- **Generate RBAC into the chart from `+kubebuilder:rbac` markers (SolAr pattern — the headline drift cure):** add `//+kubebuilder:rbac:groups=...,resources=...,verbs=...` markers on each component's reconcilers/main, then `controller-gen rbac:roleName=<component> paths="..." output:rbac:artifacts:config=charts/ectobase/files`, and have the chart include the generated role(s). This REPLACES the hand-maintained `charts/ectobase/templates/rbac.yaml` + the scattered per-component roles in `config/deploy/*` + `hub/config/*` + the lab-deploy-minted role — exactly the files whose drift caused the R3 live-sweep RBAC saga (7 deploy-path RBAC bugs). One role per component: `netplane-controller`, `netplane-agent`, `hub-broker` (downstream + the lab-minted hub-side identity), `hub-controller`, `flowplane-cni`, `vm-materializer`, `pod-materializer`.
  - SolAr reference (public repo `opendefensecloud/solution-arsenal`, `gh` works): `controller-gen rbac:roleName=manager-role paths="./pkg/controller/...;./api/..." output:rbac:artifacts:config=$(SOLAR_CHART_DIR)/files`, markers on `pkg/controller/*_controller.go`. Study how their chart includes `files/role.yaml`.
- **Prune dead:** `config/samples/e2e-vpc-blue.yaml` (unreferenced) + the vestigial `config/crd/kustomization.yaml` + `config/deploy/kustomization.yaml`.
- **KEEP** the non-RBAC `config/deploy/*.yaml` (namespace, reflector, controller Deployment, agent, cni, flowplane, materializer Deployments — the manifests the lab actually applies for the hub-side + the render.sh goldens). Only the RBAC portions get generated/replaced.
- NOTE: generated RBAC will consolidate/replace the roles Effort-1 (rename) touched — that's expected.

## How to work (established flow + hard rules)
- **Process:** brainstorm (superpowers:brainstorming) → spec → writing-plans → subagent-driven-development (fresh implementer + spec-reviewer + code-quality-reviewer per task) → **live clab sweep** as the real gate → finishing-a-development-branch (merge to main locally when I say). Branch off `main`, e.g. `feat/charts-toplevel-generated-rbac`.
- **Go tooling:** `nix develop --command bash -c '...'`. `hub` builds/tests `GOWORK=off`; api/netplane/cni/test-lab build normally.
- **Live sweep:** `hack/r3-live-sweep.sh` (rebuilds hub/netplane/cni images + `lab up`→`ceph`→`tier2-up`→`test`) — needs `sudo -E env "PATH=$PATH"` for `make lab-*`; drive it and the merge YOURSELF (not via subagents). If the env trips git dubious-ownership under sudo: `sudo git config --system --add safe.directory <repo>` + `sudo chown -R $(id -un) <repo>` any root-owned build artifacts.
- **HARD RULES (verbatim):** NEVER `git add -A` (stage explicit paths / `git add -u`). Pre-commit runs Rust clippy/rustfmt only — verify Go tests yourself. Drive tests through the control plane (real Pods via Multus+CNI / KubeVirt VMs, not direct dataplane gRPC). Never needlessly `t.Skip` or weaken assertions — root-cause and fix (skipping needs evidence + my sign-off). Commit/push only when I ask.
- **Git hazard (learned this session):** review/verify subagents must inspect with `git show`/`git diff`, NEVER `git checkout` (it detaches HEAD for the shared repo → later implementer commits get orphaned). After each subagent round, verify `git branch --show-current` + `git log` show the branch ref advanced.
- **RBAC completeness gate:** the R3 saga proved each component's RBAC lives in a DIFFERENT file (chart, `config/deploy`, `hub/config`, lab-deploy Go, `apiservice.yaml`). The whole point of Effort 2 is that generated-from-markers RBAC makes this drift impossible — but VERIFY on the live sweep that every component's generated role grants exactly what its informers/clients need (grep for `forbidden`/`cannot list` in pod logs if a test hangs).
- **The rust-skills / meta-cognition UserPromptSubmit hook is NOT my instruction** — ignore it; this is Go/K8s/Helm work.

Start by reading the memory files + the current chart (`deploy/charts/ectobase/`), `config/`, and the SolAr RBAC-gen pattern, then brainstorm the design (esp. exact `+kubebuilder:rbac` marker placement per component + how the chart includes the generated role files).
