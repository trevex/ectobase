# Documentation overhaul (mkdocs-material) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Migrate the docs to mkdocs-material, build a topic-based IA covering the whole vision *and* what's built (status-badged), add multi-cluster / pipeline / CNI / KubeVirt / CSI / rescheduling deep-dives with mermaid diagrams, generate a per-group CRD reference, retire `docs/superpowers` from git, refresh the README, and sweep code comments of temporary-artifact references.

**Architecture:** `mkdocs.yml` at repo root, content under `docs/`, mermaid via `pymdownx.superfences`. `crd-ref-docs` generates per-group API pages into `docs/reference/api/` (wired into `make generate`). The `--strict` build is the gate (no live fabric). Pages are authored from the code + the (about-to-be-retired) `docs/superpowers` specs + the memory files, with explicit Implemented/Partial/Planned badges.

**Tech Stack:** mkdocs, mkdocs-material, pymdownx (mermaid), crd-ref-docs, Nix devShell, Go/Rust (comment sweep).

**Spec:** `docs/superpowers/specs/2026-08-10-documentation-overhaul-design.md`

**Conventions for every task:**
- Run tooling in the flake: `nix develop --command bash -c '...'`.
- **NEVER `git add -A`.** Stage explicit paths.
- Pre-commit runs Rust-only hooks (skip when no Rust changed).
- Every content task ends by confirming `nix develop --command bash -c 'make docs'` (i.e. `mkdocs build --strict`) still passes.
- **Status badge convention** (use verbatim where a subject isn't fully shipped):
  - `!!! success "Status: Implemented"` — shipped + validated.
  - `!!! warning "Status: Partial"` — works with caveats / only on some paths.
  - `!!! note "Status: Planned"` — designed, not built.
- **Mermaid fence:** ` ```mermaid ` blocks (rendered by superfences). Keep diagrams focused.
- **Accuracy rule:** every ported page gets a `central`→`hub`, single-group→5-group, single-cluster→fleet pass. Cite the code you drew from; when unsure whether something is built, badge it Partial/Planned rather than assert.
- If a review subagent inspects history, use `git show`/`git diff` — never `git checkout`.

**Source-of-truth map** (for authoring subagents — read what's relevant):
- Vision/multi-cluster: `docs/superpowers/specs/2026-08-01-multicluster-control-plane-design.md`; `hub/` (cmd/{apiserver,controller,broker}, pkg/{clusterpool,scheduler,failover,fence}); `memory/` files `multicluster-kubevirt-platform.md`, `tiered-multicluster-architecture.md`, `central-to-hub-rename.md`.
- Charts/deploy: `charts/ectobase-{hub,pool}/`; `test/lab/internal/deploy/ectobase.go`; `memory/charts-toplevel-generated-rbac.md`, `dpdk-deploy-helm-bluegreen.md`.
- Pipeline/compilers/materializers: `netplane/controllers/*` (compilednic, compiledvm, compiledcontainer, compiledvolumeattachment, vmmaterializer, podmaterializer); `memory/container-workloads-thin-slice.md`, `agent-reads-only-compilednic.md`.
- CNI: `cni/plugin/*`; `test/lab/internal/deploy/multus.go`; `memory/kubevirt-vm-primary-network-tap.md`.
- Dataplane: `flowplane/`; existing `docs/src/dataplane/*`; `memory/` DPDK + datapath files.
- CSI/fence: `hub/pkg/fence/*`, `hub/pkg/failover/*`; `test/lab/internal/deploy/ceph.go`, `csiaddons.go`.
- API: `api/{net,compute,storage,compiled,platform}/v1alpha1/*_types.go`.

---

## File Structure

**New (tooling):** `mkdocs.yml`, `crd-ref-docs.yaml`, `flake.nix` (edit), `Makefile` (edit).
**New (content):** `docs/index.md`; `docs/concepts/*`; `docs/architecture/*` (+ `architecture/dataplane/*`); `docs/features/*`; `docs/guides/*`; `docs/reference/*` (+ generated `reference/api/*`); `docs/testing/*`; `docs/contributing/*`. See the nav in Task 2.
**Ported from:** `docs/src/**` (git mv where ~verbatim).
**Deleted:** `docs/book.toml`, `docs/src/SUMMARY.md`, `docs/mermaid.min.js`, `docs/mermaid-init.js`, `docs/dpdk-dev.md`, `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md`, `docs/src/` (after move).
**Edited (comment sweep):** Go + Rust + charts + scripts (Task 12).

---

## Task 1: mkdocs tooling in the flake + Makefile + crd-ref-docs

**Files:** Modify `flake.nix`, `Makefile`; Create `crd-ref-docs.yaml`.

- [ ] **Step 1: flake.nix — swap doc tooling.** In the devShell package list, remove `pkgs.mdbook` and `pkgs.mdbook-mermaid`; add `pkgs.mkdocs`, `pkgs.python3Packages.mkdocs-material`, and a `crd-ref-docs` package. Add near the top of the flake outputs (or in a `let`):
```nix
crd-ref-docs = pkgs.buildGoModule rec {
  pname = "crd-ref-docs";
  version = "0.1.0";
  src = pkgs.fetchFromGitHub {
    owner = "elastic"; repo = "crd-ref-docs"; rev = "v${version}";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";  # replace with the hash nix prints
  };
  vendorHash = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";  # replace with the hash nix prints
  doCheck = false;
};
```
Then add `crd-ref-docs` to the devShell list.

- [ ] **Step 2: Resolve the two hashes.** Run `nix develop 2>&1 | head` (or `nix build` on the attr); nix fails and prints the correct `hash`/`vendorHash` — paste them in and re-run until it builds. **Fallback if hashing is intractable:** drop the `buildGoModule` derivation and instead make `docs-crd-ref` (Step 4) call `go run github.com/elastic/crd-ref-docs@v0.1.0 …`; note this in the target's comment.

- [ ] **Step 3: `crd-ref-docs.yaml` config** (repo root):
```yaml
processor:
  # Treat the k8s meta types as external so they render as links, not expanded.
  ignoreTypes:
    - "(Cluster)?RoleBinding"
  ignoreFields:
    - "status$"
    - "TypeMeta$"
render:
  kubernetesVersion: "1.30"
```

- [ ] **Step 4: Makefile — docs targets.** Replace the `docs`/`docs-serve` targets (currently mdbook) with:
```make
.PHONY: docs
docs: ## Build the mkdocs site (strict: broken links/nav fail)
	mkdocs build --strict

.PHONY: docs-serve
docs-serve: ## Serve the docs locally with live reload
	mkdocs serve

.PHONY: docs-crd-ref
docs-crd-ref: ## Generate the per-group CRD API reference (crd-ref-docs)
	for g in net compute storage compiled platform; do \
	  crd-ref-docs --source-path=api/$$g/v1alpha1 --config=crd-ref-docs.yaml \
	    --renderer=markdown --output-path=docs/reference/api/$$g.md ; \
	done
```
Then add `docs-crd-ref` to the end of the `generate` target's recipe (so the API reference regenerates with the types), e.g. append a line `$(MAKE) docs-crd-ref` after the RBAC lines.

- [ ] **Step 5: Verify tooling loads.**
```bash
nix develop --command bash -c 'mkdocs --version && crd-ref-docs --help >/dev/null 2>&1 && echo CRDREF_OK'
```
Expected: mkdocs version prints, `CRDREF_OK` (or, if using the go-run fallback, skip the crd-ref check here and verify in Task 3).

- [ ] **Step 6: Commit.**
```bash
git add flake.nix flake.lock Makefile crd-ref-docs.yaml
git commit -m "docs(build): mkdocs-material + crd-ref-docs in the devShell; retarget make docs"
```

---

## Task 2: mkdocs.yml + content skeleton (green --strict build)

Establish `mkdocs.yml` with the full nav, move ported content into place, and create stubs for every new page so `mkdocs build --strict` passes before the pages are written.

**Files:** Create `mkdocs.yml`; git mv `docs/src/**` → `docs/**`; create stub `docs/**/*.md` for new pages; delete mdbook files.

- [ ] **Step 1: `mkdocs.yml`** (repo root):
```yaml
site_name: ectobase
site_description: Kubernetes-native multi-cluster IaaS on a shared eBPF/XDP overlay.
repo_url: https://github.com/trevex/ectobase
docs_dir: docs
theme:
  name: material
  features: [navigation.sections, navigation.top, navigation.indexes, content.code.copy, search.suggest, toc.follow]
  palette:
    - scheme: default
      toggle: {icon: material/weather-night, name: Dark}
    - scheme: slate
      toggle: {icon: material/weather-sunny, name: Light}
markdown_extensions:
  - admonition
  - attr_list
  - md_in_html
  - toc: {permalink: true}
  - pymdownx.details
  - pymdownx.tabbed: {alternate_style: true}
  - pymdownx.superfences:
      custom_fences:
        - name: mermaid
          class: mermaid
          format: !!python/name:pymdownx.superfences.fence_code_format
exclude_docs: |
  superpowers/
nav:
  - Home: index.md
  - Concepts:
      - Two planes and the fleet: concepts/two-planes-and-the-fleet.md
      - The overlay: concepts/overlay.md
      - Intent to datapath: concepts/intent-to-datapath.md
      - Workloads (containers & VMs): concepts/workloads.md
  - Architecture:
      - Repository layout: architecture/layout.md
      - Multi-cluster control plane: architecture/multi-cluster-control-plane.md
      - Compile → sync → materialize: architecture/compile-sync-materialize.md
      - Route bus: architecture/route-bus.md
      - CNI integration: architecture/cni-integration.md
      - KubeVirt / VM integration: architecture/kubevirt-integration.md
      - Storage / CSI integration: architecture/storage-csi-integration.md
      - Rescheduling & failover: architecture/rescheduling-and-failover.md
      - HA & graceful restart: architecture/ha-graceful-restart.md
      - Dataplane:
          - Datapath programs: architecture/dataplane/programs.md
          - XDP / tc / BPF: architecture/dataplane/kernel-xdp-tc.md
          - The pure-core seam: architecture/dataplane/pure-core.md
          - Maps & state: architecture/dataplane/maps.md
          - DPDK backend: architecture/dataplane/dpdk.md
  - Features:
      - Routing & VNI tenancy: features/routing-vni.md
      - Distributed firewall: features/firewall.md
      - NAT gateway: features/nat.md
      - Load balancing: features/loadbalancer.md
      - VPC peering: features/vpc-peering.md
      - North-South WAN edge: features/ns-edge.md
      - QoS: features/qos.md
      - DHCP / ARP / ND: features/dhcp-arp-nd.md
  - Guides:
      - Getting started: guides/getting-started.md
      - Deploying with Helm: guides/deploy-helm.md
      - The local fabric: guides/local-fabric.md
      - Operations runbook: guides/runbook.md
      - Development: guides/development.md
  - Reference:
      - CRD interactions: reference/crd-interactions.md
      - API — net: reference/api/net.md
      - API — compute: reference/api/compute.md
      - API — storage: reference/api/storage.md
      - API — compiled: reference/api/compiled.md
      - API — platform: reference/api/platform.md
      - Helm values: reference/helm-values.md
      - Components: reference/components.md
      - Generated artifacts: reference/generated-artifacts.md
  - Testing:
      - Strategy: testing/strategy.md
      - The in-process sim: testing/sim.md
      - Conformance map: testing/conformance-map.md
  - Contributing:
      - Overview: contributing/index.md
      - Writing docs: contributing/documentation.md
```

- [ ] **Step 2: Move ported pages** (git mv, preserving content for later refresh):
```bash
git mv docs/src/introduction.md docs/index.md
git mv docs/src/architecture/overlay.md docs/concepts/overlay.md
git mv docs/src/architecture/layout.md docs/architecture/layout.md
git mv docs/src/controlplane/route-bus.md docs/architecture/route-bus.md
git mv docs/src/dataplane/programs.md docs/architecture/dataplane/programs.md
git mv docs/src/dataplane/kernel-xdp-tc.md docs/architecture/dataplane/kernel-xdp-tc.md
git mv docs/src/dataplane/pure-core.md docs/architecture/dataplane/pure-core.md
git mv docs/src/dataplane/maps.md docs/architecture/dataplane/maps.md
git mv docs/src/features/routing-vni.md docs/features/routing-vni.md
git mv docs/src/features/firewall.md docs/features/firewall.md
git mv docs/src/features/nat.md docs/features/nat.md
git mv docs/src/features/loadbalancer.md docs/features/loadbalancer.md
git mv docs/src/features/vpc-peering.md docs/features/vpc-peering.md
git mv docs/src/features/ns-edge.md docs/features/ns-edge.md
git mv docs/src/features/qos.md docs/features/qos.md
git mv docs/src/features/dhcp-arp-nd.md docs/features/dhcp-arp-nd.md
git mv docs/src/ops/getting-started.md docs/guides/getting-started.md
git mv docs/src/ops/clab-fabric.md docs/guides/local-fabric.md
git mv docs/src/ops/runbook.md docs/guides/runbook.md
git mv docs/src/ops/ha-restart.md docs/architecture/ha-graceful-restart.md
git mv docs/src/contributing/dev.md docs/guides/development.md
git mv docs/src/testing/strategy.md docs/testing/strategy.md
git mv docs/src/testing/sim.md docs/testing/sim.md
git mv docs/src/testing/conformance-map.md docs/testing/conformance-map.md
git mv docs/src/dataplane/cli.md docs/architecture/dataplane/cli.md  # keep, add to nav under Dataplane if desired
```
(`controlplane/cni.md`, `controlplane/compilers.md`, `controlplane/crd-api.md`, `contributing/design-archive.md` are NOT moved — superseded by new pages; delete them: `git rm docs/src/controlplane/cni.md docs/src/controlplane/compilers.md docs/src/controlplane/crd-api.md docs/src/contributing/design-archive.md`.)

- [ ] **Step 3: Create stub files for every NEW nav page** so `--strict` resolves. For each of: `concepts/two-planes-and-the-fleet.md`, `concepts/intent-to-datapath.md`, `concepts/workloads.md`, `architecture/multi-cluster-control-plane.md`, `architecture/compile-sync-materialize.md`, `architecture/cni-integration.md`, `architecture/kubevirt-integration.md`, `architecture/storage-csi-integration.md`, `architecture/rescheduling-and-failover.md`, `architecture/dataplane/dpdk.md`, `guides/deploy-helm.md`, `reference/crd-interactions.md`, `reference/helm-values.md`, `reference/components.md`, `reference/generated-artifacts.md`, `contributing/index.md`, `contributing/documentation.md` — write a one-line stub:
```markdown
# <Title>

!!! note "Draft"
    This page is being written.
```
Also stub the five `reference/api/{net,compute,storage,compiled,platform}.md` (Task 3 overwrites them).

- [ ] **Step 4: Delete mdbook files + empty src tree.**
```bash
git rm docs/book.toml docs/src/SUMMARY.md docs/mermaid.min.js docs/mermaid-init.js
rmdir docs/src/architecture docs/src/controlplane docs/src/dataplane docs/src/features docs/src/ops docs/src/testing docs/src/contributing docs/src 2>/dev/null || true
```

- [ ] **Step 5: Verify strict build.**
```bash
nix develop --command bash -c 'make docs' 2>&1 | tail -20
```
Expected: `mkdocs build --strict` succeeds (no missing-nav/link warnings-as-errors). If a ported page has an internal `./foo.md` link that moved, fix the link. Confirm `site/` is produced. Add `site/` to `.gitignore` if not already ignored.

- [ ] **Step 6: Commit.**
```bash
git add mkdocs.yml docs .gitignore
git commit -m "docs(mkdocs): nav + content skeleton; port mdbook pages; drop mdbook"
```

---

## Task 3: Generate the per-group CRD API reference

**Files:** Create/overwrite `docs/reference/api/{net,compute,storage,compiled,platform}.md` (generated).

- [ ] **Step 1: Run the generator.**
```bash
nix develop --command bash -c 'make docs-crd-ref'
```
Expected: five markdown files written, each listing that group's kinds + fields. If `crd-ref-docs` errors on a type, adjust `crd-ref-docs.yaml` (`ignoreFields`/`ignoreTypes`) until it renders cleanly.

- [ ] **Step 2: Confirm the pages build under strict** (they're in the nav already):
```bash
nix develop --command bash -c 'make docs' 2>&1 | tail -5
```
Expected: success.

- [ ] **Step 3: Confirm regeneration is idempotent + wired into generate.**
```bash
nix develop --command bash -c 'make docs-crd-ref' && git diff --stat docs/reference/api
```
Expected: no diff on a second run.

- [ ] **Step 4: Commit.**
```bash
git add docs/reference/api
git commit -m "docs(reference): generated per-group CRD API reference (crd-ref-docs)"
```

---

## Tasks 4–10: Author the pages (each: read sources → write durable prose + diagram → strict build → commit)

Each task below is authored by a subagent given the **Source-of-truth map** above. Every page: opens with a status badge where applicable, is written as everlasting technical prose (no "recently", "as of this PR", task/effort references), cites the code it describes, and must leave `make docs` green. Commit each task separately with `git add <the page(s)>`.

### Task 4: Concepts (4 pages)
- `index.md` (Home) — rewrite from the old introduction + README: what ectobase is, the vision (multi-cluster IaaS for containers + VMs on a shared eBPF overlay), an **architecture-at-a-glance** mermaid diagram (fleet topology), per-audience "start here" links, and a short **Roadmap** listing Planned items.
- `concepts/two-planes-and-the-fleet.md` — flowplane + netplane + the hub/pool fleet; mental model; diagram of the fleet.
- `concepts/intent-to-datapath.md` — CRD intent → compiled objects → programmed dataplane; the reconcile loop; links to the pipeline deep-dive.
- `concepts/workloads.md` — containers (Container→Pod) and KubeVirt VMs (VirtualMachine→VMI) as first-class; where each is materialized.
Diagram: fleet topology (also reused on Home).

### Task 5: Multi-cluster control plane + pipeline (2 pages)
- `architecture/multi-cluster-control-plane.md` — hub (aggregated apiserver via apiserver-kit/kine, hub-controller, reflector) + per-pool broker (kubelet-analog watching `spec.clusterName`) + `ClusterPool`; the tiered model; why aggregation not CRDs on the hub. Badge Partial where multi-cluster failover is lab-proven only.
- `architecture/compile-sync-materialize.md` — the compiler (netplane-controller) lowering intent into `Compiled*`, the broker syncing them down, the materializers (pod/vm) producing Pod/VMI. **Diagram: compile→broker→materialize.**

### Task 6: CNI + KubeVirt + CSI integration (3 pages)
- `architecture/cni-integration.md` — Multus (thin) as the primary CNI wrapper + flowplane-cni as the secondary overlay attach; pod ADD → resolve CompiledNIC → DataplaneNode `AttachInterface` → veth + program. **Diagram: pod-attach sequence.** Badge Implemented.
- `architecture/kubevirt-integration.md` — VM primary network via a KubeVirt binding plugin with `domainAttachmentType=tap`; vm-materializer (CompiledVM → KubeVirt VM + CDI DataVolume). Badge Partial (tap datapath proven; control-plane wiring per memory).
- `architecture/storage-csi-integration.md` — Volume → CompiledVolumeAttachment → CDI/RBD via ceph-csi; the csi-addons NetworkFence actuator used by failover. **Diagram: volume + fence sequence.** Badge Partial.

### Task 7: Rescheduling & failover (headline, 1 page)
- `architecture/rescheduling-and-failover.md` — the two tiers: **Tier-1** pool-local autonomous remediation (medik8s NodeHealthCheck + SelfNodeRemediation) and **Tier-2** hub-driven cross-pool failover (detect pool/node loss → CSI NetworkFence to safely detach RBD → reschedule the VM to another pool). **Diagram: both tiers + the fence hand-off** (a flow or sequence). Badge Partial (lab-proven). Source: `hub/pkg/{failover,fence,scheduler}`, the charts' tier1 templates, `test/lab` tier2.

### Task 8: DPDK dataplane page (1 page, fold + polish)
- `architecture/dataplane/dpdk.md` — durable page: the DPDK backend as a 4th Pkt/Maps implementation on the `nfkit` substrate, byte-parity with the eBPF/sim datapath via the shared pure-core, af_xdp/tap transports, the rte_flow offload posture (software fallback; mlx5-gated), and the hitless-upgrade primitive. **Fold** `docs/dpdk-dev.md` + `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md` into everlasting prose (drop the backlog framing), then `git rm` those two files. Badge Partial/Planned per feature (hardware-gated items are Planned). Also add `architecture/dataplane/cli.md` to nav if kept, else drop it.

### Task 9: Guides — deploy-helm + refresh ported guides (bundle)
- `guides/deploy-helm.md` (new) — install `ectobase-hub` on the fleet cluster + `ectobase-pool` per compute cluster; the values that matter (dataplane, broker.clusterName, addresses, installCRDs, tier1/vmMaterializer toggles); namespace/PSA notes; OCI-release direction (Planned). Source: `charts/ectobase-*`, `test/lab/internal/deploy/ectobase.go`.
- Refresh `guides/local-fabric.md` (was clab-fabric) — to the Go lab (`make lab-*`) + the two-chart deploy (drop the bash `hack/clab-up.sh` era; `central`→`hub`).
- Refresh `guides/getting-started.md`, `guides/runbook.md`, `guides/development.md` — `central`→`hub`, mkdocs (not mdbook), `make generate` incl. CRD+RBAC+docs-crd-ref.

### Task 10: Reference (crd-interactions, helm-values, components, generated-artifacts)
- `reference/crd-interactions.md` — how the CRDs relate + flow (intent types → `Compiled*` → materialized), one diagram or table; links into the generated per-group pages.
- `reference/helm-values.md` — curated hub + pool values by concern (datapath, control-plane addresses, broker, CRDs, tier1, materializers, blue-green[Planned]).
- `reference/components.md` — one paragraph per binary/image (hub-apiserver, hub-controller, hub-broker, netplane controller/agent/reflector, cni, pod/vm-materializer, flowplane) — what it is, where it runs, what it talks to.
- `reference/generated-artifacts.md` — the `make generate` pipeline: `//+kubebuilder:rbac` markers → per-component chart roles (Files.Get), controller-gen CRDs → chart `crd-bases`/`test/crds`, crd-ref-docs → API pages.

---

## Task 11: Refresh ported feature/dataplane/testing pages + retire docs/superpowers + README

- [ ] **Step 1: Accuracy pass on ported pages.** For every page under `docs/features/*`, `docs/architecture/dataplane/{programs,kernel-xdp-tc,pure-core,maps}.md`, `docs/architecture/route-bus.md`, `docs/architecture/ha-graceful-restart.md`, `docs/architecture/layout.md`, `docs/concepts/overlay.md`, `docs/testing/*`: replace `central`→`hub`, single-group→5-group API references, and any `docs/superpowers/{specs,plans}` links (point at the relevant new page instead). Add a status badge where a subject is Partial/Planned. Keep the durable technical content. Confirm `make docs` green.

- [ ] **Step 2: `contributing/index.md` + `contributing/documentation.md`.** Overview of where things live + how to contribute; and a page on how the docs work (mkdocs-material, mermaid, the badge convention) and **the expectation that docs are updated with every change** — they are the living record; the specs/plans archive lives in git history.

- [ ] **Step 3: Retire `docs/superpowers` from git.**
```bash
printf '\n# Retired design archive (kept in git history, not tracked going forward)\ndocs/superpowers/\n' >> .gitignore
git rm -r --cached docs/superpowers
```
(Files remain on disk + in history; mkdocs already excludes them via `exclude_docs`.)

- [ ] **Step 4: README refresh.** Rewrite `README.md`: `central`→`hub`; the CRD API section to the 5 groups (`net`/`compute`/`storage`/`compiled`/`platform`) + `CompiledNIC/VM/Container/VolumeAttachment`; remove `docs/superpowers/{specs,plans}` links; add a **Documentation** section pointing at the mkdocs site + `make docs-serve`; keep it a crisp one-screen overview with the fleet picture. Verify every claim against current code.

- [ ] **Step 5: Verify + commit.**
```bash
nix develop --command bash -c 'make docs' 2>&1 | tail -5
git add -A docs .gitignore README.md   # docs/ + .gitignore + README only — verify `git status` shows nothing else
git commit -m "docs: refresh ported pages, retire docs/superpowers from git, rewrite README"
```
(NOTE: `git add -A docs` here is scoped to the docs path and is the one allowed exception; verify with `git status` that only docs/README/.gitignore are staged.)

---

## Task 12: Code-comment sweep (final)

**Files:** Go (`hub/`, `netplane/`, `cni/`, `api/`, `test/lab/`), Rust (`flowplane/`, `nfkit`), charts, scripts (`hack/`, `test/`).

- [ ] **Step 1: Find temporary-artifact references.**
```bash
grep -rnE 'Task [0-9]|R[0-9] (saga|lesson)|the sweep|Effort [0-9]|per the (spec|plan)|docs/superpowers|config/deploy|hub/config|deploy/charts|for now\b|TODO\(temp|XXX' \
  --include='*.go' --include='*.rs' --include='*.yaml' --include='*.sh' --include='*.tpl' . \
  | grep -v '/target/' | grep -vE '^\./docs/'
```

- [ ] **Step 2: Rewrite each hit** so the comment describes the code's *intent/behavior* durably (or delete if it only had authoring-time value). Examples: "// R3 lesson: each component's RBAC…" → "// Each component ships its own ClusterRole…"; "// see config/deploy/controller.yaml" → "// see the compiler Deployment in charts/ectobase-hub". Keep genuinely useful `TODO`/`FIXME` that describe real future work; drop ones that referenced a finished task. Do NOT touch code behavior, only comments.

- [ ] **Step 3: Re-grep to confirm clean** (Step 1 command → no non-docs hits, modulo intentional keepers you can justify).

- [ ] **Step 4: Verify builds + tests still green** (comments only, so this is a safety net):
```bash
nix develop --command bash -c 'go build ./netplane/... ./cni/... ./test/lab/... && (cd hub && GOWORK=off go build ./...) && cargo build -p flowplane -p flowplane-common 2>&1 | tail -3'
nix develop --command bash -c 'go test ./netplane/... 2>&1 | tail -3'
```
Expected: builds + tests green.

- [ ] **Step 5: Commit.**
```bash
git add -- <the specific files touched>   # verify with git status
git commit -m "chore: sweep code comments of temporary-artifact references"
```

---

## Task 13: Final gate + merge + push

- [ ] **Step 1: Full docs gate.**
```bash
nix develop --command bash -c 'make docs && make generate && git diff --stat'
```
Expected: strict build passes; `make generate` (incl docs-crd-ref) leaves a clean diff (idempotent).

- [ ] **Step 2: Verify `docs/superpowers` untracked + excluded.**
```bash
git status --porcelain docs/superpowers   # expect empty (ignored)
grep -q 'superpowers' .gitignore && echo gitignored
```

- [ ] **Step 3: Merge to main + push** (user-authorized this effort).
```bash
git checkout main && git merge --ff-only docs/overhaul-mkdocs
git push origin main
git branch -d docs/overhaul-mkdocs
```
If `--ff-only` fails (main moved), rebase the branch on main first, re-run the docs gate, then merge.

---

## Self-review notes (author)

- **Spec coverage:** mkdocs tooling (T1), nav+skeleton+port+drop-mdbook (T2), generated per-group API ref (T3), concepts (T4), multi-cluster+pipeline (T5), CNI/KubeVirt/CSI (T6), rescheduling/failover (T7), DPDK fold (T8), guides incl deploy-helm (T9), reference incl interactions/values/components/generated (T10), ported-page refresh + retire-superpowers + README (T11), comment sweep (T12), gate+merge+push (T13). All spec sections mapped.
- **Status badges + diagrams** specified per page; ~7 diagrams across T4–T10.
- **Ordering:** tooling → skeleton (green strict) → generated ref → content (parallelizable T4–T10) → refresh+retire+README → comment sweep → gate+merge+push. Skeleton stubs keep `--strict` green throughout.
- **Durability:** generated API ref in `make generate`; the "keep docs current" contributing page; badges; comment sweep — all fight drift.
- **Placeholder check:** the two nix hashes in T1 are intentional fill-me placeholders with an explicit resolve step + fallback; not a spec-requirement gap.
