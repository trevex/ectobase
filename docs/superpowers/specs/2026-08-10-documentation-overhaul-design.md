# Documentation overhaul: mkdocs-material, architecture deep-dives, generated API reference

**Date:** 2026-08-10
**Branch:** `docs/overhaul-mkdocs` (off `main`)

## Problem

The docs are an mdbook (`docs/src/**`, 35 pages) that is (a) on a tool we're moving off, (b) stale in places (10 pages still say "central" pre-`hub`-rename; the CRD API page predates the 5-group restructure; the README references the old single group and links `docs/superpowers`), and (c) missing the whole **multi-cluster / fleet** story — hub+pools, the compile→sync→materialize pipeline, workload rescheduling & failover across pools, and how netplane interacts with CSI, CNI, and KubeVirt. Design knowledge currently lives in `docs/superpowers/{specs,plans}`, which we are retiring: going forward the published docs are the durable source of truth.

## Goals

1. Migrate the docs to **mkdocs + mkdocs-material** (from mdbook), wired into the flake devShell; mermaid diagrams via `pymdownx.superfences`.
2. A topic-based information architecture that serves operators, contributors, and architects from one tree, covering **the whole vision *and* how it is built**, with explicit **status badges** (Implemented / Partial / Planned) so readers always know what is real today.
3. New architecture deep-dives: **multi-cluster control plane (hub + broker + pools)**, the **compile→sync→materialize pipeline**, **CNI**, **KubeVirt/VM**, and **CSI/storage** integration, and **workload rescheduling & failover across pools**, with thoughtful mermaid diagrams.
4. A **generated CRD API reference** (`crd-ref-docs`, SolAr pattern) wired into `make generate` so it never drifts, paired with hand-written "how the CRDs interact" pages.
5. **Retire `docs/superpowers`** from git (gitignore + `git rm --cached`; history preserved) so the practice stops; the published docs replace the specs/plans archive.
6. Refresh the top-level **README**.
7. A **code-comment sweep** (final task): remove references to tasks/efforts/sweeps/specs/plans and now-deleted paths so comments describe intent and stay valuable across history.

## Non-goals

- No code/behavior change beyond doc-generation wiring, the flake/Makefile, `.gitignore`, and comment edits.
- Not documenting every CRD field or values key by hand — the per-field CRD reference is generated; chart values are curated by concern.
- No new diagrams tooling beyond mermaid (already the convention).

## Tooling & build

- **flake.nix devShell:** drop `pkgs.mdbook` + `pkgs.mdbook-mermaid`; add `pkgs.mkdocs`, `pkgs.python3Packages.mkdocs-material`, and `crd-ref-docs` (not in nixpkgs → a small `buildGoModule` deriving `github.com/elastic/crd-ref-docs` at a pinned version; `go run github.com/elastic/crd-ref-docs@<ver>` is the documented fallback if the hash is inconvenient).
- **`mkdocs.yml`** at repo root. `docs_dir: docs`. `theme: material` with sensible features (navigation.sections, navigation.top, content.code.copy, search.suggest, palette toggle). `markdown_extensions`: `admonition`, `pymdownx.details`, `pymdownx.superfences` (with the mermaid custom fence), `pymdownx.tabbed`, `toc` with permalinks, `attr_list`, `md_in_html`. `repo_url` → the GitHub repo. Full `nav:` (below). `exclude_docs: |` includes `superpowers/` so the retired specs/plans (still on disk, untracked) never render.
- **Makefile:** `docs` → `mkdocs build --strict` (strict = broken nav/links fail the build — the CI gate); `docs-serve` → `mkdocs serve`; `docs-crd-ref` → the `crd-ref-docs` invocation. Fold `docs-crd-ref` into the `generate` target so the API reference regenerates with the types.
- **Delete:** `docs/book.toml`, `docs/src/SUMMARY.md`, `docs/mermaid.min.js`, `docs/mermaid-init.js`, `docs/dpdk-dev.md` + `docs/dataplane/dpdk-b2b-conntrack-nat64-backlog.md` (fold any durable content into the DPDK/dataplane pages, else drop — they read as scratch backlogs).
- **Content move:** `docs/src/**` → `docs/**` in the new IA layout (git mv where a page ports ~verbatim; new files where rewritten).

## Information architecture (`nav`)

Content root `docs/`. (✚ = new page; others port existing content with a `central`→`hub` / 5-group-API / multi-cluster refresh.)

- **Home** (`index.md`) — what ectobase is, the vision in a paragraph, architecture-at-a-glance diagram, "start here" links per audience.
- **Concepts/**
  - `two-planes-and-the-fleet.md` ✚ — flowplane + netplane, and the hub/pool fleet; the mental model.
  - `overlay.md` — IPv6 underlay, IP-in-IPv6, VNIs (port `architecture/overlay.md`).
  - `intent-to-datapath.md` ✚ — intent (CRDs) → compiled objects → programmed dataplane; the core loop.
  - `workloads.md` ✚ — containers and KubeVirt VMs as first-class workloads.
- **Architecture/**
  - `layout.md` — modules/crates (port + refresh `architecture/layout.md`).
  - `multi-cluster-control-plane.md` ✚ — hub (aggregated apiserver + controller + kine), per-pool broker (kubelet-analog), ClusterPool, the tiered model. Source: the multicluster spec + `hub/` code.
  - `compile-sync-materialize.md` ✚ — the pipeline: compiler (netplane-controller) → `Compiled*` → broker sync → materializers (pod/vm) → Pod/VM. Diagram.
  - `dataplane/` — `programs.md`, `kernel-xdp-tc.md`, `pure-core.md`, `maps.md` (port `dataplane/*`).
  - `route-bus.md` — overlay route distribution (port `controlplane/route-bus.md`, refresh central→hub).
  - `cni-integration.md` ✚ — Multus (thin) + flowplane-cni secondary network; pod ADD → AttachInterface; resolve-from-CompiledNIC. Diagram. (Supersedes `controlplane/cni.md`.)
  - `kubevirt-integration.md` ✚ — VM primary network via tap binding; vm-materializer; CompiledVM.
  - `storage-csi-integration.md` ✚ — Volume → CompiledVolumeAttachment → CDI DataVolume/RBD; ceph-csi; the NetworkFence actuator.
  - `rescheduling-and-failover.md` ✚ **(headline)** — Tier-1 (medik8s NHC + SelfNodeRemediation, pool-local) and Tier-2 (hub detects pool/node loss → CSI NetworkFence → reschedule VM to another pool). Diagram of both tiers + the fence hand-off.
  - `ha-graceful-restart.md` — dataplane pinned-maps adoption + link re-point (port `ops/ha-restart.md` content into architecture).
- **Features/** — `routing-vni.md`, `firewall.md`, `nat.md`, `loadbalancer.md`, `vpc-peering.md`, `ns-edge.md`, `qos.md`, `dhcp-arp-nd.md` (port `features/*`, refresh).
- **Guides/**
  - `getting-started.md` — Nix + make (port `ops/getting-started.md`).
  - `deploy-helm.md` ✚ — install `ectobase-hub` on the fleet cluster + `ectobase-pool` per compute cluster; the values that matter; namespaces/PSA; OCI-release direction.
  - `local-fabric.md` — the clab + kind lab (`test/lab`), `make lab-*` (port `ops/clab-fabric.md`, refresh to the Go lab + two-chart deploy).
  - `runbook.md` — operations & known gotchas (port `ops/runbook.md`, refresh).
  - `development.md` — dev workflows, `make generate`, envtest (port `contributing/dev.md`).
- **Reference/**
  - `api.md` ✚ — **generated by `crd-ref-docs`** (all 5 groups). Not hand-edited.
  - `crd-interactions.md` ✚ — hand-written: how VPC/NIC/FirewallPolicy/LoadBalancer/NATGateway/VPCPeering/VirtualMachine/Container/Volume/ClusterPool and the `Compiled*` objects relate and flow through the pipeline (the connective tissue the generated per-field ref lacks).
  - `helm-values.md` ✚ — curated hub + pool chart values by concern.
  - `components.md` ✚ — the binaries/images (apiserver, controller, broker, agent, reflector, cni, materializers, flowplane) — one paragraph each: what it is, where it runs, what it talks to.
  - `generated-artifacts.md` ✚ — the marker→CRD/RBAC→chart generation pipeline (`make generate`, `//+kubebuilder:rbac`, `crd-ref-docs`).
- **Testing/** — `strategy.md`, `sim.md`, `conformance-map.md` (port `testing/*`).
- **Contributing/**
  - `index.md` ✚ — how to contribute; where things live.
  - `documentation.md` ✚ — how the docs work (mkdocs-material, mermaid, status badges) and **the expectation that docs are updated with every change** (they replace the specs/plans archive). Note the archive lives in git history.

## Status badges

A single convention, used wherever a page describes something not fully shipped. Use mkdocs-material admonitions with fixed labels:

- `!!! success "Status: Implemented"` — shipped + validated.
- `!!! warning "Status: Partial"` — works with caveats / only on some paths (e.g. DPDK on `--no-huge`/sim; multi-cluster failover proven on the lab).
- `!!! note "Status: Planned"` — designed, not built (e.g. blue-green DPDK upgrades on hardware, VfBackend/rte_flow offload).

Each Architecture/Feature page opens with the badge that applies to its subject. A short **Roadmap** section on the Home or Concepts page lists the Planned items in one place.

## Diagrams (mermaid, ~7)

1. **Fleet topology** — hub cluster (apiserver/controller/kine/reflector) + N pool clusters (dataplane/agent/broker/materializers) over the IPv6 fabric.
2. **Compile→sync→materialize** — CRD intent → compiler → `Compiled*` → broker → materializer → Pod/VM.
3. **Rescheduling & failover** — Tier-1 (NHC/SNR local remediation) vs Tier-2 (hub fence via CSI NetworkFence → reschedule to another pool); a sequence or flow diagram.
4. **CNI pod-attach** — sequence: kubelet → Multus → flowplane-cni → DataplaneNode `AttachInterface` → veth + program.
5. **CSI volume + fence** — Volume → CompiledVolumeAttachment → CDI/RBD; and the fence path (blocklist add/remove).
6. **Packet path** — `uplink_rx` (overlay→guest) and `tc_guest_tx` (guest→overlay) with encap/decap + conntrack.
7. **Overlay encap** — IP-in-IPv6 framing (inner-proto 4/41, VNI).

Author diagrams in the pages they explain; keep them focused (a diagram earns its place or is cut).

## The other workstreams

- **Retire `docs/superpowers`:** add `docs/superpowers/` to `.gitignore`; `git rm -r --cached docs/superpowers` (files stay on disk + in history). The `contributing/documentation.md` page notes the archive is in git history and that docs are now the living record.
- **README refresh:** fix `central`→`hub`; correct the CRD API to the 5 groups + `CompiledNIC/VM/Container/VolumeAttachment`; drop the `docs/superpowers/{specs,plans}` links; add a "Documentation" pointer to the mkdocs site/`make docs-serve`; keep it a crisp one-screen overview + the fleet picture. Verify every claim against current code.
- **Code-comment sweep (final task):** grep Go + Rust + charts + scripts for references to `Task N`, `R1/R2/R3`, "the sweep", "Effort", "spec"/"plan", `config/deploy`/`hub/config`/`deploy/charts`, and "for now"/"TODO(temporary)"-style notes that only make sense at authoring time. Rewrite each to describe the code's intent/behavior (or delete if valueless). Preserve genuinely useful `TODO`/`FIXME` with issue-worthy content. Reviewed like any task; no behavior change.

## Risks / verification

- **Drift:** the whole point is durability — the generated API reference (`crd-ref-docs` in `make generate`) and status badges fight staleness; the `contributing/documentation.md` expectation makes updates part of every change.
- **`--strict` build is the gate:** `make docs` with `mkdocs build --strict` fails on broken links/nav/refs. No live fabric needed.
- **crd-ref-docs packaging:** if `buildGoModule` hashing is fiddly, the `go run …@<ver>` fallback keeps the target working.
- **Accuracy:** every ported page gets a central→hub / 5-group / multi-cluster pass; each new deep-dive is written from the code + the (about-to-be-retired) specs, and status-badged. Subagents authoring pages get a source-of-truth briefing and cite files.

## Acceptance

- `make docs` builds clean under `--strict`; `make docs-serve` works; `make generate` regenerates `docs/reference/api.md` with an otherwise-clean diff.
- Nav covers the IA above; every ✚ page exists with its diagram(s); status badges present on vision/partial/planned subjects.
- `docs/superpowers/` untracked (gitignored) with history intact; mkdocs excludes it.
- README accurate against current code; no `docs/superpowers` links.
- Comment sweep: no task/effort/spec/plan/deleted-path references remain in code comments (grep-clean); builds + unit tests still green.
- mdbook fully removed (`book.toml`, `SUMMARY.md`, mermaid JS, flake/Makefile mentions gone).
