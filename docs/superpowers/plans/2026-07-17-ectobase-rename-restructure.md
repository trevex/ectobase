# ectobase Rename & Restructure — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebrand the repo to **ectobase**; rename the dataplane `xdp-dp*` → **`flowplane*`** and
regroup its 5 crates under `flowplane/`; move the Go module root to
`github.com/trevex/ectobase`; keep `netplane`. Behavior byte-for-byte unchanged.

**Architecture:** A mechanical, token-anchored rename executed in 4 phases that each end green
(build/test gate + commit). Directory moves via `git mv` (history-preserving). Identifier
replacement is an **ordered, longest-token-first** sed sweep restricted to each phase's file set,
anchored to exact tokens so bare `xdp`/`XDP` (`XDP_PASS`, `bpf_xdp_adjust`, `xdp_action`) and the
external `dpservice`/`dpdkironcore` identifiers are never touched.

**Tech Stack:** Rust (aya eBPF workspace), Go (controller-runtime + protobuf), Docker, Nix, k8s
manifests.

**Reference spec:** `docs/superpowers/specs/2026-07-17-ectobase-rename-restructure-design.md`

**Branch:** `rename/ectobase-flowplane` (already created).

---

## The ordered token map (SHARED across phases — apply longest-first)

Every phase applies the subset of these that its files contain, **in this exact order**. Each is
an exact-token replacement; do NOT add rules for bare `xdp`/`XDP`/`dpservice`.

```
# Rust crate import identifiers (underscored) — longest first
xdp_dp_common   -> flowplane_common
xdp_dp_core     -> flowplane_core
xdp_dp_ebpf     -> flowplane_ebpf
xdp_dp_sim      -> flowplane_sim
xdp_dp          -> flowplane        # (word-bounded \bxdp_dp\b) the binary lib name

# kebab crate/dir/artifact names — longest first
xdp-dp-common   -> flowplane-common
xdp-dp-core     -> flowplane-core
xdp-dp-ebpf     -> flowplane-ebpf
xdp-dp-sim      -> flowplane-sim
xdp-dp-prog     -> flowplane-prog
xdp-dp-eph-     -> flowplane-eph-
xdp-dp          -> flowplane        # binary, dir, ds/xdp-dp, /sys/fs/bpf/xdp-dp, config base

# env vars
XDP_DP_         -> FLOWPLANE_

# Go module root
trevex/xdp-dp   -> trevex/ectobase

# dataplane image (handled explicitly in Phase 3; token has NO xdp-dp substring)
dpservice-xdp   -> ectobase/flowplane
```

**MUST NOT touch:** bare `xdp`/`XDP` tokens (`XDP_PASS`, `bpf_xdp_*`, `xdp_action`, "XDP" prose),
`dpservice` / `dpservice-cli` (external), `dpdkironcore` / `DPDKironcore` (legacy proto),
`ectobase-system` (already correct), `routebus.v1` / `dataplane.v1` (proto package names).

**Reusable sed helper** (used verbatim in each phase; operates on a file list on stdin):

```bash
# apply_rename <<files...>>  — reads NUL-separated paths on stdin, applies the ordered map
apply_rename() {
  xargs -0 -r sed -i \
    -e 's/xdp_dp_common/flowplane_common/g' \
    -e 's/xdp_dp_core/flowplane_core/g' \
    -e 's/xdp_dp_ebpf/flowplane_ebpf/g' \
    -e 's/xdp_dp_sim/flowplane_sim/g' \
    -e 's/\bxdp_dp\b/flowplane/g' \
    -e 's/xdp-dp-common/flowplane-common/g' \
    -e 's/xdp-dp-core/flowplane-core/g' \
    -e 's/xdp-dp-ebpf/flowplane-ebpf/g' \
    -e 's/xdp-dp-sim/flowplane-sim/g' \
    -e 's/xdp-dp-prog/flowplane-prog/g' \
    -e 's/xdp-dp-eph-/flowplane-eph-/g' \
    -e 's/xdp-dp/flowplane/g' \
    -e 's/XDP_DP_/FLOWPLANE_/g' \
    -e 's#trevex/xdp-dp#trevex/ectobase#g'
}
```
(The `dpservice-xdp` → `ectobase/flowplane` rule is applied separately in Phase 3 where it occurs.)

---

## Phase 1 — Rust dataplane: regroup + rename

**Files:** the 5 crate dirs (moved under `flowplane/`), root `Cargo.toml`, all `*.rs`, all crate
`Cargo.toml`, `build.rs`.

- [ ] **Step 1: Move the crate dirs under `flowplane/` (history-preserving).**

```bash
mkdir flowplane
git mv xdp-dp        flowplane/flowplane
git mv xdp-dp-common flowplane/flowplane-common
git mv xdp-dp-core   flowplane/flowplane-core
git mv xdp-dp-ebpf   flowplane/flowplane-ebpf
git mv xdp-dp-sim    flowplane/flowplane-sim
```

- [ ] **Step 2: Rename identifiers across all Rust + Cargo files.** Apply the shared sed to every
  `*.rs`, `build.rs`, and `Cargo.toml` in the workspace (root + the moved crates). Use the
  `apply_rename` helper defined above:

```bash
# from repo root, with apply_rename defined in the shell
{ find flowplane -type f \( -name '*.rs' -o -name 'Cargo.toml' \) -print0; \
  printf '%s\0' Cargo.toml; } | apply_rename
```

- [ ] **Step 3: Verify the root workspace manifest.** Open `Cargo.toml` and confirm the sweep
  produced the correct member paths; they must now be:

```toml
members = ["flowplane/flowplane-common", "flowplane/flowplane-core", "flowplane/flowplane-ebpf", "flowplane/flowplane", "flowplane/flowplane-sim"]
default-members = ["flowplane/flowplane-common", "flowplane/flowplane-core", "flowplane/flowplane", "flowplane/flowplane-sim"]

[profile.release.package.flowplane-ebpf]
```

  The sed renames the crate *names* but NOT the directory prefix in the member paths — the paths
  were `xdp-dp-common` etc. (no directory prefix before), so after sed they are
  `flowplane-common` (still no prefix). **You must hand-edit the member paths to add the
  `flowplane/` prefix** as shown above (the `git mv` put them in the subdir but the manifest still
  lists bare names). Verify `[profile.release.package.flowplane-ebpf]` got renamed by the sweep.

- [ ] **Step 4: Verify `build.rs` inter-crate paths.** In `flowplane/flowplane/build.rs`, the
  rerun-if-changed paths must now read `../flowplane-ebpf/src` and `../flowplane-ebpf/Cargo.toml`
  (siblings within `flowplane/`, same depth as before). Confirm the sweep produced these; fix if
  the depth is wrong.

- [ ] **Step 5: Build the eBPF object + host crate.** Run:
  `nix develop --command cargo build -p flowplane`
  Expected: clean build. A mangled bare-`xdp`/`XDP` token (e.g. `xdp_action`) would fail here —
  if it does, grep the error, fix the over-replacement, rebuild. Confirm `XDP_PASS`,
  `bpf_xdp_adjust_head`, `xdp_action` are still intact: `grep -rn "XDP_PASS\|xdp_action" flowplane/flowplane-ebpf/src | head`.

- [ ] **Step 6: Run the datapath tests + verifier anchors.** Run:
  `nix develop --command cargo test -p flowplane-core -p flowplane-sim` (expect all pass), then the
  tc verifier anchor under sudo:
  `nix develop --command bash -c 'cargo test -p flowplane --test verify_tc_guest --no-run; TB=$(ls -t target/debug/deps/verify_tc_guest-* | grep -v "\.d$" | head -1); /run/wrappers/bin/sudo -E "$TB" --ignored'`
  Expected: `tc_guest_classifiers_load ... ok`.

- [ ] **Step 7: Format + commit + verify HEAD.**

```bash
nix develop --command cargo fmt
git add -A
git commit -m "refactor(rename): xdp-dp* -> flowplane*, regroup crates under flowplane/"
git log --oneline -1   # MUST show this commit (pre-commit hook runs clippy+rustfmt; if HEAD
                       # didn't advance, read the hook output, fix, re-commit)
```

---

## Phase 2 — Go module root → github.com/trevex/ectobase

**Files:** all `*.go`, all `go.mod` (`api`, `cni`, `netplane`, `test/e2e`), `go.work`, all
`*.proto` (`go_package` option), regenerated `gen/` code.

- [ ] **Step 1: Rename the module path everywhere.** Apply the `trevex/xdp-dp` rule to Go + proto
  files:

```bash
{ find api cni netplane test/e2e -type f \( -name '*.go' -o -name 'go.mod' \); \
  find api -name '*.proto'; printf '%s\n' go.work; } \
  | tr '\n' '\0' | xargs -0 -r sed -i -e 's#trevex/xdp-dp#trevex/ectobase#g'
```

  This covers module declarations, `replace` directives, every import, and proto `go_package`.
  It does NOT touch `dpdkironcore` (its `go_package` is `./dpdkproto`, no trevex path) or the
  proto package names `routebus.v1`/`dataplane.v1`.

- [ ] **Step 2: Regenerate protobuf code.** Run the repo's proto-gen target (from the Makefile —
  it invokes `protoc` with the `go_package` module paths). Run:
  `nix develop --command make proto` (or the exact target name in the Makefile — grep `proto:` in
  `Makefile` first). Expected: `gen/` code regenerates with the new import paths.

- [ ] **Step 3: Tidy + build + test each module.** Run:

```bash
nix develop --command bash -c '
  for m in api cni netplane test/e2e; do (cd $m && go mod tidy); done
  cd netplane && go build ./... && go test ./...
  cd ../api && go build ./... 2>/dev/null || true
  cd ../cni && go build ./... 2>/dev/null || true
'
```
  Expected: `netplane` builds + all tests pass; `api`/`cni` build. Fix any import the sweep missed
  (grep `trevex/xdp-dp` should return nothing in `*.go`/`go.mod`).

- [ ] **Step 4: Format + commit + verify HEAD.**

```bash
nix develop --command bash -c 'cd netplane && gofmt -w $(git -C .. diff --name-only -- "*.go")' 2>/dev/null || true
git add -A
git commit -m "refactor(rename): Go module root github.com/trevex/xdp-dp -> ectobase"
git log --oneline -1
```

---

## Phase 3 — Build/deploy plumbing + scripts

**Files:** `Dockerfile`, `Dockerfile.netplane`, `Makefile`, `flake.nix`,
`.github/workflows/docker.yml`, `config/deploy/*` (incl. `xdp-dp.yaml` → `flowplane.yaml`),
`hack/**`, `test/**` (shell/yaml/py/go scripts).

- [ ] **Step 1: Rename the DaemonSet manifest file.**
  `git mv config/deploy/xdp-dp.yaml config/deploy/flowplane.yaml`

- [ ] **Step 2: Apply the shared rename to build/deploy/script files.**

```bash
{ printf '%s\n' Dockerfile Dockerfile.netplane Makefile flake.nix .github/workflows/docker.yml; \
  find config hack test -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.sh' -o -name '*.py' -o -name '*.go' -o -name '*.conf' -o -name '*.boot' -o -name '*.gen' -o -name 'kustomization*' \); } \
  | tr '\n' '\0' | apply_rename
```

- [ ] **Step 3: Fix the image names explicitly** (the `dpservice-xdp` token + the flat
  `trevex/netplane` image path). Edit these occurrences:
  - `Makefile`: `IMAGE ?= ghcr.io/trevex/dpservice-xdp` → `ghcr.io/trevex/ectobase/flowplane`;
    `NETPLANE_IMAGE ?= ghcr.io/trevex/netplane` → `ghcr.io/trevex/ectobase/netplane`;
    `KINDNODE_IMAGE ?= kindest/node-fabric` → `ghcr.io/trevex/ectobase/kind-node-fabric`; and the
    `-p xdp-dp*` build/test flags → `-p flowplane*` (the shared sed already did the `xdp-dp`→
    `flowplane` part; verify targets like `cargo build -p flowplane` and the sudo anchor lines).
  - `.github/workflows/docker.yml`: `images: ghcr.io/${{ github.repository }}` →
    `images: ghcr.io/${{ github.repository }}/flowplane` (so the dataplane image publishes under
    the ectobase repo path). Update the workflow comment/name mentioning `xdp-dp`.
  - `Dockerfile`: confirm the sweep produced `-p flowplane`, `target/release/flowplane`,
    `/flowplane`; fix any residual.
  - `config/deploy/flowplane.yaml`: confirm kind `name: flowplane`, `ds/flowplane`, the image is
    `ghcr.io/trevex/ectobase/flowplane`, the `hostPath` pin dir is `/sys/fs/bpf/flowplane`, and the
    env var names are `FLOWPLANE_*`. Do the same image/name check in the other `config/deploy/*`
    that reference the DS or image.

- [ ] **Step 4: Guard against external-string damage.** Confirm the external identifiers are
  intact (the sweep must NOT have altered them):
  `grep -rn "dpservice-cli\|dpdkironcore\|ironcore-dev/dpservice\|ectobase-system" flake.nix Makefile test/conformance | head`
  Expected: all present and unchanged (only OUR `dpservice-xdp` image string changed, in Step 3).

- [ ] **Step 5: Build gate.** Run: `nix develop --command make build` (host crates + eBPF object).
  Expected: success. If the Makefile has a lint/vet aggregate target, run it. Dockerfile is not
  built here (heavy), but verify its package/binary tokens by inspection.

- [ ] **Step 6: Commit + verify HEAD.**

```bash
git add -A
git commit -m "refactor(rename): images/manifests/scripts -> ectobase/flowplane"
git log --oneline -1
```

---

## Phase 4 — Docs + final sweep

**Files:** `README.md`, `hack/clab/README.md`, `docs/**`, plus a final workspace grep.

- [ ] **Step 1: Apply the shared rename + the image token to all Markdown.**

```bash
find . -name '*.md' -not -path './target/*' -not -path './.git/*' -print0 | apply_rename
find . -name '*.md' -not -path './target/*' -not -path './.git/*' -print0 \
  | xargs -0 -r sed -i -e 's#dpservice-xdp#ectobase/flowplane#g'
```
  (Historical spec docs under `docs/superpowers/specs/` describe the same system by its new name —
  a mechanical identifier pass is fine and keeps the final grep clean. Do NOT rewrite their prose.)

- [ ] **Step 2: Rewrite the two primary READMEs' framing.** `README.md` and `hack/clab/README.md`
  should lead with the ectobase umbrella and the flowplane/netplane component split (not just
  token-swapped). Read each and adjust the opening/architecture paragraphs so the project identity
  reads correctly (ectobase = multi-cluster IaaS layer; flowplane = dataplane; netplane = control
  plane). Keep all technical content accurate.

- [ ] **Step 3: Final sweep — must be clean except intentional survivors.** Run:

```bash
grep -rniE 'xdp-dp|xdp_dp|XDP_DP_|dpservice-xdp|trevex/xdp-dp' \
  --exclude-dir=target --exclude-dir=.git --exclude=Cargo.lock . \
  | grep -viE 'dpdkironcore|dpservice-cli|ironcore-dev/dpservice'
```
  Expected: **no output** (every remaining match, if any, must be an intentional survivor already
  filtered). Investigate and fix anything that prints. Also sanity-check bare-token integrity:
  `grep -rn "XDP_PASS\|bpf_xdp\|xdp_action" flowplane/flowplane-ebpf/src | head` (must still be
  present) and `grep -rn "dpdkironcore" api/proto` (legacy proto intact).

- [ ] **Step 4: Full workspace verification.** Run the whole gate once more on the renamed tree:
  `nix develop --command cargo build -p flowplane && nix develop --command cargo test -p flowplane-core -p flowplane-sim`
  and `nix develop --command bash -c 'cd netplane && go build ./... && go test ./...'`.
  Expected: all green.

- [ ] **Step 5: Commit + verify HEAD.**

```bash
git add -A
git commit -m "docs(rename): ectobase/flowplane across docs; final sweep clean"
git log --oneline -1
```

---

## Final

- [ ] Dispatch a final review over the whole branch (`git diff main...HEAD --stat` + spot-check the
  ordered-token integrity and that no external/wire-stable identifier changed), then use
  `superpowers:finishing-a-development-branch` to complete (verify tests → present options).
- [ ] Out-of-repo: update the memory pointers (`MEMORY.md` + affected notes) that reference
  `xdp-dp`/`netplane` paths — separate from the repo diff.

## Self-review notes

- **Spec coverage:** name map (all phases), layout regroup (P1), runtime identifiers — pin dir +
  env + ebpf object (P1), DS + go_package (P2/P3), images (P3) — all mapped. Leave-unchanged set
  guarded explicitly (P3 Step 4, P4 Step 3).
- **Ordering safety:** `apply_rename` lists longest tokens first; bare `\bxdp_dp\b` is
  word-bounded; no rule touches bare `xdp`/`XDP`/`dpservice`. The `cargo build` gate in P1/P4
  catches any over-replacement of `xdp_action`/`bpf_xdp_*`.
- **Green-at-each-phase:** P1 gates on cargo build+test+anchor; P2 on go build+test; P3 on make
  build; P4 re-runs the full gate. Env-var mismatch between Rust (P1) and manifests (P3) is
  runtime-only and not exercised by any per-phase gate, so intermediate phases stay green.
- **Type/name consistency:** crate names (`flowplane-core` etc.), import ids (`flowplane_core`),
  binary (`flowplane`), pin dir (`/sys/fs/bpf/flowplane`), env prefix (`FLOWPLANE_`), image
  (`ghcr.io/trevex/ectobase/flowplane`) used identically across all phases.
