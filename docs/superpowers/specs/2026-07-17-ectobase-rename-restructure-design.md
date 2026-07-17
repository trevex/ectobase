# ectobase Rename & Restructure — Design

**Status:** Approved (design); pending spec review
**Date:** 2026-07-17

## Summary

Rebrand the repository to **ectobase** — an umbrella name for a multi-cluster IaaS layer — and
restructure so the repo root reads as a list of ectobase components, leaving room for future
components (KubeVirt multi-cluster, storage) as siblings. Two renames + one regroup:

- **Umbrella:** repo → `ectobase`, Go module root → `github.com/trevex/ectobase`.
- **Dataplane:** `xdp-dp*` (the eBPF/XDP+tc forwarding engine) → **`flowplane*`**, and its 5 crates
  move under a single `flowplane/` component directory.
- **Control plane:** `netplane` — **unchanged** (name kept; only its Go module path changes to the
  ectobase root).

The naming forms a control/data-plane family: **netplane** orchestrates the network, **flowplane**
forwards the flows. This is a mechanical rename touching ~200 files; the risk is not logic but
completeness and the handful of *runtime* identifiers that cross process/wire/disk boundaries.

## Naming map

| Old | New |
|---|---|
| repo / umbrella | `ectobase` |
| Go module root `github.com/trevex/xdp-dp` | `github.com/trevex/ectobase` |
| Rust crates `xdp-dp`, `xdp-dp-core`, `xdp-dp-ebpf`, `xdp-dp-sim`, `xdp-dp-common` | `flowplane`, `flowplane-core`, `flowplane-ebpf`, `flowplane-sim`, `flowplane-common` |
| binary `xdp-dp serve` | `flowplane serve` |
| crate import paths `xdp_dp_core`, `xdp_dp_common`, … | `flowplane_core`, `flowplane_common`, … |
| `netplane` (crate/dir/name) | `netplane` (unchanged) |
| Go modules `github.com/trevex/xdp-dp/{api,cni,netplane,test/e2e}` | `github.com/trevex/ectobase/{api,cni,netplane,test/e2e}` |
| dataplane image `ghcr.io/trevex/dpservice-xdp` | `ghcr.io/trevex/ectobase/flowplane` |
| control-plane image `ghcr.io/trevex/netplane` | `ghcr.io/trevex/ectobase/netplane` |
| kind-node image `kindest/node-fabric` | `ghcr.io/trevex/ectobase/kind-node-fabric` |
| k8s namespace `ectobase-system` | unchanged (already migrated) |

## Target layout (group-by-component)

```
ectobase/
├─ flowplane/            # dataplane (eBPF/XDP+tc) — one root-workspace member group
│  ├─ flowplane/          # host agent + `flowplane serve` binary (was xdp-dp/)
│  ├─ flowplane-core/     # pure-core datapath (was xdp-dp-core/)
│  ├─ flowplane-ebpf/     # eBPF programs (was xdp-dp-ebpf/)
│  ├─ flowplane-sim/      # in-process datapath sim (was xdp-dp-sim/)
│  └─ flowplane-common/   # shared types (was xdp-dp-common/)
├─ netplane/             # control plane / CNI (unchanged dir)
├─ api/                  # shared CRD/proto API (unchanged dir)
├─ cni/                  # CNI shim (unchanged dir)
├─ config/  docs/  hack/  test/
└─ (future) kubevirt/  storage/
```

Only the **Rust dataplane crates move** (into `flowplane/`). They stay siblings *within* that
directory, so their inter-crate relative paths (e.g. `flowplane/flowplane/build.rs` →
`../flowplane-ebpf/src`) keep the same depth. Go module directories do not move; only their module
paths change. A **single root Cargo workspace** still covers all five crates via `flowplane/*`
member paths.

## Runtime identifiers — handle deliberately (NOT cosmetic)

These cross a process/wire/disk boundary; each must change **in lockstep with every consumer**:

1. **bpffs pin dir** `/sys/fs/bpf/xdp-dp` → `/sys/fs/bpf/flowplane`
   (`flowplane/flowplane/src/main.rs` serve default; `loader.rs` ephemeral `xdp-dp-eph-<pid>` →
   `flowplane-eph-<pid>`). The DaemonSet `hostPath` mount + the restart/HA scripts move together.
2. **env vars** `XDP_DP_*` → `FLOWPLANE_*` (11: `PIN_LINKS`, `SKB_MODE`, `DEBUG`, `GUEST_TC`,
   `CONNTRACK_MAX`, `INTERFACES_MAX`, `LB_MAX`, `MAGLEV_MAX`, `NAT_MAX`, `PORT_META_MAX`,
   `ROUTES_MAX`) — renamed in Rust `env` clap attrs AND every manifest/script that sets them.
3. **embedded eBPF object** `$OUT_DIR/xdp-dp-prog` → `flowplane-prog` (`build.rs` emitter +
   every `include_bytes_aligned!` site: `loader.rs`, the verify/anchor tests).
4. **DaemonSet** `ds/xdp-dp` + `config/deploy/xdp-dp.yaml` → `ds/flowplane` +
   `config/deploy/flowplane.yaml`.
5. **proto `go_package`** options → `github.com/trevex/ectobase/…`; protos regenerated.

## Explicitly left UNCHANGED (do not rename)

- **proto package names** `routebus.v1`, `dataplane.v1` — not xdp-dp-named; wire-stable.
- **legacy dpservice/dpdk conformance proto** `dpdkironcore.v1` / `DPDKironcore` service
  (`api/proto/dataplane/v1/dpdk.proto`) — external-compat surface for the dpservice conformance
  suite; renaming would break conformance.
- **external `dpservice` / `dpservice-cli`** flake input + package (ironcore-dev upstream, the real
  gRPC client used for conformance) — third-party, unrelated to our rename.
- **`ectobase-system`** k8s namespace — already correct.

## Touch-point inventory (by category, for the plan)

- **Rust source (~bulk):** every `use xdp_dp_core::…` / `xdp_dp_common::…` / `xdp_dp_sim` import
  across `flowplane-ebpf`, `flowplane-core`, `flowplane-sim`, `flowplane`; crate `name`/`edition`
  in 5 `Cargo.toml`; root `Cargo.toml` `members`/`default-members`/`[profile.release.package.*]`;
  `build.rs` relative paths + object name; doc comments.
- **Go source:** module paths in 4 `go.mod` (`api`, `cni`, `netplane`, `test/e2e`), `replace`
  directives, `go.work`, every import of `github.com/trevex/xdp-dp/…`, proto `go_package` +
  regenerated `gen/` code.
- **Build/deploy:** `Dockerfile` (`-p flowplane`, `target/release/flowplane`, `/flowplane`,
  comments), `Dockerfile.netplane` (image name only; COPY dirs unchanged), `Makefile`
  (`IMAGE`/`NETPLANE_IMAGE`/`KINDNODE_IMAGE` vars, targets, `-p flowplane*` flags, help text),
  `flake.nix` (the `xdp-dp-ebpf` reference in the clippy-hook comment + any devShell/pkg name;
  leave `dpservice*`), `.github/workflows/docker.yml` (image path →
  `ghcr.io/${{ github.repository }}/flowplane`).
- **Config/manifests:** `config/deploy/xdp-dp.yaml` → `flowplane.yaml` (kind name, `ds/flowplane`,
  hostPath pin dir, env vars, image); other `config/deploy/*.yaml` referencing the DS/image/pin.
- **Scripts:** `hack/**`, `test/**` (`ds/xdp-dp`, `/sys/fs/bpf/xdp-dp`, `XDP_DP_*`,
  `target/debug/xdp-dp`, `config/deploy/xdp-dp.yaml`).
- **Docs:** `README.md`, `hack/clab/README.md`, `docs/**`, any `CLAUDE.md`.

## Execution & testing strategy

Phased so each phase ends green; a break stays localized. Directory renames via `git mv`
(history-preserving). Identifier find/replace uses a careful allowlist that **excludes** the
leave-unchanged set above (`dpservice`, `dpdkironcore`, `ectobase-system`).

1. **Rust rename + regroup.** `git mv` the 5 crate dirs under `flowplane/`; rename crates, imports,
   workspace members, profile override, `build.rs` paths, `flowplane-prog`, `FLOWPLANE_*` env,
   `/sys/fs/bpf/flowplane`. **Gate:** `cargo build -p flowplane`, `cargo test -p flowplane-core
   -p flowplane-sim`, and the tc/uplink verifier anchors under sudo (`cargo fmt` first — pre-commit
   hook runs clippy+rustfmt and rejects unformatted commits).
2. **Go module root.** `github.com/trevex/xdp-dp` → `github.com/trevex/ectobase` across all 4
   modules + `go.work` + `replace` + proto `go_package`; regenerate protos. **Gate:**
   `go build ./...` + `go test ./...` in each module.
3. **Build/deploy plumbing.** Dockerfiles, Makefile, flake, CI workflow, `config/deploy/*`
   (incl. `xdp-dp.yaml`→`flowplane.yaml`), `hack/`, `test/`. **Gate:** `make build`; Dockerfile
   package/path sanity; a clab smoke if feasible.
4. **Docs.** README(s), `docs/`, `CLAUDE.md`. **Gate:** workspace-wide grep.

**Final sweep:** `grep -riE 'xdp-dp|xdp_dp|XDP_DP|dpservice-xdp|trevex/xdp-dp'` (excluding
`target/`, `.git/`, `Cargo.lock`) must return only the intentional survivors (the `dpdkironcore`
legacy proto, dpservice-conformance references, the external `dpservice-cli`). Out-of-repo memory
pointers are updated separately (not part of the repo diff).

**Execution model:** subagent-driven, one task per phase (build/test gate + commit each), on a
branch `rename/ectobase-flowplane`. `cargo fmt`/`gofmt` + `git log` HEAD-verification baked into
each task (the pre-commit hook silently rejects otherwise).

## Known caveat (ops, not correctness)

The pin-dir change (`/sys/fs/bpf/xdp-dp` → `/sys/fs/bpf/flowplane`) means the **first** post-rename
DaemonSet rollout cannot adopt the *old* pins (old pods pinned under the old path; new pods look
under the new one) — a one-time forwarding blip on that single rollout, then normal graceful
restart resumes. Acceptable for a lab/greenfield project; no code change needed, just awareness in
the rollout.

## Non-goals

- No functional/behavioral change to any datapath or control-plane path. Byte-for-byte identical
  behavior; only names/paths change.
- No new components (KubeVirt, storage) — the layout only *reserves room* for them.
- No rename of the control plane (`netplane` kept) or the wire-stable/external identifiers listed
  under "left unchanged".
