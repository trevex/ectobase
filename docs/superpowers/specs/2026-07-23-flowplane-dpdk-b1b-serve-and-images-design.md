# flowplane-dpdk B1b: serve binary + both container images — design

**Date:** 2026-07-23
**Status:** Design (approved in brainstorm; awaiting written-spec review)
**Parent:** `docs/superpowers/specs/2026-07-22-flowplane-dpdk-b1-serve-control-seam-design.md` (B1). This
slice is **B1b** of that spec, PLUS the **image half of B3** pulled forward.
**Predecessor:** B1a (`flowplane-control` crate extraction) is DONE and merged to main @f4f1998.

---

## 1. Goal & scope

Make the DPDK dataplane a runnable, image-able process, delivering exactly:

1. **Binary 2** — a new `flowplane-dpdk serve` bin crate that runs the `flowplane-core` datapath on the
   `nfkit` runtime AND serves the `DataplaneNode` gRPC, programming the DPDK config maps through the
   SHARED `flowplane-control` orchestration (the eBPF binary already does this via `AyaWriter`).
2. **Image 2** — a `Dockerfile.dpdk` + CI matrix entry publishing `ghcr.io/<repo>/flowplane-dpdk`,
   mirroring the existing eBPF `flowplane` image.

Binary 1 (`flowplane serve`, eBPF) and Image 1 (`ghcr.io/<repo>/flowplane`) already exist; this spec
adds their DPDK siblings so the deliverable is **two binaries, two images**.

**In scope:** the map split, the DPDK `MapWriter`, the serve process, the multi-lcore parity test, the
DPDK Dockerfile, and the CI matrix.

**Explicitly deferred (unchanged from B1):**
- **B2** — real host-device attach for DPDK (tap/veth/netns creation, wiring a host device to a DPDK
  port). In this slice `AttachInterface`/`DetachInterface` program the agnostic maps but stub the
  physical-device step (see §5).
- **B3 remainder** — finalized Helm DaemonSet wiring, hugepage/`-l` lcore finalization, AF_XDP-under-
  `--no-huge` live validation on a fabric.
- **Thread C** — blue-green upgrade RPCs.

## 2. Situational facts (verified 2026-07-23)

- The full `nfkit` DPDK datapath (M1–M11: `backend`/`dpdk_maps`/`dpdk_hash`/`eal`/`edt`/`flow`/`mbuf`/
  `mempool`/`port`/`rss`/`runtime`/`snapshot`), `flowplane-core`, and `flowplane-control` are ALL on
  `main`. `design/flowplane-dpdk` has **0** commits not in main. B1b builds on main with no branch merge.
- `dpdk-sys/build.rs` downloads DPDK **25.11.2** and builds it statically with meson/ninja at build
  time (PMDs: `net/null,net/pcap,net/tap,net/af_xdp`), with a `DPDK_PREFIX` escape hatch (nix/CI cache).
  `links = "dpdk"`; exposes `DEP_DPDK_PREFIX` to `nfkit`.
- The eBPF image (`Dockerfile`) is multi-stage Debian: builder installs LLVM-21 + bpf-linker (eBPF-only),
  builds `-p flowplane`; runtime is `debian:bookworm-slim` + iproute2/ethtool, single binary,
  `ENTRYPOINT ["/usr/local/bin/flowplane"]`. CI `docker.yml` publishes one image from `context: .`.
- `flowplane serve` (`flowplane/flowplane/src/main.rs`) is the structural template: clap args → datapath
  bring-up → tonic `DataplaneNode` + `tonic_health` on `127.0.0.1:1337`, listener opened only after the
  datapath is up (the DaemonSet readiness probe is `ss -ltn | grep 127.0.0.1:1337`).

## 3. New crate: `flowplane-dpdk` (bin)

A separate bin crate (per B1 §3) — it cannot share the eBPF crate: one pulls aya + the baked BPF object,
the other pulls `dpdk-sys`/EAL. Registered as a workspace **member but NOT a `default-member`**, matching
`nfkit`/`dpdk-sys` today, so the default `cargo build`/`cargo test` stays fast and DPDK-free; its tests run
explicitly via `cargo test -p flowplane-dpdk` (the same way `nfkit` tests run). It builds on the host
target; DPDK compiles via `dpdk-sys`.

**Deps:** `flowplane-control` (orchestration), `flowplane-core` (datapath), `nfkit` (EAL/maps/runtime/
RSS), `flowplane-common` (POD types), `tonic`/`prost`/`tokio`/`tonic-health`, `clap`, `anyhow`. The gRPC
service definitions are reused from the existing `proto/` (`DataplaneNode`).

### 3.1 Config-map split (B1 §3.3)

`nfkit`'s M8 `DpdkMaps` (all-per-lcore) splits by access pattern:

- **`SharedConfigMaps`** — one instance for the whole process. Each config table is an `rte_hash` created
  with `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` and RCU via `rte_hash_rcu_qsbr_add`. Tables: routes,
  routes6, nat, nat_ips, lb, maglev, fw_rules, fw_meta, underlay, ports, ifaces, neigh_nat, dhcp_config,
  dhcp_meta. Implements **both** the datapath read side of the `Maps` trait AND the write side consumed by
  the DPDK `MapWriter`. Single writer = the tokio control thread (no `MULTI_WRITER_ADD`).
- **`PerLcoreFlowMaps`** — per-lcore, shared-nothing (unchanged M8): conntrack + per-packet meter. Written
  and read only by the owning lcore.
- Each worker lcore's datapath `Maps` view = a small composed type over `&SharedConfigMaps` (RCU-read) +
  its own `PerLcoreFlowMaps`, routing getters to the correct half.

### 3.2 DPDK `MapWriter` (B1 §3.1, sibling of `AyaWriter`)

Implements `flowplane_control::MapWriter` over `SharedConfigMaps` — each `*_upsert`/`*_remove` becomes an
`rte_hash_add_key_data`/`rte_hash_del_key` on the corresponding shared table, published under the RCU
writer discipline. `MapWriter::conntrack_flush(scope)` does NOT reach into per-lcore conntrack; it bumps a
process-global `AtomicU64 config_generation` (Release) as part of the same publish (B1 §5a). The
`ControlCore<DpdkMapWriter>` this drives is the exact same orchestration the eBPF side runs — preserving
DPDK == sim == eBPF through the control path.

### 3.3 Conntrack invalidation (B1 §5a — generation tag)

Per-lcore conntrack entries are stamped at creation with the `config_generation` they were resolved under
plus their dependency key. On each per-lcore lookup, before applying a cached decision, if
`entry.gen != config_generation` the lcore re-validates the cached binding against `SharedConfigMaps`:
still valid → refresh gen (local write, fast path); binding gone/changed → drop/re-resolve. Zero stale
emission on NAT-source withdrawal, no cross-lcore writes, one-packet-bounded lingering. (This datapath-
side stamping/recheck lives in `flowplane-core`; B1b wires the writer's generation bump + the lcore
recheck hook.)

### 3.4 `serve` process (B1 §3.4)

Mirrors `flowplane serve` structurally:
1. Parse args (uplink, gateway, gateway-mac, lcores, backend `AfXdp|Nic`, `--no-huge`) — the surface the
   Helm DPDK DaemonSet passes.
2. EAL init (`nfkit::eal`), port/queue setup, symmetric-Toeplitz RSS.
3. Build `SharedConfigMaps` (LF+RCU) + one `PerLcoreFlowMaps` per worker lcore.
4. `LcoreRuntime::for_each_worker(...)` launches busy-poll datapath workers; each registers a QSBR reader
   and reports quiescence once per poll-loop iteration, running the `flowplane-core` datapath over its
   composed `Maps` view.
5. On the main thread, a tokio runtime hosts the tonic `DataplaneNode` + `tonic_health` on
   `127.0.0.1:1337`, opened only after the datapath is up. Handlers build a `DpdkMapWriter` over
   `SharedConfigMaps` and call `flowplane-control`.
6. Graceful shutdown (SIGTERM/SIGINT): stop accepting, quiesce workers, exit.

Readiness contract identical to eBPF: the gRPC listener opening == "ready to AttachInterface".

## 4. Container image: `Dockerfile.dpdk` + CI

Multi-stage Debian, mirroring `Dockerfile` in shape, different toolchain (no LLVM-21/bpf-linker):

- **Builder:** `debian:bookworm` + Rust (the repo's pinned toolchain) + DPDK build deps that
  `dpdk-sys/build.rs` requires: `meson`, `ninja-build`, `python3-pyelftools`, `libnuma-dev`,
  `clang`/`libclang` (bindgen), `pkg-config`, `build-essential`, plus `libbpf-dev`/`libxdp-dev` (net/af_xdp
  PMD) and `protobuf-compiler` (tonic-build). `cargo build --release -p flowplane-dpdk` — `dpdk-sys`
  downloads & statically builds DPDK 25.11.2 inline. Optional `DPDK_PREFIX` build-arg to reuse a cached
  DPDK prefix and skip the multi-minute DPDK compile.
- **Runtime:** `debian:bookworm-slim` + runtime shared libs (`libnuma1`, `libbpf`/`libxdp`, `libpcap`) +
  `iproute2`/`ethtool`; DPDK core is statically linked into the binary; hugepage-ready (the DaemonSet
  mounts hugepages; `--no-huge` for clab/CI). `COPY --from=builder /flowplane-dpdk /usr/local/bin/` ;
  `ENTRYPOINT ["/usr/local/bin/flowplane-dpdk"]`.
- **CI:** extend `.github/workflows/docker.yml` to a **matrix** over
  `{ image: flowplane, dockerfile: Dockerfile }` and `{ image: flowplane-dpdk, dockerfile: Dockerfile.dpdk }`,
  each pushed to `ghcr.io/<repo>/<image>` with the existing tag derivation. The eBPF job is unchanged in
  behavior; the DPDK job is additive.

Design decision: **build DPDK from source in-image via `dpdk-sys`** (not a third-party DPDK base image),
because `dpdk-sys` pins & checksums 25.11.2 with a specific PMD set and the shim compiles against exactly
that build — a base image with a different DPDK version/PMD set would diverge from what the binary links.

## 5. B2-stub boundary

`AttachInterface`/`DetachInterface` in `flowplane-dpdk`:
- **Agnostic half — implemented:** program ports/ifaces/underlay maps via `flowplane-control` (same calls
  the eBPF handlers make), so the config path is fully exercised and parity-tested.
- **Device half — stubbed:** the physical host-device step (create/wire the tap/veth to a DPDK port)
  returns `Unimplemented` with a clear log line. Consequence: the binary boots, the image runs, gRPC
  serves, the datapath processes packets on the configured uplink/queues, and every agnostic RPC works —
  but the DPDK node does not yet stand up NEW guest host interfaces. This is the honest, testable B1b+image
  milestone; B2 fills the device half.

## 6. Testing

- **B1b vertical slice** (extends the existing `multilcore_datapath` + parity harnesses, `--no-huge`):
  (a) start `SharedConfigMaps` + N `PerLcoreFlowMaps`; (b) program routes/nat/lb/fw through the DPDK
  `MapWriter` — the exact calls the gRPC handlers make; (c) run the `flowplane-core` datapath on N lcores
  over a fixture; (d) assert byte-parity with sim AND conntrack isolation across lcores. This extends the
  DPDK == sim == eBPF chain through the control path.
- **§5b concurrency anchor:** a non-EAL (tokio) writer doing `rte_hash_add/del` on an LF+RCU table
  concurrently with an lcore QSBR reader reporting quiescence. Validates that the external-writer model is
  safe. **Fallback if it isn't:** the tokio handler enqueues ops on an rte_ring drained by a control-owned
  lcore (dpservice's pattern) while keeping LF+RCU for multi-reader safety. The plan runs this anchor
  BEFORE committing to the direct-writer path.
- **§5a generation-tag test:** program a NAT binding, resolve a conntrack entry, withdraw the binding (bump
  generation), assert the next datapath packet re-validates and does not emit under the withdrawn binding.
- **Image smoke:** `docker run flowplane-dpdk --help` and boot-to-listener under `--no-huge` as far as CI
  (no hugepages) allows; assert the gRPC/health port opens.

## 7. Risks & mitigations

- **Non-EAL tokio writer on LF+RCU (§5b):** primary risk; mitigated by the anchor-first ordering and the
  rte_ring fallback.
- **af_xdp PMD runtime deps in a slim image:** the net/af_xdp PMD needs libbpf/libxdp at runtime; the
  runtime stage installs them explicitly. If the static DPDK build pulls additional transitive shared libs
  (libelf, libbsd), the plan resolves them by `ldd`-ing the built binary and installing the closure.
- **DPDK build time in CI:** the from-source DPDK build adds minutes; mitigated by the `DPDK_PREFIX`
  build-arg cache (and CI layer caching). Acceptable for an additive job.

## 8. Non-goals

Real host-device attach (**B2**); Helm DaemonSet finalization + hugepage/`-l` finalization + live AF_XDP-on-
fabric validation (**B3 remainder**); blue-green upgrade RPCs (**thread C**). This slice is the deployable-
process + image foundation those build on.
