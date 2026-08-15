# Dev environment & workflows

Everything a contributor needs is provided by the Nix flake — one pinned toolchain,
one command to enter.

```sh
nix develop     # enter the dev shell (all targets assume you are inside it)
make            # list all make targets
```

The dev shell (`flake.nix`) provides the pinned Rust toolchain (via `rustup`, from
`rust-toolchain.toml`), Go, `bpf-linker`, `protobuf`, `bpftool`, `qemu`, `iproute2`,
`kind`/`containerlab`/`helm`, `python3` (DPDK build's pyelftools), `mkdocs`+`mkdocs-material`,
`controller-gen` + `crd-ref-docs` (the CRD/RBAC/reference codegen). It also exports
`KUBEBUILDER_ASSETS`, a real in-process apiserver (kube-apiserver + etcd + kubectl) so
controller-runtime **envtest** integration tests can spin a real apiserver under `go test`.

## The everyday loop

| Command | Runs | Root? |
|---|---|---|
| `make build` | Build `flowplane` (host crates + the eBPF object via aya-build). | no |
| `make test` | Host unit + `#[repr(C)]` POD-layout tests. | no |
| `make sim` | Fast in-process datapath tests (pure-core + native sim). | no |
| `make lint` / `make fmt` | Clippy across all targets / format all Rust. | no |
| `make check` | `fmt --check` + clippy — exactly what the pre-commit hooks run. | no |
| `make sim-anchor` | `BPF_PROG_TEST_RUN` byte-parity anchor (native core vs bytecode). | sudo |
| `make verifier` | Load the programs through the kernel verifier. | sudo |
| `make e2e` | 3-node netns overlay end-to-end. | sudo |
| `make ha` | HA pinned-maps kill+adopt smoke. | sudo |
| `make docs` / `make docs-serve` | Build (`mkdocs build --strict`) / live-serve this site. | no |

The `sudo` targets need **passwordless sudo** (XDP attach, netns, raw sockets); the
scripts elevate individual commands themselves. `make` with no target prints the full
annotated list.

## Pre-commit hooks

The flake wires a pre-commit hook set (`git-hooks.nix`) that runs on every commit:

- **rustfmt** — `cargo fmt --all -- --check`
- **clippy** — `cargo clippy --all-targets`

Both run through the same `rustup`-provided toolchain as the rest of the build, so
there is exactly one Rust toolchain in play. `make check` runs the identical pair, so
you can verify locally before committing.

## After changing the API

The deploy artifacts are **generated — not hand-edited**. `make generate` regenerates, in one
pass, everything that must track the Go types and the component code:

- the **deepcopy/conversion** for each API group (via `kube::codegen`);
- the **CRD manifests** — the `net` + `compiled` groups go into `charts/ectobase-pool/crd-bases`
  (shipped by the pool chart); the dispatch-aggregated `compute`/`storage`/`platform` groups go into
  `test/crds` (for envtest);
- the **per-component RBAC** ClusterRoles, one file per component into each chart's
  `files/<role>/` (mesh controller/agent, the materializers, the cni, the dispatch
  controller/broker) — so a component's RBAC always reflects its `+kubebuilder:rbac` markers;
- the **CRD API reference** under `docs/reference/api/` (via `crd-ref-docs`, the `docs-crd-ref`
  step) so the docs never drift from the schema.

Run it after editing any `api/*/v1alpha1/*_types.go` or any component's RBAC markers:

```sh
make generate
```

Commit the generated files (deepcopy, chart CRDs, chart RBAC, `docs/reference/api/*`) alongside
the change that motivated them.

The gRPC stubs are likewise generated: `make proto-go` (the `dataplane.v1`
`DataplaneNode` Go client) and `make proto-routebus` (the `routebus.v1` Go stubs)
after editing the corresponding `.proto` under `api/proto/`.

## How to add a datapath feature

The datapath's single most important invariant is **one core, run everywhere**: the
production eBPF program and the sim call the *same* `flowplane-core` function. Adding a
feature follows that seam end to end:

1. **Port the fn into `flowplane-core`.** Write it generic over the `Pkt`/`Maps`
   traits. If it needs a new map, add the accessor to the `Maps` trait.
2. **Wire the eBPF side.** Call the new fn from `flowplane-ebpf` via the existing
   `CtxPkt`/`GlobalMaps` trait impls (`coreimpl.rs`) — do not reimplement the logic in
   the program.
3. **Implement `MemMaps`.** Add the corresponding in-memory map to `flowplane-sim` and
   implement the new `Maps` accessor.
4. **Add a sim test.** Write a `SimNode`- or `Fabric`-based scenario in
   `flowplane-sim/src/*_test.rs` (single-node or multi-hop) and run `make sim`.
5. **Add an anchor case.** Add one `BPF_PROG_TEST_RUN` case in the relevant
   `flowplane/tests/anchor_*.rs` asserting the real bytecode's output matches the
   native core; verify with `make sim-anchor`.

If the verifier cannot accept the shared core (e.g. variable-offset writes), do **not**
fork a parallel core to satisfy an anchor — move the assertion up to a live test so the
code that ships is the code under test. See
[Strategy: test at the right level](../testing/strategy.md).

## Integration: the clab + kind fabric

The primary integration environment is a containerlab IPv6 fabric wrapping a kind
cluster, with the full mesh stack and the `flowplane` DaemonSet deployed. See
[The clab + kind fabric](../guides/local-fabric.md) for bring-up and scenarios.

## See also

- [Getting started (Nix + make)](../guides/getting-started.md)
- [Design history (specs & plans archive)](../contributing/index.md)
- [The in-process sim](../testing/sim.md)
