# Getting started (Nix + make)

Everything ectobase needs to build and test is provided by the **Nix flake devShell**. You do not
install Rust, Go, protobuf, `bpf-linker`, `kind`, `containerlab`, `qemu`, or the Python packet-craft
tooling by hand — they are all pinned in `flake.nix`.

```sh
nix develop     # enter the dev shell (all targets assume you are inside it)
make            # list every target with its one-line description
```

## What the devShell provides

`flake.nix` `buildInputs` bring in, among others:

- **`rustup`** — the Rust toolchain is *not* a Nix package. It is pinned by `rust-toolchain.toml`
  to a nightly (`nightly-2026-01-15`) chosen so its `rustc` emits **LLVM 21** bitcode, matching the
  nixpkgs `bpf-linker` (built against LLVM 21). This avoids the *"Invalid record"* mismatch when
  `bpf-linker` links the eBPF object. `rust-src` is included for `-Z build-std=core` (the `bpfel`
  target has no prebuilt std). `aya-build` is told to use exactly this toolchain.
- **Go** (with default tools) — for `netplane`, the `cni/` plugin, and `controller-gen`.
- **`bpf-linker`, `protobuf` + `grpcurl`** — eBPF linking and the gRPC contracts.
- **`kind`, `containerlab`, `kubectl`** — the integration fabric.
- **`qemu`, `libvirt`, `OVMF`, `iproute2`, `bridge-utils`, `ethtool`, `tcpdump`** — VM boot and
  netns e2e harnesses.
- **`python3`** — present for the DPDK build's pyelftools; packet crafting is now the Go probe (`test/e2e/cmd/tap-dhcp-probe`).
- **`mdbook` + `mdbook-mermaid`** — this documentation.
- **`KUBEBUILDER_ASSETS`** — a real in-process apiserver for the controller-runtime envtest
  integration tests.

Because every tool is on the devShell `PATH`, the test scripts use bare tool names (no
host-specific paths) and are expected to run inside `nix develop` (the Makefile wraps them).

## Building

`flowplane` is the Rust dataplane daemon; the Go modules are `netplane`, `cni/`, and `api/`.

```sh
make build       # build flowplane (host crates + the eBPF object, via aya-build in build.rs)
make release     # the same, release mode
```

The eBPF crate (`flowplane-ebpf`) is **not** a host crate — the workspace `default-members` excludes
it so the host build never tries to compile the `#![no_main]` eBPF binary. Its bytecode is produced
by `aya-build` from `flowplane/build.rs` during `make build`. The Go modules build with the standard
`go build`/`go test` toolchain from the devShell.

## Generate / codegen targets

| Target | What it does |
|---|---|
| `make generate` | Regenerate the hand-maintained deepcopy (`zz_generated.deepcopy.go`) + CRD manifests from `api/v1alpha1` via `controller-gen`. Run it after editing any CRD type. |
| `make proto-go` | Generate the Go gRPC stubs for `dataplane.v1` into `cni/gen/`. |
| `make proto-routebus` | Generate the Go gRPC stubs for `routebus.v1` into `netplane/gen/`. |
| `make docs` | Build this mdbook into `docs/book`. |
| `make docs-serve` | Serve the docs locally with live reload. |
| `make image` / `make image-netplane` / `make image-kindnode` | Build the flowplane / netplane / fabric kind-node container images. |

## Test targets

Tests run at several levels of privilege and fidelity — see the
[testing strategy](../testing/strategy.md) for why:

| Target | Needs | What |
|---|---|---|
| `make test` | — | Host unit + POD-layout tests (no root) |
| `make lint` / `make check` | — | clippy across all targets / the pre-commit `fmt --check` + clippy |
| `make sim` | — | In-process datapath tests (no root, no clab) — the everyday dev loop |
| `make sim-anchor` | sudo | `BPF_PROG_TEST_RUN` byte-parity: native pure-core output == real bytecode |
| `make verifier` | sudo | Load the programs through the kernel verifier |
| `make e2e` | sudo | 3-node netns overlay end-to-end |
| `make ha` | sudo | HA pinned-maps kill+adopt smoke |
| `make tap-vm-smoke` | sudo + KVM | Boot a CirrOS VM on a real tap |

The `e2e`, `ha`, and `tap-*` targets need **passwordless sudo** (XDP attach, network namespaces, raw
sockets); the scripts elevate individual commands themselves. On a NixOS host see the
[runbook](./runbook.md) for the real-`sudo`-path gotcha.

## Next steps

- The integration environment: [the clab + kind fabric](./local-fabric.md).
- Zero-downtime restart semantics: [HA & graceful restart](../architecture/ha-graceful-restart.md).
- Hard-won operational findings: [the runbook](./runbook.md).
