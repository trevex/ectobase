# Development

Everything you need to build and test ectobase comes from the Nix flake, and every workflow runs
through `make`. This page covers the devShell, the `make` targets and which ones need root, what
to run before you call a change done, and the loops for API changes, datapath features and the
lab.

## The devShell

Enter the shell once; every target assumes you are inside it:

```sh
nix develop     # the pinned toolchain, plus the pre-commit hooks
make            # list every target with its one-line description
```

The scripts use bare tool names, with no host-specific paths, because the devShell puts
everything on `PATH`. `flake.nix` provides, among others:

| Tools | For |
|---|---|
| `rustup`, pinned by `rust-toolchain.toml` to `nightly-2026-01-15` with `rust-src`, `rustfmt`, `clippy` | The Rust workspace. The nightly predates Rust's switch to LLVM 22, so it emits LLVM 21 bitcode, matching the nixpkgs `bpf-linker`; a mismatch fails the eBPF link with "Invalid record". `rust-src` is there for `-Z build-std=core`, since the `bpfel` target has no prebuilt std. |
| Go, pinned to the newest patch of the minor in the `go.mod` files, with its default tools (including `golangci-lint` and `gopls`) | The Go modules. |
| `bpf-linker`, `bpftool`, `bpftrace`, `xdp-tools` | Linking and inspecting eBPF. |
| `protobuf`, `protoc-gen-go`, `protoc-gen-go-grpc`, `grpcurl` | The gRPC contracts, and calling the dataplane by hand. |
| `controller-gen`, `crd-ref-docs` | `make generate`. |
| `zensical` | This site. |
| `containerlab`, `talosctl` (pinned to `1.14.0-beta.0`, the lab's Talos image), `kubectl`, `helm` with `helm-unittest`, `kind` | The lab and the chart tests. |
| `qemu`, `libvirt`, `OVMF`, `iproute2`, `bridge-utils`, `ethtool`, `tcpdump`, `util-linux` (for `nsenter`) | VM smoke tests, netns scenarios and debugging. |

The shell also exports `KUBEBUILDER_ASSETS`, pointing at a real `kube-apiserver`, `etcd` and
`kubectl`, so controller-runtime envtest suites start an in-process apiserver under `go test`.

## Building

```sh
make build      # the flowplane binary: host crates plus the eBPF object
make release    # the same, in release mode
```

`flowplane-ebpf` is not a host crate. The workspace's `default-members` leave it out, and
`flowplane/flowplane/build.rs` builds the bytecode through `aya-build` during `make build`. The
`default-members` also leave out `flowplane-device`, so its own tests and lints run only with
`-p flowplane-device`; no `make` target does that. The Go modules
build with the plain `go` toolchain.

Container images:

| Target | Builds |
|---|---|
| `make image` | `flowplane` |
| `make image-mesh` | `mesh` (agent, compiler, reflector, both materializers) |
| `make image-cni` | `cni` |
| `make image-dispatch` | `dispatch-apiserver`, `dispatch-controller`, `dispatch-broker` |
| `make lab-app-images` | all six of the above |
| `make lab-images` | the lab's fabric images: `tayga`, `vyos`, `wan` |
| `make image-talos-mirror` | pulls the pinned Talos node image and tags it for the lab |

Image builds use host networking by default (`DOCKER_BUILD_NET=host`), because BuildKit's bridge
network cannot resolve package mirrors on some hosts. `IMAGE`, `TAG` and the other image variables
can be overridden.

## The make targets

| Target | Runs | Root |
|---|---|---|
| `make test` | `cargo test` for `flowplane-common`, `flowplane-control` and `flowplane`: unit tests and `#[repr(C)]` layout tests | no |
| `make sim` | `cargo test` for `flowplane-core` and `flowplane-sim`: the pure core and the in-process datapath sim | no |
| `make lint` | `cargo clippy --all-targets`, `golangci-lint` per Go module, and a `gofmt` check | no |
| `make fmt` | `cargo fmt` and `gofmt -w` | no |
| `make check` | `cargo fmt --check` and clippy, the same pair the pre-commit hooks run | no |
| `make chart-test` | `helm unittest` for both charts | no |
| `make ci` | `lint`, `sim`, `test`, `chart-test`, then `go test` in every Go module | no |
| `make generate` | deepcopy and conversion, the typed client, CRDs, RBAC and the API reference | no |
| `make proto-go`, `make proto-routebus` | the Go gRPC stubs for `dataplane.v1` and `routebus.v1` | no |
| `make docs`, `make docs-serve` | build this site strictly, or serve it with live reload | no |
| `make verifier` | load every forwarding program through the kernel verifier | sudo |
| `make sim-anchor` | `verifier`, then the `BPF_PROG_TEST_RUN` byte-parity anchors | sudo |
| `make ha` | the pinned-map restart and adopt contract, through the real control path | sudo |
| `make e2e` | `test/netns-e2e.sh run`, a three-hypervisor netns scenario | sudo |
| `make tap-dhcp-probe`, `make tap-vm-smoke` | DHCP on a real tap; a CirrOS VM on a real tap (needs KVM) | sudo |
| `make test-all` | `test`, `e2e` and `ha` | sudo |
| `make lab-up`, `make lab-test`, `make lab-down` | bring up the lab, run the live suite, tear it down | sudo |
| `make bpf-clean` | free leaked flowplane BPF pins on the host and in lab node containers; run it with the lab down, since it kills every `flowplane serve` | sudo |

The privileged targets need passwordless sudo: they load and attach eBPF programs, mount bpffs
and create namespaces and devices. The scripts elevate individual commands themselves. On NixOS
see [Runbook](../operations/runbook.md#nixos-and-the-real-sudo) for the real `sudo` path.
[Testing strategy](testing/strategy.md) explains what each tier proves.

## Before you call a change done

`make ci` is the gate that matches CI: `.github/workflows/test.yml` runs the same suites (`make
sim`, `make test`, `make chart-test`, `go test` per module) and a Go lint job. It is slightly
stricter than CI, because its `make lint` also runs clippy. Run it before you push.

`make ci` does not see everything. Two more checks depend on what you changed:

- Any change to the eBPF datapath is not done until `make verifier` passes. `make build`,
  `make sim` and `make ci` all pass on a program the kernel refuses to load: the object compiles
  fine, and only the verifier rejects a combined stack over 512 bytes or a program over the
  instruction limit. Run `make sim-anchor` too when you touch a path an anchor covers.
- Any change to a dataplane gRPC method, a request field, or what the dataplane accepts needs
  a look at `test/lab/livetest/`. Those tests call the gRPC API by name, carry the `live` build
  tag, and no gate compiles them; only `make lab-test` runs them, and it needs the lab up. At
  least compile them: `cd test/lab && go vet -tags live ./livetest/`. Say they were not run
  unless the lab ran.

### Cleaning up after a sudo target

A privileged cargo or Go run leaves root-owned files behind, in two places. The symptom is a
confusing failure later, such as `golangci-lint` reporting `typecheck` errors with
`permission denied` on a `.lock` file under the module cache. Fix both trees:

```sh
sudo chown -R "$(id -u):$(id -g)" target ~/go/pkg/mod
```

Don't chown `test/lab/build/`: it is root-owned on purpose (containerlab and Talos mounts,
kubeconfigs).

## Pre-commit hooks

The flake installs a pre-commit hook set (`git-hooks.nix`) when you enter the shell:

- rustfmt: `cargo fmt --all -- --check`;
- clippy: `cargo clippy --all-targets`.

Both run through the same `rustup` toolchain as the build, so there is one Rust toolchain in play.
`make check` runs the same pair.

## After changing the API

The deploy artifacts are generated. After you edit a type in `api/<group>/v1alpha1/`, a
kubebuilder marker, or a component's RBAC markers, run:

```sh
make generate
```

It regenerates deepcopy and conversion code, the typed client in `dispatch/client-go/`, the CRDs
in `charts/ectobase-pool/crd-bases/` and `test/crds/`, each component's role in
`charts/*/files/<role>/`, and the API reference in `docs/reference/api/`. Commit those files with
the change. After editing a `.proto` under `api/proto/`, run `make proto-go` or
`make proto-routebus`. [Generated artifacts](../reference/generated-artifacts.md) lists every
output.

If the change adds a component, a permission or a value, update the charts and their
`helm-unittest` suites and snapshots too (`make chart-test`).

## Adding a datapath feature

The datapath's central rule is one core, run everywhere: the production eBPF program and the sim
call the same `flowplane-core` function. A feature follows that seam end to end:

1. Write it in `flowplane-core`, generic over the `Pkt` and `Maps` traits. If it needs a new
   map, add an accessor to `Maps`.
2. Wire the eBPF side. Declare the map in `flowplane-ebpf/src/maps.rs`, implement the accessor
   in `coreimpl.rs`, and call the core function from the program. Don't reimplement the logic in
   the program.
3. Implement it in `MemMaps` in `flowplane-sim`.
4. Add sim tests in `flowplane-sim/src/*_test.rs`, single-node or across a `Fabric`, and run
   `make sim`. Cover every case: the sim is the main functional oracle, because the Geneve decap
   path cannot be driven by `BPF_PROG_TEST_RUN`.
5. Program it from the control plane through `flowplane-control` (the `MapWriter` trait), the
   gRPC handlers in `flowplane`, and, if it comes from intent, the agent in `mesh/agent/`.
6. Run `make verifier`. If the path has an anchor in `flowplane/tests/anchor_*.rs`, extend it
   and run `make sim-anchor`; a new anchor file must also be added to the `sim-anchor` target,
   which lists each one.

If the verifier cannot accept the shared core, don't fork a parallel implementation to satisfy an
anchor. Move the assertion up to a live test, so the code under test is the code that ships. See
[Testing strategy](testing/strategy.md).

## Working with the lab

The lab is a containerlab IPv6 fabric of Talos-in-container clusters with both charts installed.
[Bring up the lab](../guides/lab.md) walks through it; `test/lab/README.md` is the CLI reference.
The targets you use day to day:

```sh
make lab-images && make image-talos-mirror   # first run: fabric images and the Talos image
make lab-up          # build the six app images, bring up the fabric, install ectobase
make lab-test        # the live suite: go test -tags live ./livetest/... (45-minute timeout)
make lab-deploy      # re-run only the chart installs against the running fabric
make lab-down        # tear down, keeping the registry cache (lab-down-purge drops it)
```

`make lab-ceph` and `make lab-tier2-up` add Ceph, KubeVirt, CDI and `vm-materializer` for the
storage and failover tests.

`make lab-deploy` does not push images; only `lab up` does. To run new code on a running lab,
build the image, push it into the in-fabric registry through `127.0.0.1:5000`, and restart the
workload. The lab installs with `imagePullPolicy=Always`, so the restart pulls the new digest. See
[Runbook](../operations/runbook.md#a-redeploy-runs-the-old-image).

## Known limitations

The `dispatch` module points `go.opendefense.cloud/kit` (apiserver-kit) at a local path through a
`replace` in `dispatch/go.mod`, so it builds only with a checkout of that module at that path.
CI's `go test` for `dispatch` fails until the module is published; the comment at the top of
`.github/workflows/test.yml` records this.

## Where to go next

- [Repository layout](repository-layout.md): where the code you are changing lives.
- [Testing strategy](testing/strategy.md): which tier proves what.
- [Writing docs](documentation.md): the docs half of a change.
