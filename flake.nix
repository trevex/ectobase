{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    go-overlay = {
      url = "github:purpleclay/go-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, go-overlay, git-hooks, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ go-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };
        # Pin the dev-shell Go to the latest PATCH of the minor declared in the modules
        # (go.work + all go.mod say `go 1.26`), via the go-overlay. `fromGoMod` reads the
        # `go` directive and resolves its newest patch, so the shell tracks patches but never
        # drifts ahead of the workspace's declared minor. All modules share the minor, so
        # reading cni/go.mod is representative (there is no fromGoWork).
        go = pkgs.go-bin.fromGoMod ./cni/go.mod;

        # controller-runtime envtest assets: a directory holding exactly the three binaries
        # envtest.Environment starts a real in-process apiserver from (kube-apiserver + etcd + kubectl),
        # exported via KUBEBUILDER_ASSETS. Lets `go test` spin a real apiserver for controller
        # integration tests without a cluster. Symlinked individually to avoid bin/ collisions
        # (pkgs.kubernetes also ships kubectl).
        kubebuilderAssets = pkgs.runCommand "kubebuilder-envtest-assets" { } ''
          mkdir -p $out/bin
          ln -s ${pkgs.kubernetes}/bin/kube-apiserver $out/bin/kube-apiserver
          ln -s ${pkgs.etcd}/bin/etcd $out/bin/etcd
          ln -s ${pkgs.kubectl}/bin/kubectl $out/bin/kubectl
        '';

        # Rust is managed entirely by rustup (community-standard for aya/aya-build), pinned
        # via rust-toolchain.toml to nightly-2026-01-15 (LLVM 21) to match nixpkgs bpf-linker.
        # The pre-commit rustfmt/clippy hooks therefore run through rustup too (system hooks
        # invoking `cargo fmt` / `cargo clippy`), so there is exactly one Rust toolchain.
        pre-commit-check = git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            rustfmt-rustup = {
              enable = true;
              name = "rustfmt (rustup)";
              entry = "cargo fmt --all -- --check";
              language = "system";
              pass_filenames = false;
              files = "\\.rs$";
            };
            clippy-rustup = {
              enable = true;
              name = "clippy (rustup)";
              # default-members excludes flowplane-ebpf, so the host build never tries to compile
              # the #![no_main] eBPF bin; the ebpf object is built via aya-build from build.rs.
              entry = "cargo clippy --all-targets";
              language = "system";
              pass_filenames = false;
              files = "\\.rs$";
            };
          };
        };
      in
      {
        devShells.default = pkgs.mkShell {
          inherit (pre-commit-check) shellHook;

          buildInputs = [
            pkgs.rustup
            go.withDefaultTools
            pkgs.cargo-watch
            pkgs.cargo-edit
            pkgs.cargo-nextest
            pkgs.wasm-tools
            pkgs.mdbook
            pkgs.mdbook-mermaid
            pkgs.kubernetes-controller-tools # controller-gen: regenerates deepcopy + CRDs (see `make generate`)
            # eBPF + gRPC + VM/e2e harness tooling. Everything the test scripts need is
            # provided here, so the scripts use bare tool names (no host-specific paths) and are
            # expected to run inside `nix develop` (the Makefile wraps them).
            pkgs.bpf-linker
            pkgs.bpftools # provides `bpftool`; the clab harness runs it via nsenter or docker exec
            pkgs.bpftrace # ad-hoc XDP/tc tracepoints for hack/clab/bpf-trace.sh
            pkgs.xdp-tools # xdpdump, used by hack/clab/bpf-trace.sh
            pkgs.protobuf
            pkgs.protoc-gen-go # `make proto-go` gRPC stub generation
            pkgs.protoc-gen-go-grpc
            pkgs.grpcurl
            pkgs.qemu
            pkgs.libvirt
            pkgs.OVMF
            pkgs.iproute2
            pkgs.bridge-utils
            pkgs.ethtool
            pkgs.tcpdump
            pkgs.util-linux # nsenter, for entering container/netns namespaces from the harness
            pkgs.kubectl
            # clab fabric tooling — so hack/clab-up.sh + `go test ./test/e2e/...` work in a plain
            # `nix develop` (Cilium installs via the pinned helm chart — no cilium-cli needed).
            pkgs.kind
            pkgs.containerlab
            pkgs.kubernetes-helm
            pkgs.gettext # provides envsubst for the clab fixture/kind-config templating
            pkgs.socat
            pkgs.gnumake
            # DPDK build toolchain — dpdk-sys/build.rs downloads the pinned DPDK release and
            # builds it with meson/ninja (static). These are the DPDK build + link deps and
            # bindgen's clang. No prebuilt pkgs.dpdk — we compile our own pinned version.
            pkgs.meson
            pkgs.ninja
            pkgs.pkg-config
            pkgs.clang                        # bindgen front-end
            pkgs.python3Packages.pyelftools   # required by the DPDK build — only python3 dep; pulls python3 transitively
            pkgs.numactl                      # libnuma (DPDK dep)
            pkgs.libpcap                      # net_pcap PMD
            pkgs.libbpf                       # net_af_xdp PMD (Milestone 2)
            pkgs.xdp-tools.lib                # net_af_xdp PMD (Milestone 2) — libxdp.so is in the .lib output
          ];

          RUST_BACKTRACE = 1;
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          # rust-bindgen (dpdk-sys/build.rs) needs libclang at runtime.
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          # Real in-process apiserver for controller-runtime envtest integration tests.
          KUBEBUILDER_ASSETS = "${kubebuilderAssets}/bin";
        };

        # A fully-static iperf3 the QoS scenarios copy into a foreign (debian) kind node to
        # measure egress pacing. A dynamically-linked devShell binary can't run inside that
        # container, so this is the one sanctioned build-from-flake the harness needs — pinned
        # to this repo's nixpkgs (via `nix build .#iperf3-static`), not the floating registry.
        packages.iperf3-static = pkgs.pkgsStatic.iperf3;
      });
}
