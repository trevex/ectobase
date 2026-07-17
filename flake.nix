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
    # The genuine dpservice source, used to build the real dpservice-cli (the gRPC client our
    # conformance harness drives) from source — no out-of-band binary fetch. Pinned to the tag
    # our proto/dpdk.proto matches.
    dpservice = {
      url = "github:ironcore-dev/dpservice?ref=v0.3.22";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, go-overlay, git-hooks, dpservice, ... }:
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

        # The real dpservice-cli (cli/dpservice-cli in the dpservice repo), built from the pinned
        # `dpservice` flake input via buildGoModule. Placed on PATH in the devShell so the
        # conformance harness drives our gRPC server with the genuine client.
        dpservice-cli = pkgs.buildGoModule {
          pname = "dpservice-cli";
          version = "0.3.22";
          src = dpservice;
          modRoot = "cli/dpservice-cli";
          vendorHash = "sha256-mtJ4pS+KI9Gk3QEG9Zu1y/dCfzPDw5Tn/MW0d7g3C2o=";
          doCheck = false;
          subPackages = [ "." ];
        };

        # Python with the packages the test harnesses need (scapy for packet crafting, pytest for
        # the conformance suite). Reused across the devShell and any script run via `nix develop`.
        pythonEnv = pkgs.python3.withPackages (ps: with ps; [ scapy pytest ]);

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
        packages.dpservice-cli = dpservice-cli;

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
            # eBPF + gRPC + VM/conformance harness tooling. Everything the test scripts need is
            # provided here, so the scripts use bare tool names (no host-specific paths) and are
            # expected to run inside `nix develop` (the Makefile wraps them).
            pkgs.bpf-linker
            pkgs.protobuf
            pkgs.grpcurl
            pkgs.qemu
            pkgs.libvirt
            pkgs.OVMF
            pkgs.iproute2
            pkgs.bridge-utils
            pkgs.ethtool
            pkgs.tcpdump
            pkgs.kubectl
            pkgs.socat
            pkgs.gnumake
            pythonEnv
            dpservice-cli
          ];

          RUST_BACKTRACE = 1;
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          # Real in-process apiserver for controller-runtime envtest integration tests.
          KUBEBUILDER_ASSETS = "${kubebuilderAssets}/bin";
        };
      });
}
