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

        # helm-unittest nix package ships a single binary named `untt`, but the upstream
        # plugin.yaml uses platform-specific names (untt-linux-amd64, untt-macos-arm64, …).
        # Create a wrapper derivation that copies the plugin dir and adds the required symlink.
        helm-unittest-fixed = pkgs.runCommand "helm-unittest-fixed"
          { src = pkgs.kubernetes-helmPlugins.helm-unittest; }
          ''
            mkdir -p $out
            cp -r $src/helm-unittest $out/helm-unittest
            chmod -R u+w $out/helm-unittest
            ln -sf $out/helm-unittest/untt $out/helm-unittest/untt-linux-amd64
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
        # Pin talosctl to the Talos release the container image ships (v1.14.0-beta.0),
        # so the CLI validates the same machine-config documents the nodes run — the
        # native GoBGP BGPPeerConfig is v1.14+; nixpkgs talosctl only tracks stable.
        talosVersion = "1.14.0-beta.0";
        talosctlHash = {
          x86_64-linux = "sha256-UB5aaqxQunF60z1nOUpQhD/Xa+CMRe/q6zexs9HMV88=";
          aarch64-linux = "sha256-XY0W8FKTkKJrMnOiyWDMGtIgvnw6ST6Pqe1OF56CiE4=";
        };
        talosArch = { x86_64-linux = "amd64"; aarch64-linux = "arm64"; };
        talosOS = { x86_64-linux = "linux"; aarch64-linux = "linux"; };
        talosctl = pkgs.stdenvNoCC.mkDerivation {
          pname = "talosctl";
          version = talosVersion;
          src = pkgs.fetchurl {
            url = "https://github.com/siderolabs/talos/releases/download/v${talosVersion}/talosctl-${talosOS.${system}}-${talosArch.${system}}";
            hash = talosctlHash.${system};
          };
          dontUnpack = true;
          installPhase = "install -Dm755 $src $out/bin/talosctl";
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
            pkgs.bpftools # provides `bpftool`; the lab harness runs it via nsenter or docker exec
            pkgs.bpftrace # ad-hoc XDP/tc tracepoints for datapath debugging
            pkgs.xdp-tools # xdpdump
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
            # kind fabric tooling — so `go run ./test/lab` (make lab-*) works in a plain
            # `nix develop` (Cilium installs via the pinned helm chart — no cilium-cli needed).
            pkgs.kind
            pkgs.containerlab
            (pkgs.wrapHelm pkgs.kubernetes-helm { plugins = [ helm-unittest-fixed ]; })
            pkgs.gettext # provides envsubst for fixture/kind-config templating
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
            # VyOS clab image: ISO fetch + userspace squashfs->rootfs extraction (test/images/vyos)
            pkgs.squashfs-tools-ng            # sqfs2tar
            pkgs.libarchive                   # bsdtar
            pkgs.minisign                     # optional ISO signature verification
            talosctl                          # Talos gen/bootstrap/kubeconfig, pinned to the image version (test/images/talos)
            pkgs.zstd                         # decompress the Talos imager initramfs
            pkgs.cpio                         # unpack the imager initramfs cpio
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
