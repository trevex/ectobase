{
  description = "wan-simulator — containerised lab WAN egress (NAT44/NAT66 + ECMP return routes)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  # The image is a Linux container, so only Linux systems build it — this mirrors
  # the sandbox repo's ciImage, which likewise builds under CI on Linux. Scoping
  # to Linux also keeps evaluation clean on a Darwin dev host (iproute2/nftables
  # are Linux-only packages and would otherwise refuse to evaluate).
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Self-configuring entrypoint: bridges the lab-facing links into one L2
        # segment, holds the gateway addresses, and programs NAT + return routes
        # from the WAN_* env — the container-local port of the former host WanUp.
        # writeShellApplication shellcheck-lints it and pins ip/nft on PATH.
        entrypoint = pkgs.writeShellApplication {
          name = "wan-simulator";
          runtimeInputs = [ pkgs.iproute2 pkgs.nftables pkgs.coreutils ];
          text = builtins.readFile ./entrypoint.sh;
        };
      in
      {
        # Image = the egress toolchain (ip + nft) plus the entrypoint, as a
        # layered OCI image. Pushed to Harbor and referenced as images.wan in the
        # sandbox lab.yaml. Mirrors the sandbox repo's ciImage.
        packages.default = pkgs.dockerTools.buildLayeredImage {
          name = "wan-simulator";
          tag = "latest";
          contents = [
            entrypoint
            pkgs.iproute2 pkgs.nftables             # ip / nft (also for `docker exec` debugging)
            pkgs.bashInteractive pkgs.coreutils     # interactive shell + userland
          ];
          extraCommands = ''
            mkdir -p bin; ln -sf ${pkgs.bashInteractive}/bin/bash bin/sh
            mkdir -p tmp; chmod 1777 tmp
          '';
          config = {
            Entrypoint = [ "${entrypoint}/bin/wan-simulator" ];
            Env = [ "PATH=/bin" ];
          };
        };

        packages.wan-simulator = self.packages.${system}.default;
      });
}
