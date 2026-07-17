#!/usr/bin/env bash
# test/tap-dhcp-probe.sh — wrapper for tap-dhcp-probe.py.
# Run inside the flake devShell (the Makefile does): `make tap-dhcp-probe` or
# `nix develop -c ./test/tap-dhcp-probe.sh`. Builds flowplane, then runs the probe under sudo with
# the flake python (scapy). See tap-dhcp-probe.py for what it proves (native-mode DHCP frame
# growth on a real tap).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo build -p flowplane >/dev/null 2>&1
PYBIN="$(command -v python3)"  # flake python (with scapy), provided by nix develop

# Clean any leftovers from a prior aborted run.
sudo pkill -f 'flowplane bringup --uplink dhu0' 2>/dev/null || true
sudo ip link del dhg0 2>/dev/null || true
sudo ip link del dhu0 2>/dev/null || true
sleep 1

sudo "$PYBIN" "$ROOT/test/tap-dhcp-probe.py"
