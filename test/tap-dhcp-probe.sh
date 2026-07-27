#!/usr/bin/env bash
# test/tap-dhcp-probe.sh — wrapper for the Go tap-dhcp-probe.
# Run inside the flake devShell (the Makefile does): `make tap-dhcp-probe` or
# `nix develop -c ./test/tap-dhcp-probe.sh`. Builds flowplane and the Go probe, then runs the
# probe under sudo. See test/e2e/cmd/tap-dhcp-probe/ for what it proves (native-mode DHCP frame
# growth on a real tap).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo build -p flowplane >/dev/null 2>&1

# Build the pure-Go probe (replaces the scapy python probe) once; PROBE is the binary consumers run.
PROBE="${ROOT}/test/e2e/tap-dhcp-probe.bin"
( cd "${ROOT}/test/e2e" && CGO_ENABLED=0 go build -o "$PROBE" ./cmd/tap-dhcp-probe )

# Clean any leftovers from a prior aborted run.
sudo pkill -f 'flowplane bringup --uplink dhu0' 2>/dev/null || true
sudo ip link del dhg0 2>/dev/null || true
sudo ip link del dhu0 2>/dev/null || true
sleep 1

sudo "$PROBE"
