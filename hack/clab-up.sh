#!/usr/bin/env bash
# Deploy the lean IPv6 BGP-unnumbered fabric (FRR ToR + a kind cluster whose two
# nodes are xdp-dp "hosts"). Idempotent: containerlab deploy --reconfigure tears
# down a prior instance of the same lab first. Mirrors the reference lab's
# `make deploy` (icn/sandbox/Makefile).
#
# Requires: containerlab and kind on PATH, and a container runtime (docker). The
# fabric CANNOT run without root/containerlab — the Go e2e SKIPs when tooling is
# absent (test/e2e/fabric_test.go); this script is what a capable host runs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOPO="${HERE}/clab/ipv6-fabric.clab.yml"
CLAB="${CLAB:-containerlab}"

command -v "${CLAB%% *}" >/dev/null 2>&1 || { echo "clab-up: containerlab not found on PATH" >&2; exit 1; }
command -v kind >/dev/null 2>&1 || { echo "clab-up: kind not found on PATH" >&2; exit 1; }

# --reconfigure makes re-runs idempotent (destroy+deploy the same-named lab).
exec ${CLAB} deploy --reconfigure -t "${TOPO}" "$@"
