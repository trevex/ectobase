#!/usr/bin/env bash
# Destroy the lean IPv6-fabric lab (containerlab destroy --cleanup also removes the
# kind cluster it owns). Idempotent: a no-op if the lab is not running. Mirrors the
# reference lab's `make destroy` (icn/sandbox/Makefile).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOPO="${HERE}/clab/ipv6-fabric.clab.yml"
CLAB="${CLAB:-containerlab}"

command -v "${CLAB%% *}" >/dev/null 2>&1 || { echo "clab-down: containerlab not found on PATH" >&2; exit 1; }

exec ${CLAB} destroy --cleanup -t "${TOPO}" "$@"
