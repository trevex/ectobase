#!/usr/bin/env bash
# Destroy the lean IPv6-fabric lab (containerlab destroy --cleanup also removes the
# kind cluster it owns). Idempotent: a no-op if the lab is not running. Mirrors the
# reference lab's `make destroy` (icn/sandbox/Makefile).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOPO="${HERE}/clab/ipv6-fabric.clab.yml"
CLAB="${CLAB:-containerlab}"

command -v "${CLAB%% *}" >/dev/null 2>&1 || { echo "clab-down: containerlab not found on PATH" >&2; exit 1; }

# Free leaked flowplane BPF pins BEFORE destroy (while the kind/clab node containers
# still exist, so their per-node bpffs is swept too) — a pinned CONNTRACK map is
# ~100-150 MB of kernel RAM and clab destroy alone never touches host-side pins.
bash "${HERE}/bpf-cleanup.sh" || echo "clab-down: bpf-cleanup (pre-destroy) failed — continuing"

${CLAB} destroy --cleanup -t "${TOPO}" "$@"

# Host sweep again after destroy: catch anything the teardown respawned or left behind.
HOST_ONLY=1 bash "${HERE}/bpf-cleanup.sh" || echo "clab-down: bpf-cleanup (post-destroy) failed"
