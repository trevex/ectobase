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

# The fabric nodes use the custom kind-node image (node-IP = pre-kubelet BGP /64).
# Build it if missing, and render the per-node prefix mount paths to absolutes
# (kind rejects relative extraMounts hostPaths).
REPO="$(cd "${HERE}/.." && pwd)"
if ! docker image inspect kindest/node-fabric:dev >/dev/null 2>&1; then
  make -C "${REPO}" image-kindnode
fi
PREFIX_DIR="${HERE}/clab/prefixes"
for f in "${HERE}/clab/kind-cluster.yaml" "${HERE}/clab/kind-cluster-k02.yaml" "${HERE}/clab/kind-cluster-k03.yaml"; do
  sed "s#PREFIX_DIR#${PREFIX_DIR}#g" "$f" > "${f}.gen"
done

# The WAN edge attaches to the `clabwan` host bridge (a clab `bridge`-kind node references a
# pre-existing host bridge). Create it + the nat_ip masquerade before deploy. Idempotent.
bash "${HERE}/clab/wan-up.sh"

# --reconfigure makes re-runs idempotent (destroy+deploy the same-named lab).
exec ${CLAB} deploy --reconfigure -t "${TOPO}" "$@"
