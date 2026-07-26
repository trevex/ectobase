#!/usr/bin/env bash
# Deploy the lean IPv6 BGP-unnumbered fabric (FRR ToR + a kind cluster whose two
# nodes are flowplane "hosts"). Idempotent: containerlab deploy --reconfigure tears
# down a prior instance of the same lab first. Mirrors the reference lab's
# `make deploy` (icn/sandbox/Makefile).
#
# Requires: containerlab and kind on PATH, and a container runtime (docker). The
# fabric CANNOT run without root/containerlab — the Go e2e SKIPs when tooling is
# absent (test/e2e/fabric_test.go); this script is what a capable host runs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/clab/env.sh"
TOPO="${HERE}/clab/ipv6-fabric.clab.yml"

# Resolve external tools to ABSOLUTE paths ONCE, so invocations run the real binary
# regardless of PATH quirks (NixOS root secure_path drops nix-provided tools).
CLAB="$(command -v "${CLAB:-containerlab}")"; : "${CLAB:?containerlab not found on PATH — run inside 'nix develop'}"
KIND="$(command -v kind)"                   ; : "${KIND:?kind not found on PATH — run inside 'nix develop'}"
DOCKER="$(command -v docker)"               ; : "${DOCKER:?docker not found on PATH}"

# Defensive: clear leaked flowplane BPF pins from any prior crashed run before we
# stand a new fabric up, so kernel memory doesn't compound across up/down cycles.
# HOST_ONLY — a stale prior lab's containers are torn down by `deploy --reconfigure`.
HOST_ONLY=1 bash "${HERE}/bpf-cleanup.sh" || echo "clab-up: bpf-cleanup (pre-deploy) failed — continuing"

# The fabric nodes use the custom kind-node image (node-IP = pre-kubelet BGP /64).
# Build it if missing, and render the per-node prefix mount paths to absolutes
# (kind rejects relative extraMounts hostPaths).
REPO="$(cd "${HERE}/.." && pwd)"
if ! "$DOCKER" image inspect "${CLAB_IMAGE_KINDNODE}" >/dev/null 2>&1; then
  make -C "${REPO}" image-kindnode
fi
PREFIX_DIR="${HERE}/clab/prefixes"
for f in "${HERE}/clab/kind-cluster.yaml" "${HERE}/clab/kind-cluster-k02.yaml" "${HERE}/clab/kind-cluster-k03.yaml"; do
  sed "s#PREFIX_DIR#${PREFIX_DIR}#g" "$f" > "${f}.gen"
done

# The WAN edge attaches to the `clabwan` host bridge (a clab `bridge`-kind node references a
# pre-existing host bridge). Create it + the nat_ip masquerade before deploy. Idempotent.
bash "${HERE}/clab/wan-up.sh"

# Let the kind clusters' nodes reach each other over the `kind` docker bridge (IPv6). With
# br_netfilter loaded, `bridge-nf-call-ip6tables=1` makes even SAME-BRIDGE (L2-bridged) frames
# traverse the host ip6tables FORWARD chain — and containerlab sets that chain's policy to DROP
# with ACCEPT rules ONLY for its own bridges (oob/clabwan/ksw*), NOT the kind bridge. Result:
# inter-node IPv6 ND (neighbor solicitation) between a multi-node cluster's nodes (k01 cp<->worker)
# is silently dropped, so the worker can't reach the API server and its CNI/kubelet never go Ready
# (this was the "flaky boot-race"). Turning the sysctl off makes bridged frames bypass ip6tables
# entirely — routed WAN egress still hits FORWARD and clab's rules, so nothing else regresses.
sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1 \
  || { modprobe br_netfilter 2>/dev/null && sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1; } \
  || echo "clab-up: warning: could not clear bridge-nf-call-ip6tables (inter-node kind IPv6 may drop)"

# --reconfigure makes re-runs idempotent (destroy+deploy the same-named lab).
# The kind clusters have disableDefaultCNI (see kind-cluster*.yaml), so their nodes come up
# NotReady and the clab k8s-kind deploy wait is 0s (kind must not gate on Ready without a CNI).
#
# TTY note: clab's vyos kind talks to the VyOS CLI over a pty to wait for "Cli ready". With no
# controlling terminal (backgrounded / CI / `>log`), that pty read fails ("read /dev/ptmx:
# input/output error") and clab loops FOREVER. So when stdout is not a TTY, run the deploy under
# script(1) to give it a pty. (Interactive runs already have one and take the direct path.)
if [ -t 1 ]; then
  "${CLAB}" deploy --reconfigure -t "${TOPO}" "$@"
else
  script -qefc "${CLAB} deploy --reconfigure -t ${TOPO} $*" /dev/null
fi

# Install the CNI (Cilium, tunnel mode) on each kind cluster — this is what brings the nodes
# Ready. Sequential so a failure is attributable; each call blocks until its cluster is Ready.
for c in k01 k02 k03; do
  bash "${HERE}/clab/cilium-up.sh" "$c"
done
echo "clab-up: fabric up, all kind clusters Ready (Cilium tunnel-mode CNI installed)"
