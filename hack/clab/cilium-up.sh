#!/usr/bin/env bash
# cilium-up.sh — install Cilium (tunnel mode, IPv6-only, kubeProxyReplacement) on a kind
# cluster whose default CNI is disabled (see kind-cluster*.yaml: disableDefaultCNI + Cilium
# values in cilium-values.yaml). Idempotent (helm upgrade --install). Blocks until the
# cluster's nodes are Ready, so clab-up.sh can treat "returns 0" as "cluster usable".
#
#   cilium-up.sh <kind-cluster-name> [control-plane-container]
#
# The nodes stay NotReady from `kind create` until this runs — that is expected and why
# the clab k8s-kind deploy wait is 0s (kind must NOT gate on Ready without a CNI).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER="${1:?usage: cilium-up.sh <kind-cluster-name> [control-plane-container]}"
CP="${2:-${CLUSTER}-control-plane}"
# 1.20+ is required on nftables-only host kernels (no legacy ip6_tables module): earlier Cilium
# fatally `modprobe ip6_tables` in its iptables manager when IPv6 is enabled, even though the
# rules go through iptables-nft. 1.20 handles the missing legacy module gracefully. See README.
CILIUM_VERSION="${CILIUM_VERSION:-1.20.0-rc.0}"
VALUES="${HERE}/cilium-values.yaml"

KC="$(mktemp)"; trap 'rm -f "$KC"' EXIT
kind get kubeconfig --name "$CLUSTER" > "$KC"
export KUBECONFIG="$KC"

# With kube-proxy replaced there is no ClusterIP to bootstrap against, so the agents must
# reach the API server directly. Use the control-plane container's kind-network IPv6 (kubeadm
# advertises the API server there); it is reachable from every node over the kind docker net.
API_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}} {{end}}' "$CP" 2>/dev/null | tr ' ' '\n' | grep -m1 . || true)"
[ -n "$API_IP" ] || { echo "cilium-up: could not resolve API server IPv6 for $CP" >&2; exit 1; }

# clab returns as soon as `kind create` finishes (deploy wait 0s); give the API a moment.
for _ in $(seq 1 60); do kubectl get --raw='/healthz' >/dev/null 2>&1 && break; sleep 2; done

helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
helm repo update cilium >/dev/null 2>&1 || true

echo "cilium-up: installing Cilium ${CILIUM_VERSION} on ${CLUSTER} (API [${API_IP}]:6443)"
helm upgrade --install cilium cilium/cilium \
  --version "$CILIUM_VERSION" --namespace kube-system \
  -f "$VALUES" \
  --set k8sServiceHost="$API_IP" --set k8sServicePort=6443 \
  --wait --timeout 180s

echo "cilium-up: waiting for nodes Ready (${CLUSTER})..."
kubectl wait --for=condition=Ready nodes --all --timeout=180s
echo "cilium-up: ${CLUSTER} ready"
