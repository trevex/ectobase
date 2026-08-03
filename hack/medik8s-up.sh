#!/usr/bin/env bash
set -euo pipefail
# Install the medik8s NodeHealthCheck (NHC) + Self Node Remediation (SNR) operators for
# dev/kind — the Tier-1 autonomous local failover backend. NOT a production install.
#
# medik8s ships no plain install.yaml, so this applies each operator's kustomize base
# directly from GitHub at a pinned tag via `kubectl apply -k`. On kind (no hardware
# watchdog) SNR uses its software-reboot default; enable a hardware watchdog through the
# ectobase chart (tier1Failover.watchdog.enabled=true) on real hardware.
#
# Usage:
#   hack/medik8s-up.sh          # install NHC + SNR operators
#   hack/medik8s-up.sh --help   # show this help
#
# Env overrides:
#   SNR_VERSION   Self Node Remediation tag (default v0.13.0)
#   NHC_VERSION   Node Health Check tag     (default v0.12.0)
#   SNR_NAMESPACE SNR operator namespace     (default self-node-remediation)
#   NHC_NAMESPACE NHC operator namespace     (default nhc)
#
# Caveat: config/default pins the manager image inside each repo tag; if the applied
# Deployment lands with an unexpected image, override it with `kubectl -n <ns> set image`.

SNR_VERSION="${SNR_VERSION:-v0.13.0}"
NHC_VERSION="${NHC_VERSION:-v0.12.0}"
SNR_NAMESPACE="${SNR_NAMESPACE:-self-node-remediation}"
NHC_NAMESPACE="${NHC_NAMESPACE:-nhc}"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '3,22p' "$0"
  exit 0
fi

echo "== Self Node Remediation operator ${SNR_VERSION} =="
kubectl apply -k "github.com/medik8s/self-node-remediation/config/default?ref=${SNR_VERSION}"

echo "== Node Health Check operator ${NHC_VERSION} =="
kubectl apply -k "github.com/medik8s/node-healthcheck-operator/config/default?ref=${NHC_VERSION}"

echo "== waiting for operator deployments to become available =="
kubectl -n "${SNR_NAMESPACE}" rollout status deploy --timeout=5m \
  || echo "   WARN: no ready deploy in ${SNR_NAMESPACE} (override SNR_NAMESPACE if it differs)"
# NHC's install namespace is upstream-dependent and may not be the default; warn (don't fail) if absent.
kubectl -n "${NHC_NAMESPACE}" rollout status deploy --timeout=5m \
  || echo "   WARN: no ready deploy in ${NHC_NAMESPACE}; NHC namespace is upstream-dependent — run 'kubectl get deploy -A | grep -i health' and set NHC_NAMESPACE"

echo "== medik8s operators applied. Enable Tier-1 on a pool with:"
echo "   helm upgrade ectobase deploy/charts/ectobase --set tier1Failover.enabled=true"
