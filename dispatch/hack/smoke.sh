#!/usr/bin/env bash
# Copyright 2026 ectobase contributors
# SPDX-License-Identifier: Apache-2.0
#
# Single-cluster live smoke for the dispatch control plane:
#   1. bring up a plain kind cluster
#   2. build the dispatch-apiserver + dispatch-controller binaries on the HOST
#      (GOWORK=off, CGO disabled, static) and bake them into distroless images
#      (host build sidesteps the local `replace go.opendefense.cloud/kit` in
#       dispatch/go.mod, which points outside the module tree and so is not
#       reachable from a Docker build context)
#   3. `kind load` the images, `helm install ectobase-dispatch` (the dispatch chart)
#   4. wait for rollouts, then prove:
#        - `kubectl get clusterpools.platform.ectobase.dev` works (aggregation up)
#        - a created ClusterPool gets status.phase: Pending (controller reconciles)
#
# The envtest controller test (dispatch/test/controller_test.go) is the
# authoritative gate; this is best-effort end-to-end validation. Run from the
# repo root: `bash dispatch/hack/smoke.sh`.
set -euo pipefail

HUB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER="${KIND_CLUSTER:-dispatch-smoke}"
APISERVER_IMG="ghcr.io/trevex/ectobase/dispatch-apiserver:dev"
CONTROLLER_IMG="ghcr.io/trevex/ectobase/dispatch-controller:dev"
BROKER_IMG="ghcr.io/trevex/ectobase/dispatch-broker:dev"

cleanup() {
  # Remove host-built binaries copied next to the Dockerfiles.
  rm -f "${HUB_DIR}/dispatch-apiserver" "${HUB_DIR}/dispatch-controller" "${HUB_DIR}/dispatch-broker"
}
trap cleanup EXIT

echo "==> kind cluster: ${CLUSTER}"
kind get clusters 2>/dev/null | grep -qx "${CLUSTER}" || kind create cluster --name "${CLUSTER}"

echo "==> building host binaries (GOWORK=off, static)"
(
  cd "${HUB_DIR}"
  GOWORK=off CGO_ENABLED=0 go build -o dispatch-apiserver ./cmd/apiserver
  GOWORK=off CGO_ENABLED=0 go build -o dispatch-controller ./cmd/controller
  GOWORK=off CGO_ENABLED=0 go build -o dispatch-broker ./cmd/broker
)

echo "==> building images"
docker build -f "${HUB_DIR}/Dockerfile.apiserver" -t "${APISERVER_IMG}" "${HUB_DIR}"
docker build -f "${HUB_DIR}/Dockerfile.controller" -t "${CONTROLLER_IMG}" "${HUB_DIR}"
docker build -f "${HUB_DIR}/Dockerfile.broker" -t "${BROKER_IMG}" "${HUB_DIR}"

echo "==> loading images into kind"
kind load docker-image --name "${CLUSTER}" "${APISERVER_IMG}"
kind load docker-image --name "${CLUSTER}" "${CONTROLLER_IMG}"
kind load docker-image --name "${CLUSTER}" "${BROKER_IMG}"

echo "==> installing the ectobase-dispatch chart"
# The chart also ships the netplane compiler + reflector (they need the netplane:dev image, which
# this dispatch-only smoke does not build), so DON'T --wait on the whole release — just install and then
# wait on the system-namespace rollouts below. --create-namespace makes the baseline-safe `system`
# release namespace; the chart creates the PSA-privileged ectobase-system namespace itself.
helm upgrade --install ectobase-dispatch "${HUB_DIR}/../charts/ectobase-dispatch" \
  --namespace system --create-namespace

echo "==> waiting for rollouts"
kubectl -n system rollout status deploy/postgres --timeout=120s
kubectl -n system rollout status deploy/kine --timeout=120s
kubectl -n system rollout status deploy/dispatch-apiserver --timeout=180s
kubectl -n system rollout status deploy/dispatch-controller --timeout=120s

echo "==> waiting for the aggregated API to be available"
for i in $(seq 1 30); do
  if kubectl get clusterpools.platform.ectobase.dev >/dev/null 2>&1; then break; fi
  sleep 2
done
kubectl get clusterpools.platform.ectobase.dev

echo "==> creating a ClusterPool and asserting status.phase == Pending"
kubectl apply -f - <<'EOF'
apiVersion: platform.ectobase.dev/v1alpha1
kind: ClusterPool
metadata:
  name: smoke-pool
spec:
  region: eu
EOF

phase=""
for i in $(seq 1 30); do
  phase="$(kubectl get clusterpool smoke-pool -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  [ "${phase}" = "Pending" ] && break
  sleep 2
done

if [ "${phase}" = "Pending" ]; then
  echo "SMOKE PASS: ClusterPool smoke-pool reached status.phase=Pending"
else
  echo "SMOKE FAIL: ClusterPool smoke-pool phase=${phase:-<empty>} (expected Pending)"
  kubectl -n system get pods
  kubectl -n system logs deploy/dispatch-controller --tail=50 || true
  exit 1
fi

echo "==> cleanup: kind delete cluster --name ${CLUSTER}   (left running for inspection)"
