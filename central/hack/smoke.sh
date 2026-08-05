#!/usr/bin/env bash
# Copyright 2026 ectobase contributors
# SPDX-License-Identifier: Apache-2.0
#
# Single-cluster live smoke for the central control plane:
#   1. bring up a plain kind cluster
#   2. build the central-apiserver + central-controller binaries on the HOST
#      (GOWORK=off, CGO disabled, static) and bake them into distroless images
#      (host build sidesteps the local `replace go.opendefense.cloud/kit` in
#       central/go.mod, which points outside the module tree and so is not
#       reachable from a Docker build context)
#   3. `kind load` the images, `kubectl apply -k central/config`
#   4. wait for rollouts, then prove:
#        - `kubectl get clusterpools.platform.ectobase.dev` works (aggregation up)
#        - a created ClusterPool gets status.phase: Pending (controller reconciles)
#
# The envtest controller test (central/test/controller_test.go) is the
# authoritative gate; this is best-effort end-to-end validation. Run from the
# repo root: `bash central/hack/smoke.sh`.
set -euo pipefail

CENTRAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER="${KIND_CLUSTER:-central-smoke}"
APISERVER_IMG="ghcr.io/trevex/ectobase/central-apiserver:dev"
CONTROLLER_IMG="ghcr.io/trevex/ectobase/central-controller:dev"
BROKER_IMG="ghcr.io/trevex/ectobase/central-broker:dev"

cleanup() {
  # Remove host-built binaries copied next to the Dockerfiles.
  rm -f "${CENTRAL_DIR}/central-apiserver" "${CENTRAL_DIR}/central-controller" "${CENTRAL_DIR}/central-broker"
}
trap cleanup EXIT

echo "==> kind cluster: ${CLUSTER}"
kind get clusters 2>/dev/null | grep -qx "${CLUSTER}" || kind create cluster --name "${CLUSTER}"

echo "==> building host binaries (GOWORK=off, static)"
(
  cd "${CENTRAL_DIR}"
  GOWORK=off CGO_ENABLED=0 go build -o central-apiserver ./cmd/apiserver
  GOWORK=off CGO_ENABLED=0 go build -o central-controller ./cmd/controller
  GOWORK=off CGO_ENABLED=0 go build -o central-broker ./cmd/broker
)

echo "==> building images"
docker build -f "${CENTRAL_DIR}/Dockerfile.apiserver" -t "${APISERVER_IMG}" "${CENTRAL_DIR}"
docker build -f "${CENTRAL_DIR}/Dockerfile.controller" -t "${CONTROLLER_IMG}" "${CENTRAL_DIR}"
docker build -f "${CENTRAL_DIR}/Dockerfile.broker" -t "${BROKER_IMG}" "${CENTRAL_DIR}"

echo "==> loading images into kind"
kind load docker-image --name "${CLUSTER}" "${APISERVER_IMG}"
kind load docker-image --name "${CLUSTER}" "${CONTROLLER_IMG}"
kind load docker-image --name "${CLUSTER}" "${BROKER_IMG}"

echo "==> applying manifests"
kubectl apply -k "${CENTRAL_DIR}/config"

echo "==> waiting for rollouts"
kubectl -n system rollout status deploy/postgres --timeout=120s
kubectl -n system rollout status deploy/kine --timeout=120s
kubectl -n system rollout status deploy/central-apiserver --timeout=180s
kubectl -n system rollout status deploy/central-controller --timeout=120s

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
  kubectl -n system logs deploy/central-controller --tail=50 || true
  exit 1
fi

echo "==> cleanup: kind delete cluster --name ${CLUSTER}   (left running for inspection)"
