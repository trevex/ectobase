#!/usr/bin/env bash
set -euo pipefail
# BEST-EFFORT live validation of Tier-1 autonomous local failover on a dev kind cluster.
# NOT CI-wired: it needs a multi-node kind cluster with KubeVirt + CDI + Rook + medik8s.
# It boots a VM on an RWO RBD DataVolume, hard-kills the VM's node, and asserts the VMI
# reschedules onto a surviving node (medik8s fences the dead node via the out-of-service
# taint; ceph-csi reattaches the RBD; KubeVirt runStrategy=RerunOnFailure restarts it).
#
# Prerequisites (bring the stack up first):
#   INSTALL_ROOK=1 INSTALL_MEDIK8S=1 hack/install-stack.sh
#   helm upgrade --install ectobase deploy/charts/ectobase \
#     --namespace ectobase-system --create-namespace \
#     --set tier1Failover.enabled=true
#
# Usage:
#   hack/tier1-failover-e2e.sh          # run the node-kill reschedule test
#   hack/tier1-failover-e2e.sh --help   # show this help
#
# Env overrides:
#   NS         VM namespace (default default)
#   VM_NAME    VirtualMachine name (default tier1-vm)
#   TIMEOUT    reschedule wait, seconds (default 600)

NS="${NS:-default}"
VM_NAME="${VM_NAME:-tier1-vm}"
TIMEOUT="${TIMEOUT:-600}"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '3,22p' "$0"
  exit 0
fi

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== 1) wait for VMI ${VM_NAME} to be Running =="
kubectl -n "${NS}" wait "vmi/${VM_NAME}" --for=jsonpath='{.status.phase}'=Running --timeout="${TIMEOUT}s" \
  || fail "VMI ${VM_NAME} never reached Running (is the stack + a VM booted?)"

node="$(kubectl -n "${NS}" get vmi "${VM_NAME}" -o jsonpath='{.status.nodeName}')"
[ -n "${node}" ] || fail "could not read VMI node"
echo "   VMI is on node: ${node}"

echo "== 2) hard-kill the node (docker kill of the kind node container) =="
docker kill "${node}" || fail "failed to kill node ${node} (kind node container name == node name)"

echo "== 3) wait for the VMI to reschedule onto a DIFFERENT node =="
deadline=$(( $(date +%s) + TIMEOUT ))
while :; do
  cur="$(kubectl -n "${NS}" get vmi "${VM_NAME}" -o jsonpath='{.status.nodeName}' 2>/dev/null || true)"
  phase="$(kubectl -n "${NS}" get vmi "${VM_NAME}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ -n "${cur}" ] && [ "${cur}" != "${node}" ] && [ "${phase}" = "Running" ]; then
    echo "PASS: VMI rescheduled ${node} -> ${cur} and is Running"
    exit 0
  fi
  [ "$(date +%s)" -ge "${deadline}" ] && fail "VMI did not reschedule off ${node} within ${TIMEOUT}s (phase=${phase}, node=${cur})"
  sleep 10
done
