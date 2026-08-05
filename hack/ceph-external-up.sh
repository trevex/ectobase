#!/usr/bin/env bash
set -euo pipefail
# Install external ceph-csi (RBD) into a target cluster, wired to the shared clab ceph/demo
# fabric node via the connection params emitted by hack/ceph-demo-up.sh. Dev-only, NOT production.
#
# Creates: namespace `ceph-csi`, Secret `csi-rbd-secret`, ConfigMap `ceph-csi-config`
# (clusterID -> monitors map), the upstream ceph-csi RBD provisioner + nodeplugin + CSIDriver
# + rbac, and a `ceph-rbd` StorageClass wired to rbd.csi.ceph.com. Idempotent (kubectl apply).
#
# Usage:
#   hack/ceph-external-up.sh [--kubeconfig <kc>] [--params <file>]
#   hack/ceph-external-up.sh --help
#
# Params source: --params <file> (the ceph-demo-up.sh output) OR CEPH_* from the environment:
#   CEPH_FSID     ceph cluster fsid  -> StorageClass/config clusterID
#   CEPH_MON      v6 mon endpoint    -> ceph-csi-config monitors  (e.g. [fd00:db8:0:5::1]:6789)
#   CEPH_POOL     RBD pool           -> StorageClass pool         (default replicapool)
#   CEPH_RBD_KEY  client.rbd key     -> csi-rbd-secret userKey
#
# Env overrides:
#   KUBECTL             kubectl binary            (default kubectl)
#   CEPH_CSI_VERSION    ceph-csi release tag      (default v3.11.0)   [LIVE-ITERATE]
#   CSI_USER            csi rbd client user       (default rbd)
CEPH_CSI_VERSION="${CEPH_CSI_VERSION:-v3.11.0}"
KUBECTL="${KUBECTL:-kubectl}"
CSI_USER="${CSI_USER:-rbd}"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then sed -n '3,24p' "$0"; exit 0; fi

KUBECONFIG_ARG=""
PARAMS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --kubeconfig) KUBECONFIG_ARG="--kubeconfig=${2:-}"; shift 2 ;;
    --params)     PARAMS="${2:-}"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Load CEPH_* from the params file if given (else expect them in the environment).
if [ -n "$PARAMS" ]; then
  # shellcheck disable=SC1090
  set -a; . "$PARAMS"; set +a
fi

: "${CEPH_FSID:?CEPH_FSID required (from ceph-demo-up.sh --params or env)}"
: "${CEPH_MON:?CEPH_MON required (from ceph-demo-up.sh --params or env)}"
: "${CEPH_RBD_KEY:?CEPH_RBD_KEY required (from ceph-demo-up.sh --params or env)}"
CEPH_POOL="${CEPH_POOL:-replicapool}"

kc() { $KUBECTL $KUBECONFIG_ARG "$@"; }

echo "== namespace ceph-csi =="
kc create namespace ceph-csi --dry-run=client -o yaml | kc apply -f -

echo "== csi-rbd-secret + ceph-csi-config =="
kc apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: csi-rbd-secret
  namespace: ceph-csi
stringData:
  userID: ${CSI_USER}
  userKey: ${CEPH_RBD_KEY}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ceph-csi-config
  namespace: ceph-csi
data:
  config.json: |-
    [
      {
        "clusterID": "${CEPH_FSID}",
        "monitors": ["${CEPH_MON}"]
      }
    ]
EOF

# ceph-csi RBD upstream deploy manifests (provisioner + nodeplugin + CSIDriver + rbac).
# LIVE-ITERATE: exact filename set / IPv6 mon handling may need tuning against the pinned tag.
RAW="https://raw.githubusercontent.com/ceph/ceph-csi/${CEPH_CSI_VERSION}/deploy/rbd/kubernetes"
echo "== ceph-csi RBD deploy manifests ${CEPH_CSI_VERSION} =="
for m in \
  csidriver.yaml \
  csi-provisioner-rbac.yaml \
  csi-nodeplugin-rbac.yaml \
  csi-rbdplugin-provisioner.yaml \
  csi-rbdplugin.yaml \
; do
  # Upstream manifests default to namespace "default"; retarget to ceph-csi.
  kc apply -n ceph-csi -f "${RAW}/${m}"
done

echo "== ceph-rbd StorageClass =="
kc apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ceph-rbd
provisioner: rbd.csi.ceph.com
parameters:
  clusterID: ${CEPH_FSID}
  pool: ${CEPH_POOL}
  imageFeatures: layering
  csi.storage.k8s.io/provisioner-secret-name: csi-rbd-secret
  csi.storage.k8s.io/provisioner-secret-namespace: ceph-csi
  csi.storage.k8s.io/controller-expand-secret-name: csi-rbd-secret
  csi.storage.k8s.io/controller-expand-secret-namespace: ceph-csi
  csi.storage.k8s.io/node-secret-name: csi-rbd-secret
  csi.storage.k8s.io/node-secret-namespace: ceph-csi
  csi.storage.k8s.io/fstype: ext4
allowVolumeExpansion: true
reclaimPolicy: Delete
EOF

echo "== external ceph-csi (RBD) applied into namespace ceph-csi (clusterID ${CEPH_FSID}) =="
