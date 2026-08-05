#!/usr/bin/env bash
set -euo pipefail
# Install external ceph-csi (RBD) into a target cluster via the upstream Helm chart, wired to the
# shared clab ceph/demo fabric node using the params emitted by hack/ceph-demo-up.sh. Dev-only.
#
# Installs the ceph-csi-rbd chart (provisioner + nodeplugin + CSIDriver + rbac + the ceph-csi-config
# ConfigMap from csiConfig) into namespace `ceph-csi`, and — via chart values — the `csi-rbd-secret`
# Secret (userID/userKey) + a `ceph-rbd` StorageClass. Helm is the upstream-preferred install path;
# it namespaces everything cleanly (the raw manifests hardcode `namespace: default`) and lets us pin
# provisioner.replicaCount=1 for single-node kind (the chart default 3 + pod anti-affinity leaves 2
# replicas Pending forever on a one-node cluster). Idempotent (helm upgrade --install).
#
# Usage:
#   hack/ceph-external-up.sh [--kubeconfig <kc>] [--params <file>]
#   hack/ceph-external-up.sh --help
#
# Params source: --params <file> (the ceph-demo-up.sh output) OR CEPH_* from the environment:
#   CEPH_FSID     ceph cluster fsid  -> StorageClass/csiConfig clusterID
#   CEPH_MON      v6 mon endpoint    -> csiConfig monitors  (e.g. [fd00:db8:0:5::1]:3300, msgr-v2)
#   CEPH_POOL     RBD pool           -> StorageClass pool    (default replicapool)
#   CEPH_RBD_KEY  client.rbd key     -> csi-rbd-secret userKey
#
# Env overrides:
#   KUBECTL             kubectl binary            (default kubectl)
#   HELM                helm binary               (default helm)
#   CEPH_CSI_CHART_VER  ceph-csi-rbd chart tag    (default 3.11.0)
#   CSI_USER            csi rbd client user       (default rbd)
KUBECTL="${KUBECTL:-kubectl}"
HELM="${HELM:-helm}"
CEPH_CSI_CHART_VER="${CEPH_CSI_CHART_VER:-3.11.0}"
CSI_USER="${CSI_USER:-rbd}"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then sed -n '3,29p' "$0"; exit 0; fi

KC=""
PARAMS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --kubeconfig) KC="${2:-}"; shift 2 ;;
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

KCARG=""; [ -n "$KC" ] && KCARG="--kubeconfig=$KC"

echo "== ceph-csi-rbd Helm chart ${CEPH_CSI_CHART_VER} -> namespace ceph-csi (clusterID ${CEPH_FSID}) =="
$HELM $KCARG repo add ceph-csi https://ceph.github.io/csi-charts >/dev/null 2>&1 || true
$HELM $KCARG repo update ceph-csi >/dev/null 2>&1 || true

# The chart renders the ceph-csi-config ConfigMap from csiConfig, the csi-rbd-secret from secret.*,
# and a StorageClass from storageClass.*. The StorageClass secret refs default to secret.name in the
# release namespace, i.e. csi-rbd-secret / ceph-csi — which is exactly what the central failover
# controller's -csi-secret-name/-namespace point at.
VALUES="$(mktemp -t cephcsi-values.XXXXXX.yaml)"
trap 'rm -f "$VALUES"' EXIT
cat > "$VALUES" <<EOF
csiConfig:
  - clusterID: "${CEPH_FSID}"
    monitors:
      - "${CEPH_MON}"
provisioner:
  replicaCount: 1            # single-node kind: the chart default (3) leaves 2 replicas Pending
secret:
  create: true
  name: csi-rbd-secret
  userID: "${CSI_USER}"
  userKey: "${CEPH_RBD_KEY}"
storageClass:
  create: true
  name: ceph-rbd
  clusterID: "${CEPH_FSID}"
  pool: "${CEPH_POOL}"
  imageFeatures: "layering"
  # krbd (the kernel rbd client used at NodeStage/`rbd map`, e.g. by CDI import + VM attach) must be
  # told ms_mode to reach this msgr-v2-ONLY mon on :3300 — otherwise it tries legacy msgr1 and fails
  # "rbd: failed to get mon address (possible ms_mode mismatch)". prefer-crc negotiates v2 (crc, no
  # encryption) and is supported on modern kernels (>=5.11). librbd (provisioner) doesn't need this.
  mapOptions: "ms_mode=prefer-crc"
  mountOptions: []
  reclaimPolicy: Delete
  allowVolumeExpansion: true
  fstype: ext4
EOF

$HELM $KCARG upgrade --install ceph-csi-rbd ceph-csi/ceph-csi-rbd \
  --version "${CEPH_CSI_CHART_VER}" \
  --namespace ceph-csi --create-namespace \
  -f "$VALUES" --wait --timeout 5m

echo "== external ceph-csi (RBD) installed via Helm into namespace ceph-csi (clusterID ${CEPH_FSID}) =="
