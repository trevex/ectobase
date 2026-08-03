#!/usr/bin/env bash
set -euo pipefail
# Minimal Rook Ceph for dev/kind — single-mon, replica-1, NO redundancy. NOT for production.
#
# Deploys the Rook operator (pinned release), a minimal CephCluster (1 mon, 1 mgr,
# a PVC-backed OSD on the kind default StorageClass so it needs no raw block device),
# a replica-1 CephBlockPool (replicapool), and a `ceph-rbd` StorageClass wired to the
# rook-ceph.rbd.csi.ceph.com provisioner. This is the storage backend the Ceph-volume
# chain (Volume -> CompiledVolumeAttachment -> CDI DataVolume(RBD PVC)) materializes onto.
#
# Usage:
#   hack/rook-ceph-up.sh          # apply operator + minimal cluster/pool/StorageClass
#   hack/rook-ceph-up.sh --help   # show this help
#
# Env overrides:
#   ROOK_VERSION   Rook release tag (default v1.15.5)
#   ROOK_NAMESPACE Namespace for Rook + Ceph (default rook-ceph)
#   OSD_PVC_SIZE   Size of the PVC-backed OSD (default 20Gi)
#   OSD_SC         StorageClass backing the OSD PVC (default standard, kind's default)
#
# Caveat: the PVC-backed OSD needs a working default StorageClass in the host cluster
# (kind ships `standard` via local-path). replica-1 + requireSafeReplicaSize=false means
# a single OSD loss is data loss — dev only.

ROOK_VERSION="${ROOK_VERSION:-v1.15.5}"
ROOK_NAMESPACE="${ROOK_NAMESPACE:-rook-ceph}"
OSD_PVC_SIZE="${OSD_PVC_SIZE:-20Gi}"
OSD_SC="${OSD_SC:-standard}"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '3,30p' "$0"
  exit 0
fi

RAW="https://raw.githubusercontent.com/rook/rook/${ROOK_VERSION}/deploy/examples"

echo "== Rook operator ${ROOK_VERSION} (crds, common, operator) =="
kubectl apply -f "${RAW}/crds.yaml"
kubectl apply -f "${RAW}/common.yaml"
kubectl apply -f "${RAW}/operator.yaml"

echo "== waiting for the rook-ceph-operator deployment =="
kubectl -n "${ROOK_NAMESPACE}" rollout status deploy/rook-ceph-operator --timeout=5m

echo "== minimal CephCluster + CephBlockPool + ceph-rbd StorageClass =="
kubectl apply -f - <<EOF
apiVersion: ceph.rook.io/v1
kind: CephCluster
metadata:
  name: rook-ceph
  namespace: ${ROOK_NAMESPACE}
spec:
  dataDirHostPath: /var/lib/rook
  mon:
    count: 1
    allowMultiplePerNode: true
  mgr:
    count: 1
  dashboard:
    enabled: false
  cephVersion:
    image: quay.io/ceph/ceph:v18.2.4
    allowUnsupported: true
  storage:
    useAllNodes: false
    useAllDevices: false
    # PVC-backed OSD so this runs on kind with no raw block device: one OSD carved
    # from a PVC on the host cluster's default StorageClass.
    storageClassDeviceSets:
      - name: set1
        count: 1
        portable: false
        tuneDeviceClass: true
        encrypted: false
        volumeClaimTemplates:
          - metadata:
              name: data
            spec:
              accessModes:
                - ReadWriteOnce
              resources:
                requests:
                  storage: ${OSD_PVC_SIZE}
              storageClassName: ${OSD_SC}
              volumeMode: Block
---
apiVersion: ceph.rook.io/v1
kind: CephBlockPool
metadata:
  name: replicapool
  namespace: ${ROOK_NAMESPACE}
spec:
  failureDomain: osd
  replicated:
    size: 1
    requireSafeReplicaSize: false
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ceph-rbd
provisioner: rook-ceph.rbd.csi.ceph.com
parameters:
  clusterID: ${ROOK_NAMESPACE}
  pool: replicapool
  imageFormat: "2"
  imageFeatures: layering
  csi.storage.k8s.io/provisioner-secret-name: rook-csi-rbd-provisioner
  csi.storage.k8s.io/provisioner-secret-namespace: ${ROOK_NAMESPACE}
  csi.storage.k8s.io/controller-expand-secret-name: rook-csi-rbd-provisioner
  csi.storage.k8s.io/controller-expand-secret-namespace: ${ROOK_NAMESPACE}
  csi.storage.k8s.io/node-secret-name: rook-csi-rbd-node
  csi.storage.k8s.io/node-secret-namespace: ${ROOK_NAMESPACE}
  csi.storage.k8s.io/fstype: ext4
allowVolumeExpansion: true
reclaimPolicy: Delete
EOF

echo "== applied. The CephCluster may take several minutes to reach HEALTH_OK. =="
echo "   watch: kubectl -n ${ROOK_NAMESPACE} get cephcluster,cephblockpool,pods"
