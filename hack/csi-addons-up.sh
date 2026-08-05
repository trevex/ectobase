#!/usr/bin/env bash
set -euo pipefail
# Install the csi-addons controller + NetworkFence CRD (the k01 storage-fence executor)
# at a pinned release into a target cluster. Dev-only, NOT production.
#
# csi-addons provides the NetworkFence CRD + controller that the Tier-2 fence gate drives
# to block a partitioned node's ceph RBD access (fence-before-failover). This installs the
# upstream CRDs + rbac + controller from the pinned kubernetes-csi-addons release assets.
#
# Usage:
#   hack/csi-addons-up.sh [--kubeconfig <kc>]
#   hack/csi-addons-up.sh --help
#
# It ALSO wires the csi-addons k8s-sidecar into the ceph-csi RBD provisioner (the actuator the
# controller dials to run `ceph osd blocklist`): the ceph-csi-rbd Helm chart ships the driver's
# csi-addons socket but NO sidecar, so without this the controller has no CSIAddonsNode to target
# and NetworkFence never leaves Pending.
#
# Usage:
#   hack/csi-addons-up.sh [--kubeconfig <kc>]
#   hack/csi-addons-up.sh --help
#
# Env overrides:
#   KUBECTL              kubectl binary                (default kubectl)
#   CSI_ADDONS_VERSION   csi-addons release tag        (default v0.12.0)   [LIVE-ITERATE]
#   CEPH_CSI_NS          ceph-csi namespace            (default ceph-csi)
#   CEPH_CSI_PROV        ceph-csi provisioner deploy   (default ceph-csi-rbd-provisioner)
#   CEPH_CSI_PROV_SA     ceph-csi provisioner SA       (default ceph-csi-rbd-provisioner)
KUBECTL="${KUBECTL:-kubectl}"
CSI_ADDONS_VERSION="${CSI_ADDONS_VERSION:-v0.12.0}"
CEPH_CSI_NS="${CEPH_CSI_NS:-ceph-csi}"
CEPH_CSI_PROV="${CEPH_CSI_PROV:-ceph-csi-rbd-provisioner}"
CEPH_CSI_PROV_SA="${CEPH_CSI_PROV_SA:-ceph-csi-rbd-provisioner}"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then sed -n '3,17p' "$0"; exit 0; fi

KUBECONFIG_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --kubeconfig) KUBECONFIG_ARG="--kubeconfig=${2:-}"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

kc() { $KUBECTL $KUBECONFIG_ARG "$@"; }

# kubernetes-csi-addons release assets: CRDs (incl. NetworkFence), rbac, controller. The controller
# runs in namespace csi-addons-system; rbac.yaml references it (ServiceAccount/RoleBindings) but does
# NOT create it, so create it first (else rbac apply -> "namespaces csi-addons-system not found").
REL="https://github.com/csi-addons/kubernetes-csi-addons/releases/download/${CSI_ADDONS_VERSION}"
echo "== csi-addons ${CSI_ADDONS_VERSION} (crds, rbac, controller) =="
kc apply -f "${REL}/crds.yaml"
kc create namespace csi-addons-system --dry-run=client -o yaml | kc apply -f -
kc apply -f "${REL}/rbac.yaml"
kc apply -f "${REL}/setup-controller.yaml"

echo "== csi-addons controller applied (NetworkFence CRD available) =="

# --- csi-addons k8s-sidecar into the ceph-csi RBD provisioner (the fence actuator) ---
# The sidecar (image tag == the csi-addons release) runs beside the driver, self-registers a
# CSIAddonsNode, and serves the NetworkFence RPC the controller dials to blocklist a /64 at ceph.
SIDECAR_IMAGE="quay.io/csiaddons/k8s-sidecar:${CSI_ADDONS_VERSION}"
if kc -n "$CEPH_CSI_NS" get deploy "$CEPH_CSI_PROV" >/dev/null 2>&1; then
  echo "== wiring csi-addons sidecar into ${CEPH_CSI_NS}/${CEPH_CSI_PROV} =="
  # RBAC for the provisioner SA the sidecar runs as: manage its CSIAddonsNode, read pods +
  # replicasets/deployments (to set the node's owner ref), and system:auth-delegator so it can
  # TokenReview the controller's mTLS identity (csi-addons enables auth by default).
  kc apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: ceph-csi-addons-sidecar }
rules:
  - apiGroups: ["csiaddons.openshift.io"]
    resources: ["csiaddonsnodes"]
    verbs: ["create","get","list","watch","update","patch","delete"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get","list"]
  - apiGroups: ["apps"]
    resources: ["replicasets","deployments","daemonsets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: ceph-csi-addons-sidecar }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: ceph-csi-addons-sidecar }
subjects:
  - { kind: ServiceAccount, name: ${CEPH_CSI_PROV_SA}, namespace: ${CEPH_CSI_NS} }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: ceph-csi-addons-authdelegator }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:auth-delegator }
subjects:
  - { kind: ServiceAccount, name: ${CEPH_CSI_PROV_SA}, namespace: ${CEPH_CSI_NS} }
EOF
  # Add the sidecar container (strategic-merge: idempotent by container name). It shares the driver's
  # socket-dir emptyDir (/csi) where ceph-csi exposes csi-addons.sock.
  kc -n "$CEPH_CSI_NS" patch deploy "$CEPH_CSI_PROV" --type=strategic -p "{
    \"spec\":{\"template\":{\"spec\":{\"containers\":[{
      \"name\":\"csi-addons\",
      \"image\":\"${SIDECAR_IMAGE}\",
      \"args\":[\"--node-id=\$(NODE_ID)\",\"--csi-addons-address=\$(CSIADDONS_ENDPOINT)\",\"--controller-port=9070\",\"--pod=\$(POD_NAME)\",\"--namespace=\$(POD_NAMESPACE)\",\"--pod-uid=\$(POD_UID)\"],
      \"ports\":[{\"containerPort\":9070}],
      \"env\":[
        {\"name\":\"NODE_ID\",\"valueFrom\":{\"fieldRef\":{\"fieldPath\":\"spec.nodeName\"}}},
        {\"name\":\"POD_NAME\",\"valueFrom\":{\"fieldRef\":{\"fieldPath\":\"metadata.name\"}}},
        {\"name\":\"POD_NAMESPACE\",\"valueFrom\":{\"fieldRef\":{\"fieldPath\":\"metadata.namespace\"}}},
        {\"name\":\"POD_UID\",\"valueFrom\":{\"fieldRef\":{\"fieldPath\":\"metadata.uid\"}}},
        {\"name\":\"CSIADDONS_ENDPOINT\",\"value\":\"unix:///csi/csi-addons.sock\"}
      ],
      \"volumeMounts\":[{\"name\":\"socket-dir\",\"mountPath\":\"/csi\"}]
    }]}}}
  }"
  kc -n "$CEPH_CSI_NS" rollout status deploy/"$CEPH_CSI_PROV" --timeout=120s
  echo "== csi-addons sidecar wired; a CSIAddonsNode should register (kubectl get csiaddonsnode -A) =="
else
  echo "WARN: ${CEPH_CSI_NS}/${CEPH_CSI_PROV} not found — run hack/ceph-external-up.sh first, then re-run this to wire the fence actuator" >&2
fi
