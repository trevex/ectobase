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
# Env overrides:
#   KUBECTL              kubectl binary                (default kubectl)
#   CSI_ADDONS_VERSION   csi-addons release tag        (default v0.12.0)   [LIVE-ITERATE]
KUBECTL="${KUBECTL:-kubectl}"
CSI_ADDONS_VERSION="${CSI_ADDONS_VERSION:-v0.12.0}"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then sed -n '3,17p' "$0"; exit 0; fi

KUBECONFIG_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --kubeconfig) KUBECONFIG_ARG="--kubeconfig=${2:-}"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

kc() { $KUBECTL $KUBECONFIG_ARG "$@"; }

# kubernetes-csi-addons release assets: CRDs (incl. NetworkFence), rbac, controller.
# LIVE-ITERATE: exact asset filenames may differ by tag — verify against the release page.
REL="https://github.com/csi-addons/kubernetes-csi-addons/releases/download/${CSI_ADDONS_VERSION}"
echo "== csi-addons ${CSI_ADDONS_VERSION} (crds, rbac, controller) =="
kc apply -f "${REL}/crds.yaml"
kc apply -f "${REL}/rbac.yaml"
kc apply -f "${REL}/setup-controller.yaml"

echo "== csi-addons controller applied (NetworkFence CRD available) =="
