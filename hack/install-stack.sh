#!/usr/bin/env bash
set -euo pipefail
# Installs KubeVirt + Multus + CDI into the current-context cluster and registers
# the `dataplane` network binding (managedTap). Versions are pinned per the
# Phase B research docs; overridable via env.
KV="${KUBEVIRT_VERSION:-v1.5.0}"
CDI="${CDI_VERSION:-v1.61.0}"

# Multus (thick)
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset-thick.yml

# KubeVirt operator + CR
kubectl apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KV}/kubevirt-operator.yaml"
kubectl apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KV}/kubevirt-cr.yaml"
kubectl -n kubevirt wait kv/kubevirt --for=condition=Available --timeout=10m

# kind has no KVM: emulation. Register the `flowplane` network binding: domainAttachmentType=tap
# (our CNI creates the tap in the launcher netns; NOT managedTap, which builds KubeVirt's own bridge
# + hijacks DHCP) referencing our NAD (config/deploy/kubevirt-binding.yaml, applied with the stack).
# NetworkBindingPlugins gate enables the binding-plugin infra.
kubectl -n kubevirt patch kubevirt kubevirt --type=merge -p '{"spec":{"configuration":{
  "developerConfiguration":{"useEmulation":true,"featureGates":["NetworkBindingPlugins"]},
  "network":{"binding":{"flowplane":{
    "domainAttachmentType":"tap",
    "networkAttachmentDefinition":"ectobase-system/flowplane"}}}}}}'

# CDI
kubectl apply -f "https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI}/cdi-operator.yaml"
kubectl apply -f "https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI}/cdi-cr.yaml"
kubectl -n cdi wait cdi/cdi --for=condition=Available --timeout=10m

# Optional: minimal Rook Ceph storage backend (dev only). Off by default (slow on kind).
if [ "${INSTALL_ROOK:-}" = "1" ]; then
  bash "$(dirname "$0")/rook-ceph-up.sh"
fi

# Optional: medik8s NHC + SNR operators for Tier-1 autonomous local failover (dev only).
if [ "${INSTALL_MEDIK8S:-}" = "1" ]; then
  bash "$(dirname "$0")/medik8s-up.sh"
fi
