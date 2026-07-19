#!/bin/sh
# cni-install.sh — node installer for the flowplane CNI (runs as a DaemonSet).
#
# Drops the CNI binary onto the node and writes the SA-token kubeconfig the plugin
# uses (from the host netns) to read the pod + net.ectobase.dev CRDs. Multus invokes
# the binary by name (per the binding NAD), so no /etc/cni/net.d/*.conf drop-in is
# needed — only the binary + the kubeconfig. Then loops, refreshing the (rotating,
# projected) SA token into the kubeconfig so it never expires under the plugin.
set -eu

BIN_DIR="${CNI_BIN_DIR:-/host/opt/cni/bin}"
CONF_DIR="${CNI_CONF_DIR:-/host/etc/cni/net.d}"
KUBECONFIG_NAME="${KUBECONFIG_NAME:-dataplane-kubeconfig}"
SA=/var/run/secrets/kubernetes.io/serviceaccount

echo "cni-install: copying /flowplane-cni -> ${BIN_DIR}/flowplane-cni"
install -m 0755 /flowplane-cni "${BIN_DIR}/flowplane-cni"

# The CNI runs in the node host netns; the in-cluster API is reachable there via the
# kubernetes ClusterIP (kube-proxy programs it on the host). The kubeconfig is fully
# self-contained (CA + token inline) so it needs no files on the host besides itself.
API="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"
CA_B64="$(base64 -w0 < ${SA}/ca.crt 2>/dev/null || base64 < ${SA}/ca.crt | tr -d '\n')"

write_kubeconfig() {
  TOKEN="$(cat ${SA}/token)"
  tmp="${CONF_DIR}/.${KUBECONFIG_NAME}.tmp"
  cat > "${tmp}" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: local
    cluster:
      server: ${API}
      certificate-authority-data: ${CA_B64}
users:
  - name: cni
    user:
      token: ${TOKEN}
contexts:
  - name: cni
    context: {cluster: local, user: cni}
current-context: cni
EOF
  mv -f "${tmp}" "${CONF_DIR}/${KUBECONFIG_NAME}"
}

echo "cni-install: writing ${CONF_DIR}/${KUBECONFIG_NAME} (server ${API})"
write_kubeconfig
echo "cni-install: done; refreshing the SA token every 10m."
while :; do sleep 600; write_kubeconfig; done
