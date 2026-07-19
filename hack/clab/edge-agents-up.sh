#!/usr/bin/env bash
# hack/clab/edge-agents-up.sh — run a netplane AGENT on each WAN edge, brokered to the central k01
# cluster (like a compute cluster's agent). This is the edge-identity slice: each edge is a proper
# self-advertising node — its agent learns NEIGHBOR_NAT off the routebus (applyNat) and announces
# the external default route (DesiredExternalRoutes/A3), replacing the manual grpcurl programming.
#
# Prereq: the fabric is up with the netplane stack on k01, and each edge has a UNIQUE control-plane
# loopback (fd00:db8:0:9::{1,2}) distinct from the anycast datapath /128 (fd00:db8:0:9::e) — see
# hack/clab/vyos/edge{1,2}.boot — so replies from k01 return to the specific edge (not ECMP'd).
#   sudo -E env "PATH=$PATH" bash hack/clab/edge-agents-up.sh
set -euo pipefail

EDGE_UL="fd00:db8:0:9::e"          # anycast datapath underlay = the edge's identity for the records
REFLECTOR="[fd00:db8:0:1::1]:1338" # k01 reflector on the fabric loopback
APISERVER="https://[fd00:db8:0:1::1]:6443"
K1=$(mktemp)
kind get kubeconfig --name k01 > "$K1" 2>/dev/null

# k01-issued token so the edge agents can read the CRDs from k01's apiserver over the fabric.
kubectl --kubeconfig "$K1" -n ectobase-system create serviceaccount netplane-agent 2>/dev/null || true
TOKEN=$(kubectl --kubeconfig "$K1" -n ectobase-system create token netplane-agent --duration=8760h)
KC=$(mktemp)
cat > "$KC" <<EOF
apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "$APISERVER", insecure-skip-tls-verify: true}}]
users: [{name: u, user: {token: "$TOKEN"}}]
contexts: [{name: c, context: {cluster: c, user: u}}]
current-context: c
EOF

for e in edge1 edge2; do
  # Each edge's UNIQUE control-plane loopback (on VyOS dum0, see vyos/edge{1,2}.boot):
  # announced as the EDGE_UNDERLAY owner so replies pin to this edge (not the anycast /128).
  case "$e" in
    edge1) EDGE_LO="fd00:db8:0:9::1" ;;
    edge2) EDGE_LO="fd00:db8:0:9::2" ;;
  esac
  docker rm -f ${e}-agent 2>/dev/null || true
  docker run -d --name ${e}-agent --restart unless-stopped \
    --network "container:clab-xdp-ipv6-fabric-${e}" \
    -v "$KC":/kc:ro ghcr.io/trevex/ectobase/netplane:dev \
    agent --node-id "${e}" --underlay "$EDGE_UL" --reflector "$REFLECTOR" \
    --dataplane 127.0.0.1:1337 --edge-loopback "$EDGE_LO" --kubeconfig /kc >/dev/null
  echo "started ${e}-agent (node-id=${e}, underlay=${EDGE_UL}, edge-loopback=${EDGE_LO})"
done
echo "edge agents up: they learn NEIGHBOR_NAT off routebus + announce the external default (no grpcurl)"
