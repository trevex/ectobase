#!/usr/bin/env bash
# hack/multicluster-e2e.sh — deploy the route-distribution stack across TWO kind
# clusters on the shared containerlab IPv6 BGP fabric and prove CROSS-CLUSTER overlay
# connectivity.
#
# Topology (hack/clab/ipv6-fabric.clab.yml, already deployed by hack/clab-up.sh):
#   * k01 = CENTRAL cluster (2 nodes). Holds the reflector (on the control-plane node's
#     fabric loopback fd00:db8:0:1::1) and the VPC/NetworkInterface CRDs.
#   * k02 = COMPUTE cluster (1 node, /64 fd00:db8:0:3::1). Brokered to k01: its agent
#     peers k01's reflector AND reads the CRDs from k01's API, both over the fabric,
#     authenticating with a k01-issued ServiceAccount token.
#
# Endpoints: 10.0.0.1 on k01-control-plane, 10.0.0.3 on k02-control-plane (both in the
# same VPC vni 100). Success = 10.0.0.1 <-> 10.0.0.3 ping over the IP-in-IPv6 overlay,
# i.e. routes distributed by the central reflector to agents in a DIFFERENT cluster.
#
# Prereqs: the two-cluster fabric is up (sudo ./hack/clab-up.sh), and the images
# ghcr.io/trevex/ectobase/{flowplane,netplane}:dev are built. Run from the repo root.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PATH="$HOME/go/bin:$PATH"

REFLECTOR6="fd00:db8:0:1::1"            # k01 control-plane fabric loopback
APISERVER6="https://[${REFLECTOR6}]:6443"
K1=/tmp/k01.kubeconfig
K2=/tmp/k02.kubeconfig
GRPCURL_IMG="fullstorydev/grpcurl:latest"
PROTO_MNT="-v $(pwd)/api/proto:/proto:ro"
XDP=ghcr.io/trevex/ectobase/flowplane:dev
NETPLANE=ghcr.io/trevex/ectobase/netplane:dev

say() { echo -e "\n=== $* ==="; }

say "kubeconfigs"
sudo kind get kubeconfig --name k01 > "$K1"
sudo kind get kubeconfig --name k02 > "$K2"
kubectl --kubeconfig "$K1" get nodes -o name
kubectl --kubeconfig "$K2" get nodes -o name

say "load images into both clusters"
for c in k01 k02; do
  sudo kind load docker-image "$XDP" --name "$c" 2>&1 | tail -1
  sudo kind load docker-image "$NETPLANE" --name "$c" 2>&1 | tail -1
done

say "k01 (central): CRDs + full stack (reflector + flowplane + agent)"
kubectl --kubeconfig "$K1" apply -k config/crd 2>&1 | tail -1
kubectl --kubeconfig "$K1" apply -k config/deploy 2>&1 | grep -E 'created|configured|unchanged' | tail -6

say "mint a k01 token for the k02 agent (cross-cluster brokering)"
kubectl --kubeconfig "$K1" -n ectobase-system create serviceaccount netplane-agent 2>/dev/null || true
TOKEN=$(kubectl --kubeconfig "$K1" -n ectobase-system create token netplane-agent --duration=8760h)
[ -n "$TOKEN" ] && echo "token minted (${#TOKEN} chars)"

say "k02 (compute): namespace + flowplane DS + agent (points at k01 central over the fabric)"
kubectl --kubeconfig "$K2" apply -f config/deploy/namespace.yaml
kubectl --kubeconfig "$K2" apply -f config/deploy/rbac.yaml
kubectl --kubeconfig "$K2" apply -f config/deploy/flowplane.yaml
# k02 agent kubeconfig: explicit k01 token (not the local SA), server = k01 API on the fabric.
kubectl --kubeconfig "$K2" -n ectobase-system create configmap netplane-agent-kubeconfig \
  --from-literal=kubeconfig="apiVersion: v1
kind: Config
clusters:
  - name: central
    cluster:
      server: ${APISERVER6}
      insecure-skip-tls-verify: true
users:
  - name: sa
    user:
      token: ${TOKEN}
contexts:
  - name: central
    context: {cluster: central, user: sa}
current-context: central
" --dry-run=client -o yaml | kubectl --kubeconfig "$K2" apply -f -
# k02 agent DS: same image, reflector on the fabric, kubeconfig = the central one above.
sed -e 's#\(--reflector=\).*#\1[fd00:db8:0:1::1]:1338"#' config/deploy/agent.yaml \
  | kubectl --kubeconfig "$K2" apply -f -
kubectl --kubeconfig "$K2" -n ectobase-system rollout status ds/flowplane --timeout=90s 2>&1 | tail -1

say "VPC + NetworkInterfaces in k01 (central): 10.0.0.1 on k01-cp, 10.0.0.3 on k02-cp"
kubectl --kubeconfig "$K1" apply -f - <<'EOF'
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: blue, namespace: default}
spec: {vni: 100}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: nic-a, namespace: default}
spec: {vpcRef: {name: blue}, ips: ["10.0.0.1"], nodeName: k01-control-plane}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: nic-c, namespace: default}
spec: {vpcRef: {name: blue}, ips: ["10.0.0.3"], nodeName: k02-control-plane}
EOF
kubectl --kubeconfig "$K1" patch vpc blue --subresource=status --type=merge -p '{"status":{"vni":100,"state":"Ready"}}'

# attach_endpoint <node-container> <iface-id> <overlay-ip>  -> prints allocated underlay /128
attach_endpoint() {
  local node="$1" id="$2" ip="$3"
  sudo docker exec "$node" ip netns add "$id" 2>/dev/null || true
  local out ul
  out=$(sudo docker run --rm --network "container:$node" $PROTO_MNT "$GRPCURL_IMG" -plaintext \
    -import-path /proto/dataplane/v1 -proto dataplane.proto \
    -d "{\"interface_id\":\"$id\",\"netns_path\":\"/var/run/netns/$id\",\"vni\":100,\"requested_ips\":[\"$ip\"]}" \
    127.0.0.1:1337 dataplane.v1.DataplaneNode/AttachInterface 2>&1)
  ul=$(echo "$out" | grep -o 'fd00:[0-9a-f:]*' | head -1)
  # dpservice-model addressing inside the endpoint netns
  sudo docker exec "$node" sh -c "ip netns exec $id ip addr add $ip/32 dev $id; \
    ip netns exec $id ip route add 169.254.0.1/32 dev $id; \
    ip netns exec $id ip route add default via 169.254.0.1 dev $id" 2>/dev/null
  echo "$ul"
}

say "attach endpoints on both clusters' nodes"
UL_A=$(attach_endpoint k01-control-plane nic-a 10.0.0.1); echo "k01 nic-a underlay=$UL_A"
UL_C=$(attach_endpoint k02-control-plane nic-c 10.0.0.3); echo "k02 nic-c underlay=$UL_C"

say "record allocated underlay /128s in the CRD status (agent announces these)"
kubectl --kubeconfig "$K1" patch networkinterface nic-a --subresource=status --type=merge \
  -p "{\"status\":{\"vni\":100,\"underlayRoute\":\"$UL_A\",\"state\":\"Ready\"}}"
kubectl --kubeconfig "$K1" patch networkinterface nic-c --subresource=status --type=merge \
  -p "{\"status\":{\"vni\":100,\"underlayRoute\":\"$UL_C\",\"state\":\"Ready\"}}"
kubectl --kubeconfig "$K1" -n ectobase-system rollout restart ds/netplane-agent
kubectl --kubeconfig "$K2" -n ectobase-system rollout restart ds/netplane-agent
sleep 18

say "routes learned cross-cluster? (k02's flowplane should have 10.0.0.1 via k01's underlay)"
K2X=$(sudo docker exec k02-control-plane crictl ps --name flowplane -o json 2>/dev/null | grep -o '"id": "[a-f0-9]*"' | head -1 | cut -d'"' -f4)
sudo docker exec k02-control-plane crictl logs "$K2X" 2>&1 | grep -i ROUTE | tail -4

say "stage busybox (musl) for ping"
CID=$(sudo docker create busybox:musl); sudo docker cp "$CID":/bin/busybox /tmp/busybox-musl >/dev/null; sudo docker rm "$CID" >/dev/null
sudo docker cp /tmp/busybox-musl k01-control-plane:/busybox
sudo docker cp /tmp/busybox-musl k02-control-plane:/busybox

say "CROSS-CLUSTER OVERLAY PING: k01 nic-a 10.0.0.1  -->  k02 nic-c 10.0.0.3"
sudo docker exec k01-control-plane ip netns exec nic-a /busybox ping -c 3 -W 2 10.0.0.3 2>&1 | tail -5
say "reverse: k02 nic-c 10.0.0.3  -->  k01 nic-a 10.0.0.1"
sudo docker exec k02-control-plane ip netns exec nic-c /busybox ping -c 3 -W 2 10.0.0.1 2>&1 | tail -5
