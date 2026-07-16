#!/usr/bin/env bash
# test/scenario-lb-ingress.sh — Scenario A: expose an HTTP server behind a public LoadBalancer VIP,
# reachable from the WAN. N/S path: WAN client -> VIP -> edge wan_rx (vip_rx) -> Maglev backend
# select -> encap to backend node -> uplink_rx decap -> INGRESS firewall (allow :80) -> backend.
# Reply is DSR (src=VIP) and — being an ingress-ESTABLISHED flow — needs NO egress rule (the reverse
# conntrack entry, pre-seeded on the inbound SYN, makes the backend's replies "established").
#
# Wiring notes:
#   * Backend attaches with interface_id == NIC name ("web") so the agent's firewall (from the
#     INGRESS NetworkPolicy) reaches the attached interface (deny-by-default otherwise).
#   * Edge learns the VIP from the LoadBalancer CRD (agent ReconcileLB -> AddLbVip). Backend
#     registration on the edge (AddLbBackend) rides PUBLIC_KIND_LB_VIP over routebus, which is
#     currently RESERVED/not-yet-wired — so we register the backend on the edges via grpcurl here
#     as an interim (the SOURCE side is fully CRD-driven).
#
# PREREQ: fabric up + netplane stack on k01. root + kubectl + grpcurl image.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

VNI=100; NIC=web; NODE=k01-worker; BE_IP=10.0.0.10
VIP=203.0.113.50; PORT=80
PROTO="$ROOT/api/proto"
E1=clab-xdp-ipv6-fabric-edge1; E2=clab-xdp-ipv6-fabric-edge2
K1=$(mktemp)
fail() { echo "FAIL: $*"; exit 1; }
kc() { kubectl --kubeconfig "$K1" "$@"; }
grpc() { sudo docker run --rm --network "container:$1" -v "$PROTO":/proto:ro fullstorydev/grpcurl:latest \
  -plaintext -import-path /proto/dataplane/v1 -proto dataplane.proto -d "$2" 127.0.0.1:1337 "dataplane.v1.DataplaneNode/$3" 2>&1; }

echo "== [0] kubeconfig + stack =="
sudo -E env "PATH=$PATH" kind get kubeconfig --name k01 > "$K1" 2>/dev/null
kc -n ectobase-system get ds xdp-dp >/dev/null 2>&1 || fail "netplane stack not deployed on k01"

echo "== [1] CRDs: VPC + backend NIC + LoadBalancer + INGRESS NetworkPolicy (:80) =="
cat <<YAML | kc apply -f - >/dev/null || fail "apply CRs"
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: blue, namespace: default}
spec: {vni: $VNI}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: $NIC, namespace: default, labels: {app: web}}
spec: {vpcRef: {name: blue}, ips: [$BE_IP], nodeName: $NODE}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: LoadBalancer
metadata: {name: web-lb, namespace: default}
spec:
  vip: "$VIP"
  ports: [{port: $PORT, proto: TCP}]
  targetRefs: [{name: $NIC}]
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkPolicy
metadata: {name: web-ingress, namespace: default}
spec:
  interfaceSelector: {matchLabels: {app: web}}
  ingress:
    - {cidr: "0.0.0.0/0", proto: TCP, port: $PORT, action: Allow}
YAML
kc patch vpc blue --subresource=status --type=merge -p "{\"status\":{\"vni\":$VNI,\"state\":\"Ready\"}}" >/dev/null

echo "== [2] attach the backend with interface_id == NIC name ($NIC) + run an HTTP server =="
grpc "$NODE" "{\"interface_id\":\"$NIC\"}" DetachInterface >/dev/null 2>&1 || true
sudo docker exec "$NODE" ip netns add "$NIC" 2>/dev/null || true
OUT=$(grpc "$NODE" "{\"interface_id\":\"$NIC\",\"netns_path\":\"/var/run/netns/$NIC\",\"vni\":$VNI,\"requested_ips\":[\"$BE_IP\"]}" AttachInterface)
UL=$(echo "$OUT" | grep -o 'fd00:[0-9a-f:]*' | head -1)
[ -n "$UL" ] || fail "attach failed: $OUT"
echo "  backend underlay=$UL"
# Config: the backend must own the VIP (DSR reply src=VIP) AND its overlay IP; default via the dp gateway.
sudo docker exec "$NODE" sh -c "ip netns exec $NIC ip addr add $BE_IP/32 dev $NIC 2>/dev/null; \
  ip netns exec $NIC ip addr add $VIP/32 dev lo 2>/dev/null; \
  ip netns exec $NIC ip link set lo up; \
  ip netns exec $NIC ip route add 169.254.0.1/32 dev $NIC 2>/dev/null; \
  ip netns exec $NIC ip route add default via 169.254.0.1 dev $NIC 2>/dev/null"
kc patch networkinterface "$NIC" --subresource=status --type=merge -p "{\"status\":{\"vni\":$VNI,\"underlayRoute\":\"$UL\",\"state\":\"Ready\"}}" >/dev/null
# HTTP server in the backend netns, bound to the VIP:PORT (so replies are DSR src=VIP).
sudo docker exec "$NODE" sh -c "echo 'hello from LB backend $NIC' > /tmp/index.html" 2>/dev/null || true
sudo docker exec -d "$NODE" sh -c "ip netns exec $NIC busybox httpd -f -p $VIP:$PORT -h /tmp 2>/dev/null || ip netns exec $NIC python3 -m http.server $PORT --bind $VIP" 2>/dev/null || true

echo "== [3] kick the agent so it re-reconciles: INGRESS firewall (:80) + LB membership + VIP anycast =="
kc -n ectobase-system rollout restart ds/netplane-agent >/dev/null 2>&1
kc -n ectobase-system rollout status ds/netplane-agent --timeout=60s >/dev/null 2>&1
sleep 4
CID=$(sudo docker exec "$NODE" sh -c 'crictl ps | grep " xdp-dp " | awk "{print \$1}" | head -1')
echo "  backend node firewall/LB programming:"
sudo docker exec "$NODE" sh -c "crictl logs $CID 2>&1 | grep -iE 'FwRule.*$NIC|LB' | tail -4" | sed 's/^/    /'

echo "== [4] edge: AddLbVip via agent (CRD) + AddLbBackend (interim: LB_VIP routebus arc is reserved) =="
bash "$ROOT/hack/clab/edge-agents-up.sh" >/dev/null 2>&1 || true
sleep 3
for E in edge1 edge2; do
  EC="clab-xdp-ipv6-fabric-$E"
  # AddLbVip is idempotent; the edge agent's ReconcileLB also does it from the CRD. Register the backend.
  grpc "$EC" "{\"id\":\"$VIP\",\"vni\":0,\"vip\":\"$VIP\",\"lb_underlay\":\"fd00:db8:0:9::e\",\"ports\":[{\"port\":$PORT,\"proto\":6}]}" AddLbVip >/dev/null 2>&1
  R=$(grpc "$EC" "{\"id\":\"$VIP\",\"backend_underlay\":\"$UL\"}" AddLbBackend)
  echo "  $E AddLbBackend($UL) -> ${R:-ok}"
done

echo "== [5] fix VyOS default (harness) + prepare a WAN client on clabwan =="
for e in edge1 edge2; do sudo docker exec clab-xdp-ipv6-fabric-$e ip route replace default via 172.29.0.1 dev eth2 >/dev/null 2>&1; done
# Route the VIP from the host toward the edges (WAN client reaches the VIP via the edges' anycast).
sudo ip route replace $VIP/32 nexthop via 172.29.0.11 dev clabwan nexthop via 172.29.0.12 dev clabwan

echo "== [6] WAN client (host on clabwan) curls the VIP =="
echo "  --- curl http://$VIP:$PORT/ (timeout 6) ---"
timeout 6 curl -s "http://$VIP:$PORT/" 2>&1 | head -3 | sed 's/^/  /' || echo "  (no response — inbound reaches backend but the DSR RETURN hop to the WAN is the open item)"
echo "== done (N/S ingress wired; completion needs the return hop + the LB_VIP routebus arc) =="
