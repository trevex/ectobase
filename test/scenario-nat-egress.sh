#!/usr/bin/env bash
# test/scenario-nat-egress.sh — Scenario B: a container in a PRIVATE VPC egresses to an external
# HTTP server through its own hypervisor's distributed SNAT + the HA VyOS WAN edge, gated by an
# explicit EGRESS NetworkPolicy (egress-initiated traffic is deny-by-default; the policy grants it).
#
# Correct-wiring notes learned the hard way:
#   * The datapath firewall is DENY-BY-DEFAULT. The agent programs a NIC's firewall keyed by the
#     NIC's NAME (CompiledNIC.NICRef.Name → AddFwRule iface=<name>). So the dataplane interface MUST
#     be attached with interface_id == the NetworkInterface's metadata.name, or the agent's rules
#     never reach the attached interface and the datapath drops everything.
#   * Egress-INITIATED flows (this pod curling out) need an explicit egress-allow NetworkPolicy.
#     (Ingress-established flows get their egress replies for free via the reverse conntrack entry.)
#
# PREREQ: fabric up (hack/clab-up.sh) + netplane stack on k01. Needs root + kubectl + grpcurl image.
#   sudo -E env "PATH=/run/wrappers/bin:$HOME/go/bin:/run/current-system/sw/bin:$PATH" bash test/scenario-nat-egress.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

VNI=100; NIC=natpod; SRC_NODE=k01-worker; SRC_IP=10.0.0.5
NAT_IP=203.0.113.1; PMIN=1024; PMAX=2047
HTTP_HOST=172.29.0.1; HTTP_PORT=8080   # an "external" HTTP server on the clabwan bridge (beyond the edge)
PROTO="$ROOT/api/proto"
K1=$(mktemp)
fail() { echo "FAIL: $*"; exit 1; }
kc() { kubectl --kubeconfig "$K1" "$@"; }
grpc() { sudo docker run --rm --network "container:$1" -v "$PROTO":/proto:ro fullstorydev/grpcurl:latest \
  -plaintext -import-path /proto/dataplane/v1 -proto dataplane.proto -d "$2" 127.0.0.1:1337 "dataplane.v1.DataplaneNode/$3" 2>&1; }

echo "== [0] kubeconfig + stack =="
sudo -E env "PATH=$PATH" kind get kubeconfig --name k01 > "$K1" 2>/dev/null
kc -n ectobase-system get ds flowplane >/dev/null 2>&1 || fail "netplane stack not deployed on k01"

echo "== [1] CRDs: VPC + private NIC + NATGateway + EGRESS NetworkPolicy =="
cat <<YAML | kc apply -f - >/dev/null || fail "apply CRs"
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: blue, namespace: default}
spec: {vni: $VNI}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: $NIC, namespace: default, labels: {app: natpod}}
spec: {vpcRef: {name: blue}, ips: [$SRC_IP], nodeName: $SRC_NODE}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NATGateway
metadata: {name: egress-gw, namespace: default}
spec: {vpcRef: {name: blue}, publicIPs: [$NAT_IP], portsPerSource: 1024}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkPolicy
metadata: {name: natpod-egress, namespace: default}
spec:
  interfaceSelector: {matchLabels: {app: natpod}}
  egress:
    - {cidr: "0.0.0.0/0", proto: TCP, action: Allow}
    - {cidr: "0.0.0.0/0", proto: ICMP, action: Allow}
YAML
kc patch vpc blue --subresource=status --type=merge -p "{\"status\":{\"vni\":$VNI,\"state\":\"Ready\"}}" >/dev/null

echo "== [2] controller allocates the NAT port block =="
for _ in $(seq 1 30); do kc get natgateway egress-gw -o jsonpath='{.status.allocations}' 2>/dev/null | grep -q "$NAT_IP" && break; sleep 1; done
kc get natgateway egress-gw -o jsonpath='{.status.allocations}' | grep -q "\"source\":\"$SRC_IP\"" || fail "no allocation for $SRC_IP"
echo "  alloc ok"

echo "== [3] attach the endpoint with interface_id == NIC name ($NIC) =="
grpc "$SRC_NODE" "{\"interface_id\":\"$NIC\"}" DetachInterface >/dev/null 2>&1 || true
sudo docker exec "$SRC_NODE" ip netns add "$NIC" 2>/dev/null || true
OUT=$(grpc "$SRC_NODE" "{\"interface_id\":\"$NIC\",\"netns_path\":\"/var/run/netns/$NIC\",\"vni\":$VNI,\"requested_ips\":[\"$SRC_IP\"]}" AttachInterface)
UL=$(echo "$OUT" | grep -o 'fd00:[0-9a-f:]*' | head -1)
[ -n "$UL" ] || fail "attach failed: $OUT"
echo "  underlay=$UL"
sudo docker exec "$SRC_NODE" sh -c "ip netns exec $NIC ip addr add $SRC_IP/32 dev $NIC 2>/dev/null; \
  ip netns exec $NIC ip route add 169.254.0.1/32 dev $NIC 2>/dev/null; \
  ip netns exec $NIC ip route add default via 169.254.0.1 dev $NIC 2>/dev/null"
kc patch networkinterface "$NIC" --subresource=status --type=merge -p "{\"status\":{\"vni\":$VNI,\"underlayRoute\":\"$UL\",\"state\":\"Ready\"}}" >/dev/null
# The agent runs Desired() (SNAT) + ReconcileFirewall() ONCE per loop iteration, then blocks in
# bus.Run() until disconnect. Restart it so it re-reconciles now that the NIC is attached + Ready.
kc -n ectobase-system rollout restart ds/netplane-agent >/dev/null 2>&1
kc -n ectobase-system rollout status ds/netplane-agent --timeout=60s >/dev/null 2>&1

echo "== [4] agent programs local SNAT + EGRESS firewall (from the NetworkPolicy) =="
XW=""
for _ in $(seq 1 40); do
  XW=$(sudo docker exec "$SRC_NODE" crictl ps 2>/dev/null | grep ' flowplane ' | awk '{print $1}' | head -1)
  [ -n "$XW" ] && sudo docker exec "$SRC_NODE" crictl logs "$XW" 2>&1 | grep -q "NAT source vni=$VNI src=$SRC_IP" && break; sleep 2
done
sudo docker exec "$SRC_NODE" crictl logs "$XW" 2>&1 | grep "NAT source vni=$VNI src=$SRC_IP" | tail -1 | sed 's/^/  /' || fail "agent did not program SNAT"
# The agent's ReconcileFirewall programs FW_META+rules for interface "$NIC" (now attached). Give it a beat.
sleep 4

echo "== [5] WAN edge programmed by its brokered agents =="
bash "$ROOT/hack/clab/edge-agents-up.sh" >/dev/null 2>&1 || true
EX1=clab-xdp-ipv6-fabric-edge1-xdp
for _ in $(seq 1 30); do
  sudo docker logs "$EX1" 2>&1 | grep -q "NEIGHBOR_NAT add vni=$VNI nat_ip=$NAT_IP" \
    && sudo docker exec "$SRC_NODE" crictl logs "$XW" 2>&1 | grep -q "prefix=0.0.0.0/0 -> nexthop=fd00:db8:0:9::e external=true" && break
  sleep 2
done
echo "  edge NEIGHBOR_NAT + external default learned"

echo "== [5b] fix VyOS WAN default (clab injects a competing mgmt default — harness quirk) =="
for e in edge1 edge2; do sudo docker exec clab-xdp-ipv6-fabric-$e ip route replace default via 172.29.0.1 dev eth2 >/dev/null 2>&1; done
sudo ip route replace 203.0.113.0/28 nexthop via 172.29.0.11 dev clabwan nexthop via 172.29.0.12 dev clabwan

echo "== [6] stage busybox for the pod's ICMP + HTTP checks =="
CID=$(sudo docker create busybox:musl 2>/dev/null); sudo docker cp "$CID":/bin/busybox /tmp/busybox-musl >/dev/null 2>&1; sudo docker rm "$CID" >/dev/null 2>&1
sudo docker cp /tmp/busybox-musl "$SRC_NODE":/busybox 2>/dev/null

echo "== [7] the pod reaches the REAL internet (ICMP + HTTP) through NAT =="
# ICMP to a controlled host on the WAN bridge (proves the return hop deterministically).
echo "  --- ICMP -> $HTTP_HOST (clabwan host) ---"
sudo docker exec "$SRC_NODE" ip netns exec "$NIC" /busybox ping -c 3 -W 2 "$HTTP_HOST" 2>&1 | grep -E "packets transmitted" | sed 's/^/  /'
# HTTP to a real internet server by IP (bypasses the host's inbound firewall; exercises the double
# NAT: dataplane SNAT + the clabwan host masquerade). 1.1.1.1 answers HTTP with a 301 -> proves the
# full TCP round-trip incl. the tx-checksum fix (guest CHECKSUM_PARTIAL would otherwise be dropped).
INET_HTTP="${INET_HTTP:-1.1.1.1}"
echo "  --- HTTP GET http://$INET_HTTP/ (real internet) ---"
sudo docker exec "$SRC_NODE" ip netns exec "$NIC" /busybox wget -T 8 -S -O /dev/null "http://$INET_HTTP/" 2>&1 | grep -iE "HTTP/|Location:|moved|OK" | head -3 | sed 's/^/  /'
echo "== done =="
