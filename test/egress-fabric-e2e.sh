#!/usr/bin/env bash
# test/egress-fabric-e2e.sh — North-South EGRESS e2e on the live containerlab fabric: an overlay
# VM reaches the REAL internet through its own hypervisor's distributed SNAT + a HA VyOS WAN edge.
#
# Proves the full D5-D8 chain: NATGateway controller (deterministic alloc) -> node agent programs
# local SNAT -> source encaps egress to the anycast edge -> edge uplink_rx decap -> VyOS -> clabwan
# host masquerade -> real internet -> return -> edge wan_rx re-encap to the owner -> uplink_rx decap
# -> reverse-conntrack -> VM. Also exercises the HA return via BOTH edges (multi-uplink uplink_rx).
#
# PREREQ: the fabric is up (hack/clab-up.sh) with the netplane stack loaded on k01 and the edge
# flowplane sidecars running. Needs root (docker/netns) + kubectl + the fullstorydev/grpcurl image.
#   sudo -E env "PATH=$PATH" bash test/egress-fabric-e2e.sh
#
# INTERIM: the EDGE side (NEIGHBOR_NAT + external default) is programmed via grpcurl here because
# the edge agents can't yet broker to k01 (the anycast edge source has no unique control-plane
# identity — the PublicVNI edge-identity follow-up). The SOURCE side is fully control-plane-driven.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

VNI=100; SRC_NODE="k01-worker"; SRC_IP="10.0.0.5"
NAT_POOL_IP="203.0.113.1"; PMIN=1024; PMAX=2047   # matches NATGateway alloc (portsPerSource 1024)
EDGE_UL="fd00:db8:0:9::e"; TARGET="1.1.1.1"
E1=clab-xdp-ipv6-fabric-edge1; E2=clab-xdp-ipv6-fabric-edge2
EX1=clab-xdp-ipv6-fabric-edge1-xdp   # the edge flowplane sidecar (clab-managed, shares E1's netns)
K1=$(mktemp)   # fresh, root-owned (this script runs under sudo)
PROTO="$ROOT/api/proto"
fail() { echo "FAIL: $*"; exit 1; }
kc() { kubectl --kubeconfig "$K1" "$@"; }
# grpc <node-container> <json> <Method>
grpc() { sudo docker run --rm --network "container:$1" -v "$PROTO":/proto:ro fullstorydev/grpcurl:latest \
  -plaintext -import-path /proto/dataplane/v1 -proto dataplane.proto -d "$2" 127.0.0.1:1337 "dataplane.v1.DataplaneNode/$3" 2>&1; }

echo "== [0] kubeconfig + stack up =="
sudo -E env "PATH=$PATH" kind get kubeconfig --name k01 > "$K1" 2>/dev/null
kc -n ectobase-system get ds flowplane >/dev/null 2>&1 || fail "netplane stack not deployed on k01 (apply config/crd + config/deploy)"

echo "== [1] VPC + NATGateway + source NIC (CRDs) =="
cat <<YAML | kc apply -f - >/dev/null || fail "apply CRs"
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: blue, namespace: default}
spec: {vni: $VNI}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: nic-src, namespace: default}
spec: {vpcRef: {name: blue}, ips: [$SRC_IP], nodeName: $SRC_NODE}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NATGateway
metadata: {name: egress-gw, namespace: default}
# No edgeUnderlay: egress is edge-flag driven now (the edge agents run --edge-loopback).
spec: {vpcRef: {name: blue}, publicIPs: [$NAT_POOL_IP], portsPerSource: 1024}
YAML
kc patch vpc blue --subresource=status --type=merge -p "{\"status\":{\"vni\":$VNI,\"state\":\"Ready\"}}" >/dev/null

echo "== [2] controller allocates (deterministic) =="
for _ in $(seq 1 30); do kc get natgateway egress-gw -o jsonpath='{.status.allocations}' 2>/dev/null | grep -q "$NAT_POOL_IP" && break; sleep 1; done
ALLOC=$(kc get natgateway egress-gw -o jsonpath='{.status.allocations}')
echo "$ALLOC" | grep -q "\"source\":\"$SRC_IP\"" || fail "no controller allocation for $SRC_IP ($ALLOC)"
echo "  alloc: $ALLOC"

echo "== [3] attach the source endpoint on $SRC_NODE =="
grpc "$SRC_NODE" '{"interface_id":"src"}' DetachInterface >/dev/null 2>&1 || true   # idempotent re-run
sudo docker exec "$SRC_NODE" ip netns add src 2>/dev/null || true
OUT=$(grpc "$SRC_NODE" "{\"interface_id\":\"src\",\"netns_path\":\"/var/run/netns/src\",\"vni\":$VNI,\"requested_ips\":[\"$SRC_IP\"]}" AttachInterface)
UL=$(echo "$OUT" | grep -o 'fd00:[0-9a-f:]*' | head -1)
[ -n "$UL" ] || fail "attach failed: $OUT"
echo "  source underlay = $UL"
sudo docker exec "$SRC_NODE" sh -c "ip netns exec src ip addr add $SRC_IP/32 dev src 2>/dev/null; ip netns exec src ip route add 169.254.0.1/32 dev src 2>/dev/null; ip netns exec src ip route add default via 169.254.0.1 dev src 2>/dev/null"
kc patch networkinterface nic-src --subresource=status --type=merge -p "{\"status\":{\"vni\":$VNI,\"underlayRoute\":\"$UL\",\"state\":\"Ready\"}}" >/dev/null
kc -n ectobase-system rollout restart ds/netplane-agent >/dev/null 2>&1

echo "== [4] agent programs local SNAT (A2) =="
for _ in $(seq 1 40); do
  XW=$(sudo docker exec "$SRC_NODE" crictl ps 2>/dev/null | grep -i flowplane | awk '{print $1}' | head -1)
  sudo docker exec "$SRC_NODE" crictl logs "$XW" 2>&1 | grep -q "NAT source vni=$VNI src=$SRC_IP" && break; sleep 2
done
sudo docker exec "$SRC_NODE" crictl logs "$XW" 2>&1 | grep "NAT source vni=$VNI src=$SRC_IP" | tail -1 | sed 's/^/  /' || fail "agent did not program SNAT"

echo "== [5] WAN edge programmed by its BROKERED AGENTS (edge-identity slice; no grpcurl) =="
# Each edge runs a netplane agent brokered to k01 (unique per-edge loopback so replies return to
# the right edge). The edge agents self-advertise: applyNat learns the NEIGHBOR_NAT off routebus
# and DesiredExternalRoutes (A3) announces the external default -> the source installs it.
bash "$ROOT/hack/clab/edge-agents-up.sh" >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  ne=$(sudo docker logs "$EX1" 2>&1 | grep -c "NEIGHBOR_NAT add vni=$VNI nat_ip=$NAT_POOL_IP")
  ex=$(sudo docker exec "$SRC_NODE" crictl logs "$XW" 2>&1 | grep -c "prefix=0.0.0.0/0 -> nexthop=$EDGE_UL external=true")
  [ "${ne:-0}" -ge 1 ] && [ "${ex:-0}" -ge 1 ] && break; sleep 2
done
[ "${ne:-0}" -ge 1 ] || fail "edge agent did not learn NEIGHBOR_NAT off routebus"
[ "${ex:-0}" -ge 1 ] || fail "edge agent did not announce the external default route"
echo "  edge agents: NEIGHBOR_NAT learned + external default announced (via routebus)"

echo "== [6] stage busybox for ping =="
CID=$(sudo docker create busybox:musl 2>/dev/null); sudo docker cp "$CID":/bin/busybox /tmp/busybox-musl >/dev/null 2>&1; sudo docker rm "$CID" >/dev/null 2>&1
sudo docker cp /tmp/busybox-musl "$SRC_NODE":/busybox 2>/dev/null

# ping_via <edge-clabwan-ip> : force the nat_ip return via one edge, then ping the real internet.
ping_via() {
  sudo ip route replace 203.0.113.0/28 via "$1" dev clabwan
  sudo docker exec "$SRC_NODE" ip netns exec src /busybox ping -c 4 -W 3 "$TARGET" 2>&1 | grep -E "packets transmitted"
}

echo "== [7] EGRESS to the REAL internet, HA return via EACH edge (multi-uplink uplink_rx) =="
R1=$(ping_via 172.29.0.11); echo "  return via edge1: $R1"
R2=$(ping_via 172.29.0.12); echo "  return via edge2: $R2"
# restore ECMP
sudo ip route replace 203.0.113.0/28 nexthop via 172.29.0.11 dev clabwan nexthop via 172.29.0.12 dev clabwan

ok1=$(echo "$R1" | grep -oE '[0-9]+ packets received' | grep -oE '^[0-9]+'); ok1=${ok1:-0}
ok2=$(echo "$R2" | grep -oE '[0-9]+ packets received' | grep -oE '^[0-9]+'); ok2=${ok2:-0}
[ "$ok1" -ge 1 ] || fail "no reply on the return-via-edge1 path"
[ "$ok2" -ge 1 ] || fail "no reply on the return-via-edge2 path (multi-uplink uplink_rx?)"
echo "PASS: overlay VM $SRC_IP reached the real internet $TARGET via distributed SNAT + HA edge (return via BOTH edges)"
