#!/usr/bin/env bash
# test/route-netns.sh — smoke test for DataplaneNode.AddRoute/WithdrawRoute.
# Attaches ONE endpoint, then programs a REMOTE /32 via AddRoute (nexthop = a bogus
# remote underlay). We can't ping a fake remote from here (that is the two-node e2e in
# test/e2e/routebus_test.go); this proves the RPC parses + programs the route (the
# datapath's own "ROUTE add …" confirmation line) and that WithdrawRoute round-trips.
#
# Run inside the flake devShell (provides cargo + grpcurl + ip); needs sudo for netns/eBPF:
#   nix develop --command sh -c 'sudo env "PATH=$PATH" bash test/route-netns.sh'
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
DUMMY="dp-dummy"; ULA_ADDR="fd00:db8:0:7::1/64"; ADDR="127.0.0.1:1337"; VNI=100
NS="rt-ep"; UPLINK="rt-uplink"; UPLINK_PEER="rt-uplink-peer"; LOG="$(mktemp)"
GW="169.254.0.1"; GW_MAC="02:00:00:00:00:01"
GRPCURL="$(command -v grpcurl)"
cleanup() {
  [ -n "${SERVE_PID:-}" ] && kill -9 "$SERVE_PID" 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  ip link del "$UPLINK" 2>/dev/null
  ip link del "$DUMMY" 2>/dev/null
  rm -f "$LOG"
}
trap cleanup EXIT

ip link add "$DUMMY" type dummy 2>/dev/null || true
ip link set "$DUMMY" up
ip -6 addr replace "$ULA_ADDR" dev "$DUMMY"
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up

ip link del "$UPLINK" 2>/dev/null
ip link add "$UPLINK" type veth peer name "$UPLINK_PEER"
ip link set "$UPLINK" up
ip link set "$UPLINK_PEER" up

cargo build -p flowplane 2>&1 | tail -1
FLOWPLANE_SKB_MODE=1 ./target/debug/flowplane serve \
  --addr "$ADDR" \
  --uplink "$UPLINK" \
  --local-underlay "fd00:db8:0:7::1" \
  --gateway "$GW" \
  --gateway-mac "$GW_MAC" \
  >"$LOG" 2>&1 &
SERVE_PID=$!

# Wait for the gRPC listener.
for _ in $(seq 1 50); do
  if ! kill -0 "$SERVE_PID" 2>/dev/null; then echo "FAIL: serve died during startup"; cat "$LOG"; exit 1; fi
  grep -q "serving DPDKironcore on" "$LOG" 2>/dev/null && break
  sleep 0.2
done
grep -q "serving DPDKironcore on" "$LOG" 2>/dev/null || { echo "FAIL: serve did not start listening"; cat "$LOG"; exit 1; }

grpc() { "$GRPCURL" -plaintext -import-path "$ROOT/api/proto" -proto dataplane/v1/dataplane.proto "$@"; }

echo "=== AttachInterface one endpoint ==="
grpc -d "{\"interface_id\":\"rt0\",\"netns_path\":\"/var/run/netns/$NS\",\"vni\":$VNI,\"requested_ips\":[\"10.0.0.1\"]}" \
  "$ADDR" dataplane.v1.DataplaneNode/AttachInterface
echo "=== AddRoute a remote /32 ==="
grpc -d "{\"vni\":$VNI,\"prefix\":\"10.0.0.2/32\",\"nexthop_underlay\":\"fd00:db8:0:2::a\"}" \
  "$ADDR" dataplane.v1.DataplaneNode/AddRoute
echo "=== WithdrawRoute it ==="
grpc -d "{\"vni\":$VNI,\"prefix\":\"10.0.0.2/32\"}" \
  "$ADDR" dataplane.v1.DataplaneNode/WithdrawRoute
echo "=== assertions ==="
grep -q "ROUTE add vni=$VNI prefix=10.0.0.2/32 -> nexthop=fd00:db8:0:2::a" "$LOG" \
  && echo "PASS: AddRoute programmed" || { echo "FAIL: no AddRoute log"; cat "$LOG"; exit 1; }
grep -q "ROUTE withdraw vni=$VNI prefix=10.0.0.2/32" "$LOG" \
  && echo "PASS: WithdrawRoute programmed" || { echo "FAIL: no WithdrawRoute log"; exit 1; }
