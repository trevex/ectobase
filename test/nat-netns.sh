#!/usr/bin/env bash
# test/nat-netns.sh — smoke test for DataplaneNode.AddNatSource/WithdrawNatSource and
# AddNeighborNat/WithdrawNeighborNat. Attaches ONE source endpoint, programs egress SNAT
# for it via AddNatSource (a deterministic (nat_ip, port-block)), then programs + withdraws
# a NEIGHBOR_NAT return-to-owner entry. We can't drive real egress traffic from here (that is
# the fabric e2e in test/e2e/egress_test.go); this proves the RPCs parse + program the NAT
# datapath (the datapath's own "NAT source …" / "NEIGHBOR_NAT …" confirmation lines) and that
# the Withdraw* RPCs round-trip.
#
# Run inside the flake devShell (provides cargo + grpcurl + ip); needs sudo for netns/eBPF:
#   nix develop --command sh -c 'sudo env "PATH=$PATH" bash test/nat-netns.sh'
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
DUMMY="dp-dummy"; ULA_ADDR="fd00:db8:0:7::1/64"; ADDR="127.0.0.1:1337"; VNI=100
NS="nat-ep"; UPLINK="nat-uplink"; UPLINK_PEER="nat-uplink-peer"; LOG="$(mktemp)"
GW="169.254.0.1"; GW_MAC="02:00:00:00:00:01"
SRC_IP="10.0.0.1"; NAT_IP="203.0.113.10"; PMIN=1024; PMAX=2048
OWNER_UL="fd00:db8:0:2::a"
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
  grep -q "serving DataplaneNode on" "$LOG" 2>/dev/null && break
  sleep 0.2
done
grep -q "serving DataplaneNode on" "$LOG" 2>/dev/null || { echo "FAIL: serve did not start listening"; cat "$LOG"; exit 1; }

grpc() { "$GRPCURL" -plaintext -import-path "$ROOT/api/proto" -proto dataplane/v1/dataplane.proto "$@"; }

echo "=== AttachInterface one source endpoint ==="
grpc -d "{\"interface_id\":\"nat0\",\"netns_path\":\"/var/run/netns/$NS\",\"vni\":$VNI,\"requested_ips\":[\"$SRC_IP\"]}" \
  "$ADDR" dataplane.v1.DataplaneNode/AttachInterface
echo "=== AddNatSource (egress SNAT block) ==="
grpc -d "{\"vni\":$VNI,\"source_ip\":\"$SRC_IP\",\"nat_ip\":\"$NAT_IP\",\"port_min\":$PMIN,\"port_max\":$PMAX}" \
  "$ADDR" dataplane.v1.DataplaneNode/AddNatSource
echo "=== AddNeighborNat (return-to-owner) ==="
grpc -d "{\"vni\":$VNI,\"nat_ip\":\"$NAT_IP\",\"port_min\":$PMIN,\"port_max\":$PMAX,\"owner_underlay\":\"$OWNER_UL\"}" \
  "$ADDR" dataplane.v1.DataplaneNode/AddNeighborNat
echo "=== WithdrawNeighborNat ==="
grpc -d "{\"vni\":$VNI,\"nat_ip\":\"$NAT_IP\",\"port_min\":$PMIN,\"port_max\":$PMAX}" \
  "$ADDR" dataplane.v1.DataplaneNode/WithdrawNeighborNat
echo "=== WithdrawNatSource ==="
grpc -d "{\"vni\":$VNI,\"source_ip\":\"$SRC_IP\"}" \
  "$ADDR" dataplane.v1.DataplaneNode/WithdrawNatSource
echo "=== assertions ==="
grep -q "NAT source vni=$VNI src=$SRC_IP -> nat_ip=$NAT_IP ports=$PMIN..$PMAX" "$LOG" \
  && echo "PASS: AddNatSource programmed" || { echo "FAIL: no AddNatSource log"; cat "$LOG"; exit 1; }
grep -q "NEIGHBOR_NAT add vni=$VNI nat_ip=$NAT_IP ports=$PMIN..$PMAX -> owner=$OWNER_UL" "$LOG" \
  && echo "PASS: AddNeighborNat programmed" || { echo "FAIL: no AddNeighborNat log"; cat "$LOG"; exit 1; }
grep -q "NEIGHBOR_NAT withdraw vni=$VNI nat_ip=$NAT_IP ports=$PMIN..$PMAX" "$LOG" \
  && echo "PASS: WithdrawNeighborNat programmed" || { echo "FAIL: no WithdrawNeighborNat log"; exit 1; }
grep -q "NAT source withdraw vni=$VNI src=$SRC_IP" "$LOG" \
  && echo "PASS: WithdrawNatSource programmed" || { echo "FAIL: no WithdrawNatSource log"; exit 1; }
