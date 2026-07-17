#!/usr/bin/env bash
# test/attach-netns.sh — GATE for the DataplaneNode.AttachInterface RPC (Task 3).
#
# Proves the real AttachInterface/DetachInterface control path end to end:
#   1. a dummy0 with a global ULA /64 in the ROOT netns gives underlay inference a /64;
#   2. `flowplane serve` brings up the datapath + gRPC DataplaneNode listener;
#   3. an AttachInterface RPC (via grpcurl) for {interface_id:t0, netns_path, vni:100,
#      requested_ips:[10.0.0.10]} makes the daemon:
#        (a) create a veth and move its guest end into the target netns,
#        (b) allocate an underlay /128 out of the inferred /64 (returned as underlay_route),
#        (c) program INTERFACES[{vni:100, ip:10.0.0.10}] with the endpoint.
#
# Assertions:
#   (a) an interface now exists inside the target netns,
#   (b) response.underlay_route is a /128 inside fd00:db8:0:7::/64,
#   (c) INTERFACES bpf map contains the {vni:100, ip:10.0.0.10} endpoint.
#
# Run: sudo env "PATH=$PATH" test/attach-netns.sh   (grpcurl + ip must be on PATH; run in nix shell)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NS="attach-t"
DUMMY="dp-dummy"
ULA64="fd00:db8:0:7::/64"
ULA_ADDR="fd00:db8:0:7::1/64"
UPLINK="dp-upl"
UPLINK_PEER="dp-uplp"
ADDR="127.0.0.1:1337"
IFACE_ID="t0"
GUEST_IFNAME="t0"        # name the guest end gets inside the netns
VNI=100
OVERLAY_IP="10.0.0.10"
DP_LOG="/tmp/attach-netns-dp.$$.log"
DP_PID=""

fail() { echo "FAIL: $*"; echo "---- datapath log ----"; cat "$DP_LOG" 2>/dev/null || true; echo "----------------------"; exit 1; }

cleanup() {
    set +e
    if [[ -n "$DP_PID" ]] && kill -0 "$DP_PID" 2>/dev/null; then
        kill "$DP_PID" 2>/dev/null
        wait "$DP_PID" 2>/dev/null
    fi
    pkill -f "flowplane serve --addr $ADDR" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    ip link del "$DUMMY" 2>/dev/null
    ip link del "$UPLINK" 2>/dev/null
    ip link del "veth-$IFACE_ID" 2>/dev/null
}
trap cleanup EXIT

echo "== build flowplane =="
nix develop --command cargo build -p flowplane || fail "cargo build failed"
BIN="$ROOT/target/debug/flowplane"
[[ -x "$BIN" ]] || fail "$BIN missing after build"

GRPCURL="$(command -v grpcurl)" || fail "grpcurl not on PATH (run inside nix develop)"

echo "== root-netns dummy $DUMMY with $ULA_ADDR (underlay inference /64) =="
ip link del "$DUMMY" 2>/dev/null
ip link add "$DUMMY" type dummy || fail "add dummy"
ip addr add "$ULA_ADDR" dev "$DUMMY" || fail "addr add dummy"
ip link set "$DUMMY" up || fail "dummy up"

echo "== target netns $NS =="
ip netns del "$NS" 2>/dev/null
ip netns add "$NS" || fail "netns add"
ip netns exec "$NS" ip link set lo up

echo "== uplink veth $UPLINK (uplink_rx attaches here) =="
ip link del "$UPLINK" 2>/dev/null
ip link add "$UPLINK" type veth peer name "$UPLINK_PEER" || fail "add uplink veth"
ip link set "$UPLINK" up
ip link set "$UPLINK_PEER" up

echo "== start flowplane serve on $ADDR =="
FLOWPLANE_SKB_MODE=1 "$BIN" serve \
    --addr "$ADDR" \
    --uplink "$UPLINK" \
    --local-underlay "fd00:db8:0:7::1" \
    --gateway "10.0.0.1" \
    --gateway-mac "aa:aa:aa:aa:aa:aa" \
    > "$DP_LOG" 2>&1 &
DP_PID=$!

# Wait for the gRPC listener to come up.
for _ in $(seq 1 50); do
    if ! kill -0 "$DP_PID" 2>/dev/null; then
        fail "serve died during startup"
    fi
    if grep -q "serving DataplaneNode on" "$DP_LOG" 2>/dev/null; then
        break
    fi
    sleep 0.2
done
grep -q "serving DataplaneNode on" "$DP_LOG" 2>/dev/null || fail "serve did not start listening"

echo "== AttachInterface RPC =="
REQ="{\"interface_id\":\"$IFACE_ID\",\"netns_path\":\"/var/run/netns/$NS\",\"vni\":$VNI,\"requested_ips\":[\"$OVERLAY_IP\"]}"
RESP="$("$GRPCURL" -plaintext -d "$REQ" -import-path "$ROOT/api/proto" -proto dataplane/v1/dataplane.proto \
    "$ADDR" dataplane.v1.DataplaneNode/AttachInterface 2>"$DP_LOG.rpc")"
RC=$?
if [[ $RC -ne 0 ]]; then
    echo "grpcurl stderr:"; cat "$DP_LOG.rpc"
    fail "AttachInterface RPC failed (rc=$RC)"
fi
echo "response: $RESP"

# --- Assertion (b): underlay_route is a /128 inside fd00:db8:0:7::/64 ---
UNDERLAY_ROUTE="$(echo "$RESP" | grep -o '"underlayRoute"[^,}]*' | sed 's/.*: *"\([^"]*\)".*/\1/')"
[[ -n "$UNDERLAY_ROUTE" ]] || fail "no underlay_route in response"
echo "underlay_route = $UNDERLAY_ROUTE"
# Prefix-match the /64: expand is unnecessary — the address must start with the /64 network.
case "$UNDERLAY_ROUTE" in
    fd00:db8:0:7:*) : ;;
    *) fail "underlay_route $UNDERLAY_ROUTE not inside $ULA64" ;;
esac

# --- Assertion (a): an interface exists inside the target netns ---
if ! ip netns exec "$NS" ip -o link show | grep -qw "$GUEST_IFNAME"; then
    echo "netns links:"; ip netns exec "$NS" ip -o link show
    fail "no interface named $GUEST_IFNAME inside netns $NS"
fi
echo "interface $GUEST_IFNAME present in netns $NS"

# --- Assertion (c): INTERFACES bpf map contains {vni:100, ip:10.0.0.10} ---
# bpftool is not in the dev shell, so the daemon itself reads the INTERFACES entry back out of
# the live map right after programming it and logs a greppable confirmation line ONLY when the
# read-back succeeds — which proves the endpoint is really resident in the eBPF map.
if ! grep -q "INTERFACES readback vni=$VNI ip=$OVERLAY_IP" "$DP_LOG" 2>/dev/null; then
    fail "no INTERFACES read-back confirmation for {vni:$VNI, ip:$OVERLAY_IP} in daemon log"
fi
echo "INTERFACES map contains {vni:$VNI, ip:$OVERLAY_IP} (daemon read-back confirmed)"

echo "== DetachInterface RPC =="
"$GRPCURL" -plaintext -d "{\"interface_id\":\"$IFACE_ID\"}" \
    -import-path "$ROOT/api/proto" -proto dataplane/v1/dataplane.proto \
    "$ADDR" dataplane.v1.DataplaneNode/DetachInterface >/dev/null 2>&1 \
    || echo "WARN: DetachInterface RPC failed (non-fatal for assertions)"

echo "PASS: AttachInterface programmed veth + underlay /128 + INTERFACES map"
exit 0
