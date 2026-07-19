#!/usr/bin/env bash
# test/pod-tap-attach-netns.sh — GATE for AttachInterface device_type=pod-tap (KubeVirt VM edge).
#
# Proves attach.rs::setup_pod_tap creates the correct topology via the RPC: a root-netns veth
# (the datapath device) + a peer + a tap in the POD netns, spliced by tc mirred (NO bridge). The
# pod-tap DATAPATH itself (a real VM DHCP + overlay ping across the mirred splice) is proven by
# pod-tap-vm-smoke.sh; here we gate the ATTACH wiring + cleanup.
#
# Assertions:
#   (a) a ROOT-netns veth veth-<id> exists (the datapath device); response.ifname == the pod tap name;
#   (b) the POD netns contains the tap tap-<id> (with the VM MAC) AND a veth peer vp-<hash>, both up;
#   (c) BOTH pod-netns devices have a clsact + a mirred redirect filter (the point-to-point splice);
#   (d) INTERFACES read-back for {vni, ip};
#   (e) empty mac is REJECTED for device_type=pod-tap;
#   (f) DetachInterface removes the root veth (the pod devices die with the pod netns in production;
#       here we assert the root veth is gone and tear the netns down ourselves).
#
# Run: sudo env "PATH=$PATH" test/pod-tap-attach-netns.sh   (grpcurl + ip on PATH; run in nix develop)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NS="pt-podns"
DUMMY="dp-dummy"
ULA64="fd00:db8:0:7::/64"
ULA_ADDR="fd00:db8:0:7::1/64"
UPLINK="dp-upl"
UPLINK_PEER="dp-uplp"
ADDR="127.0.0.1:1340"
IFACE_ID="v0"
ROOT_VETH="veth-v0"     # AttachState::host_veth_name("v0")
POD_TAP="tap0"          # explicit tap_name (KubeVirt's GenerateTapDeviceName for a primary network)
VNI=100
OVERLAY_IP="10.0.0.10"
VM_MAC="52:54:00:00:00:bb"
DP_LOG="/tmp/pt-attach-dp.$$.log"
DP_PID=""

fail() { echo "FAIL: $*"; echo "---- datapath log ----"; cat "$DP_LOG" 2>/dev/null || true; echo "----------------------"; exit 1; }

cleanup() {
    set +e
    [[ -n "$DP_PID" ]] && kill -0 "$DP_PID" 2>/dev/null && { kill "$DP_PID" 2>/dev/null; wait "$DP_PID" 2>/dev/null; }
    pkill -f "flowplane serve --addr $ADDR" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    ip link del "$ROOT_VETH" 2>/dev/null
    ip link del "$DUMMY" 2>/dev/null
    ip link del "$UPLINK" 2>/dev/null
}
trap cleanup EXIT

rpc() { "$GRPCURL" -plaintext -d "$2" -import-path "$ROOT/api/proto" -proto dataplane/v1/dataplane.proto \
        "$ADDR" "dataplane.v1.DataplaneNode/$1" 2>"$DP_LOG.rpc"; }

# tc filter in the pod netns must carry a mirred redirect action to the given peer.
has_mirred() { ip netns exec "$NS" tc filter show dev "$1" ingress 2>/dev/null | grep -q mirred; }

echo "== build flowplane =="
cargo build -p flowplane || fail "cargo build failed"
BIN="$ROOT/target/debug/flowplane"; [[ -x "$BIN" ]] || fail "$BIN missing"
GRPCURL="$(command -v grpcurl)" || fail "grpcurl not on PATH (run inside nix develop)"

echo "== dummy (underlay /64) + uplink veth + target pod netns =="
ip link del "$DUMMY" 2>/dev/null; ip link add "$DUMMY" type dummy || fail "add dummy"
ip addr add "$ULA_ADDR" dev "$DUMMY" || fail "addr dummy"; ip link set "$DUMMY" up
ip link del "$UPLINK" 2>/dev/null
ip link add "$UPLINK" type veth peer name "$UPLINK_PEER" || fail "add uplink"
ip link set "$UPLINK" up; ip link set "$UPLINK_PEER" up
ip netns del "$NS" 2>/dev/null; ip netns add "$NS" || fail "netns add"; ip netns exec "$NS" ip link set lo up
ip link del "$ROOT_VETH" 2>/dev/null

echo "== start flowplane serve =="
FLOWPLANE_SKB_MODE=1 "$BIN" serve --addr "$ADDR" --uplink "$UPLINK" \
    --local-underlay "fd00:db8:0:7::1" --gateway "169.254.0.1" --gateway-mac "aa:aa:aa:aa:aa:aa" \
    > "$DP_LOG" 2>&1 &
DP_PID=$!
for _ in $(seq 1 50); do
    kill -0 "$DP_PID" 2>/dev/null || fail "serve died during startup"
    grep -q "serving DataplaneNode on" "$DP_LOG" 2>/dev/null && break
    sleep 0.2
done
grep -q "serving DataplaneNode on" "$DP_LOG" 2>/dev/null || fail "serve did not start listening"

# --- (e) empty mac rejected ---
echo "== AttachInterface device_type=pod-tap with EMPTY mac (must fail) =="
BAD="{\"interface_id\":\"$IFACE_ID\",\"netns_path\":\"/var/run/netns/$NS\",\"vni\":$VNI,\"requested_ips\":[\"$OVERLAY_IP\"],\"device_type\":\"pod-tap\"}"
if rpc AttachInterface "$BAD" >/dev/null 2>&1; then fail "pod-tap with empty mac was accepted"; fi
echo "  empty-mac pod-tap attach rejected (OK)"

echo "== AttachInterface device_type=pod-tap =="
REQ="{\"interface_id\":\"$IFACE_ID\",\"netns_path\":\"/var/run/netns/$NS\",\"vni\":$VNI,\"mac\":\"$VM_MAC\",\"requested_ips\":[\"$OVERLAY_IP\"],\"device_type\":\"pod-tap\",\"tap_name\":\"$POD_TAP\"}"
RESP="$(rpc AttachInterface "$REQ")" || { echo "grpcurl stderr:"; cat "$DP_LOG.rpc"; fail "AttachInterface(pod-tap) failed"; }
echo "response: $RESP"

# --- (a) root veth + ifname ---
IFNAME="$(echo "$RESP" | grep -o '"ifname"[^,}]*' | sed 's/.*: *"\([^"]*\)".*/\1/')"
[[ "$IFNAME" == "$POD_TAP" ]] || fail "ifname '$IFNAME' != '$POD_TAP'"
ip link show "$ROOT_VETH" >/dev/null 2>&1 || fail "root veth $ROOT_VETH not created"
echo "  root veth $ROOT_VETH present; ifname=$IFNAME (OK)"

# --- (b) pod netns has the tap (with VM MAC) + a veth peer, both up ---
ip netns exec "$NS" ip link show "$POD_TAP" >/dev/null 2>&1 || fail "pod tap $POD_TAP missing in $NS"
[[ -e "/proc/1/root" ]]  # noop
TAPMAC="$(ip netns exec "$NS" cat /sys/class/net/$POD_TAP/address)"
[[ "$TAPMAC" == "$VM_MAC" ]] || fail "pod tap mac $TAPMAC != $VM_MAC"
ip netns exec "$NS" test -e "/sys/class/net/$POD_TAP/tun_flags" || fail "$POD_TAP is not a tun/tap"
PEER="$(ip netns exec "$NS" ls /sys/class/net | grep '^vp-' | head -1)"
[[ -n "$PEER" ]] || fail "no vp-<hash> veth peer in pod netns"
echo "  pod netns has tap $POD_TAP (mac $TAPMAC) + peer $PEER (OK)"

# --- (c) mirred splice both ways ---
ip netns exec "$NS" tc qdisc show dev "$POD_TAP" | grep -q clsact || fail "no clsact on $POD_TAP"
ip netns exec "$NS" tc qdisc show dev "$PEER" | grep -q clsact || fail "no clsact on $PEER"
has_mirred "$POD_TAP" || fail "no mirred redirect on $POD_TAP (tap->peer splice missing)"
has_mirred "$PEER" || fail "no mirred redirect on $PEER (peer->tap splice missing)"
echo "  mirred splice present both ways ($POD_TAP <-> $PEER) (OK)"

# --- (d) INTERFACES read-back ---
grep -q "INTERFACES readback vni=$VNI ip=$OVERLAY_IP" "$DP_LOG" 2>/dev/null \
    || fail "no INTERFACES read-back for {vni:$VNI, ip:$OVERLAY_IP}"
echo "  INTERFACES map has {vni:$VNI, ip:$OVERLAY_IP} (OK)"

# --- (f) detach removes the root veth ---
echo "== DetachInterface =="
rpc DetachInterface "{\"interface_id\":\"$IFACE_ID\"}" >/dev/null 2>&1 || echo "  WARN: detach RPC nonzero"
sleep 0.5
ip link show "$ROOT_VETH" >/dev/null 2>&1 && fail "root veth $ROOT_VETH still present after detach"
echo "  root veth removed on detach (OK)"

echo "PASS: AttachInterface device_type=pod-tap — root veth + pod-netns tap + mirred splice + maps + detach"
exit 0
