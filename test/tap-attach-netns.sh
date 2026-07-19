#!/usr/bin/env bash
# test/tap-attach-netns.sh — GATE for AttachInterface with device_type=tap (VM edge wiring).
#
# The veth path is covered by attach-netns.sh; this proves the TAP path added for KubeVirt VMs:
# an AttachInterface RPC with {device_type:"tap", mac:<VM NIC MAC>} makes the daemon create a
# ROOT-netns tap (no netns move, no peer — symmetric with the container host-veth), set its MAC +
# MTU, attach tc_guest_tx, and program INTERFACES/UNDERLAY. The VM-on-tap DATAPATH itself (DHCP +
# overlay ping with a real guest) is proven separately by tap-vm-smoke.sh; here we gate the ATTACH
# wiring (setup_tap + Control::create_interface reuse + detach cleanup).
#
# Assertions:
#   (a) a ROOT-netns tap named tap-<id> exists with the requested MAC and is UP;
#   (b) response.ifname == that tap name; response.underlay_route is a /128 inside the inferred /64;
#   (c) tc_guest_tx is attached (clsact) on the tap;
#   (d) INTERFACES bpf map contains {vni, ip} (daemon read-back);
#   (e) an empty mac is REJECTED for device_type=tap (the VM MAC is required);
#   (f) DetachInterface removes the tap.
#
# Run: sudo env "PATH=$PATH" test/tap-attach-netns.sh   (grpcurl + ip on PATH; run in nix develop)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DUMMY="dp-dummy"
ULA64="fd00:db8:0:7::/64"
ULA_ADDR="fd00:db8:0:7::1/64"
UPLINK="dp-upl"
UPLINK_PEER="dp-uplp"
ADDR="127.0.0.1:1339"
IFACE_ID="v0"
TAP_NAME="tap-v0"        # AttachState::tap_name("v0")
VNI=100
OVERLAY_IP="10.0.0.10"
VM_MAC="52:54:00:00:00:aa"
DP_LOG="/tmp/tap-attach-dp.$$.log"
DP_PID=""

fail() { echo "FAIL: $*"; echo "---- datapath log ----"; cat "$DP_LOG" 2>/dev/null || true; echo "----------------------"; exit 1; }

cleanup() {
    set +e
    [[ -n "$DP_PID" ]] && kill -0 "$DP_PID" 2>/dev/null && { kill "$DP_PID" 2>/dev/null; wait "$DP_PID" 2>/dev/null; }
    pkill -f "flowplane serve --addr $ADDR" 2>/dev/null
    ip link del "$TAP_NAME" 2>/dev/null
    ip link del "$DUMMY" 2>/dev/null
    ip link del "$UPLINK" 2>/dev/null
}
trap cleanup EXIT

rpc() { # rpc <Method> <json>
    "$GRPCURL" -plaintext -d "$2" -import-path "$ROOT/api/proto" -proto dataplane/v1/dataplane.proto \
        "$ADDR" "dataplane.v1.DataplaneNode/$1" 2>"$DP_LOG.rpc"
}

echo "== build flowplane =="
cargo build -p flowplane || fail "cargo build failed"
BIN="$ROOT/target/debug/flowplane"
[[ -x "$BIN" ]] || fail "$BIN missing"
GRPCURL="$(command -v grpcurl)" || fail "grpcurl not on PATH (run inside nix develop)"

echo "== root-netns dummy (underlay /64 inference) + uplink veth =="
ip link del "$DUMMY" 2>/dev/null; ip link add "$DUMMY" type dummy || fail "add dummy"
ip addr add "$ULA_ADDR" dev "$DUMMY" || fail "addr dummy"; ip link set "$DUMMY" up
ip link del "$UPLINK" 2>/dev/null
ip link add "$UPLINK" type veth peer name "$UPLINK_PEER" || fail "add uplink"
ip link set "$UPLINK" up; ip link set "$UPLINK_PEER" up
ip link del "$TAP_NAME" 2>/dev/null

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

# --- (e) an empty mac must be REJECTED for a tap ---
echo "== AttachInterface device_type=tap with EMPTY mac (must fail) =="
BADREQ="{\"interface_id\":\"$IFACE_ID\",\"vni\":$VNI,\"requested_ips\":[\"$OVERLAY_IP\"],\"device_type\":\"tap\"}"
if rpc AttachInterface "$BADREQ" >/dev/null 2>&1; then
    fail "device_type=tap with empty mac was accepted (should require the VM MAC)"
fi
echo "  empty-mac tap attach rejected (OK)"

echo "== AttachInterface device_type=tap =="
REQ="{\"interface_id\":\"$IFACE_ID\",\"vni\":$VNI,\"mac\":\"$VM_MAC\",\"requested_ips\":[\"$OVERLAY_IP\"],\"device_type\":\"tap\"}"
RESP="$(rpc AttachInterface "$REQ")" || { echo "grpcurl stderr:"; cat "$DP_LOG.rpc"; fail "AttachInterface(tap) RPC failed"; }
echo "response: $RESP"

# --- (b) ifname == tap name; underlay_route /128 inside the /64 ---
IFNAME="$(echo "$RESP" | grep -o '"ifname"[^,}]*' | sed 's/.*: *"\([^"]*\)".*/\1/')"
[[ "$IFNAME" == "$TAP_NAME" ]] || fail "response ifname '$IFNAME' != expected '$TAP_NAME'"
UROUTE="$(echo "$RESP" | grep -o '"underlayRoute"[^,}]*' | sed 's/.*: *"\([^"]*\)".*/\1/')"
case "$UROUTE" in fd00:db8:0:7:*) echo "  underlay_route=$UROUTE (inside $ULA64)";; *) fail "underlay_route $UROUTE not in $ULA64";; esac

# --- (a) a root-netns tap exists, correct MAC, UP ---
ip link show "$TAP_NAME" >/dev/null 2>&1 || fail "tap $TAP_NAME not created in root netns"
GOTMAC="$(cat /sys/class/net/$TAP_NAME/address)"
[[ "$GOTMAC" == "$VM_MAC" ]] || fail "tap MAC $GOTMAC != requested $VM_MAC"
ip link show "$TAP_NAME" | grep -q 'state UP\|,UP' || fail "tap $TAP_NAME not UP"
# It must be a tap (has /sys/class/net/<if>/tun_flags), not a veth.
[[ -e "/sys/class/net/$TAP_NAME/tun_flags" ]] || fail "$TAP_NAME is not a tun/tap device"
echo "  tap $TAP_NAME present, mac=$GOTMAC, UP (OK)"

# --- (c) tc_guest_tx attached (clsact) on the tap ---
tc qdisc show dev "$TAP_NAME" | grep -q clsact || fail "no clsact (tc_guest_tx) on $TAP_NAME"
echo "  clsact / tc_guest_tx attached on $TAP_NAME (OK)"

# --- (d) INTERFACES read-back ---
grep -q "INTERFACES readback vni=$VNI ip=$OVERLAY_IP" "$DP_LOG" 2>/dev/null \
    || fail "no INTERFACES read-back for {vni:$VNI, ip:$OVERLAY_IP}"
echo "  INTERFACES map has {vni:$VNI, ip:$OVERLAY_IP} (OK)"

# --- (f) DetachInterface removes the tap ---
echo "== DetachInterface =="
rpc DetachInterface "{\"interface_id\":\"$IFACE_ID\"}" >/dev/null 2>&1 || echo "  WARN: detach RPC returned nonzero"
sleep 0.5
ip link show "$TAP_NAME" >/dev/null 2>&1 && fail "tap $TAP_NAME still present after DetachInterface"
echo "  tap removed on detach (OK)"

echo "PASS: AttachInterface device_type=tap — root-netns tap + mac + tc + maps + detach cleanup"
exit 0
