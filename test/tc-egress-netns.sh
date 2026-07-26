#!/usr/bin/env bash
# test/tc-egress-netns.sh — Phase-3 GATE for the tc (clsact ingress) guest-edge OVERLAY EGRESS.
#
# Proves the tc datapath ENCAPSULATES a guest's inner IPv4 frame into Eth+IPv6 (IPIP) and
# redirects it out the uplink. Topology, all inside a unique netns:
#   - guest tap `tctap0`  (MAC 66:66:66:66:66:00 — the gateway-side MAC the host presents)
#   - uplink veth pair `uplink`/`uplinkpeer`  (frames the datapath redirects onto `uplink`
#     are readable on `uplinkpeer`)
#
# Steps:
#   1. build the release binary,
#   2. create the netns + devices,
#   3. run `flowplane tc-bringup --tap tctap0 --uplink uplink ... --remote 10.0.0.2=fc00:2::2=100`
#      (the verifier loads tc_guest_tx here),
#   4. send Ether/IP(10.0.0.1->10.0.0.2)/ICMP on tctap0 (guest egress) and capture on uplinkpeer,
#   5. REQUIRE the captured frame to be outer Ether + IPv6(nh=4, src=fc00:1::1, dst=fc00:2::2)
#      carrying inner IP(10.0.0.1->10.0.0.2).
#
# PASS -> "ENCAP OK" from the probe, exit 0. Else dumps captured hex + datapath log, exit 1.
#
# Run inside the flake devShell (cargo + go):
#   nix develop --command ./test/tc-egress-netns.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NS="tcegr$$"
TAP="tctap0"
UPLINK="uplink"
PEER="uplinkpeer"
GUEST_MAC="52:54:00:00:00:01"   # guest's own MAC (inner eth src)
TAP_MAC="66:66:66:66:66:00"     # tap (gateway-side) MAC
GW_MAC="aa:aa:aa:aa:aa:aa"      # underlay next-hop MAC (outer eth dst)
GUEST_IP="10.0.0.1"
DP_LOG="/tmp/tc-egr-dp.$$.log"
DP_PID=""

cleanup() {
    set +e
    if [[ -n "$DP_PID" ]] && kill -0 "$DP_PID" 2>/dev/null; then
        sudo kill "$DP_PID" 2>/dev/null
        wait "$DP_PID" 2>/dev/null
    fi
    sudo pkill -f "tc-bringup --tap $TAP" 2>/dev/null
    sudo ip netns del "$NS" 2>/dev/null
}
trap cleanup EXIT

echo "== build release binary =="
cargo build --release -p flowplane
BIN="$ROOT/target/release/flowplane"
[[ -x "$BIN" ]] || { echo "FAIL: $BIN missing after build"; exit 1; }

echo "== create netns $NS + tap $TAP + veth $UPLINK/$PEER =="
sudo ip netns add "$NS"
sudo ip netns exec "$NS" ip link set lo up
sudo ip netns exec "$NS" ip tuntap add dev "$TAP" mode tap
sudo ip netns exec "$NS" ip link set dev "$TAP" address "$TAP_MAC"
sudo ip netns exec "$NS" ip link set dev "$TAP" up
sudo ip netns exec "$NS" ip link add "$UPLINK" type veth peer name "$PEER"
sudo ip netns exec "$NS" ip link set dev "$UPLINK" up
sudo ip netns exec "$NS" ip link set dev "$PEER" up
# Disable offloads on the veth so the captured frame is not coalesced/segmented.
sudo ip netns exec "$NS" ethtool -K "$UPLINK" gro off tso off gso off 2>/dev/null || true
sudo ip netns exec "$NS" ethtool -K "$PEER" gro off tso off gso off 2>/dev/null || true

echo "== run tc-bringup inside $NS (verifier loads tc_guest_tx here) =="
sudo ip netns exec "$NS" env FLOWPLANE_DEBUG=1 "$BIN" tc-bringup \
    --tap "$TAP" --uplink "$UPLINK" \
    --guest-ipv4 "$GUEST_IP" --gateway-ipv4 "$GUEST_IP" --guest-mac "$GUEST_MAC" \
    --gateway-mac "$GW_MAC" --local-underlay fc00:1::1 --guest-underlay fc00:1::1 \
    --remote 10.0.0.2=fc00:2::2=100 \
    --remote6 2001:db8:2::2=fc00:2::2=100 --guest6 2001:db8:1::1 \
    > "$DP_LOG" 2>&1 &
DP_PID=$!

# Give aya time to load (verify) + attach + program the maps.
sleep 2

if ! kill -0 "$DP_PID" 2>/dev/null; then
    echo "FAIL: datapath died during bringup — likely a verifier rejection. Full log:"
    echo "------------------------------------------------------------------------"
    cat "$DP_LOG"
    echo "------------------------------------------------------------------------"
    exit 1
fi
echo "datapath alive (pid $DP_PID); bringup log so far:"
cat "$DP_LOG" || true

echo "== send inner IPv4 on $TAP, capture ENCAPPED frame on $PEER =="
# Build the pure-Go probe (replaces the scapy python probe) once; PROBE is the binary consumers run.
PROBE="${ROOT}/test/e2e/tap-dhcp-probe.bin"
( cd "${ROOT}/test/e2e" && CGO_ENABLED=0 go build -o "$PROBE" ./cmd/tap-dhcp-probe )
set +e
sudo ip netns exec "$NS" "$PROBE" \
    --egress --tap "$TAP" --peer "$PEER" --timeout 5
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
    echo "FAIL: egress encap not correct (probe rc=$RC). Datapath log tail:"
    echo "------------------------------------------------------------------------"
    tail -n 60 "$DP_LOG" || true
    echo "------------------------------------------------------------------------"
    exit 1
fi

echo "== send inner IPv6 on $TAP, capture ENCAPPED v6 frame on $PEER =="
set +e
sudo ip netns exec "$NS" "$PROBE" \
    --egress6 --tap "$TAP" --peer "$PEER" \
    --guest6 2001:db8:1::1 --dst6 2001:db8:2::2 \
    --nexthop6 fc00:2::2 --guest-underlay fc00:1::1 --timeout 5
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
    echo "FAIL: IPv6 egress encap not correct (probe rc=$RC). Datapath log tail:"
    echo "------------------------------------------------------------------------"
    tail -n 60 "$DP_LOG" || true
    echo "------------------------------------------------------------------------"
    exit 1
fi

echo "PASS: tc egress encap OK"
exit 0
