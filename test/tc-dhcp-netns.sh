#!/usr/bin/env bash
# test/tc-dhcp-netns.sh — Phase-1 integration GATE for the tc (clsact ingress) guest edge.
#
# This is the FIRST load of the tc eBPF programs (tc_guest_tx, tc_guest_dhcp) through the kernel
# verifier. It proves the clsact datapath answers guest DHCPv4 end-to-end:
#   1. build the release binary,
#   2. make a netns + a tap inside it (MAC = gateway MAC),
#   3. run `flowplane tc-bringup` to attach the tc datapath to that tap (verifier runs HERE),
#   4. send a DHCP DISCOVER on the tap (via the tap fd, exactly how a guest TXes),
#   5. assert a DHCP OFFER for 10.0.0.1 comes back.
#
# PASS -> prints "PASS: tc DHCP OFFER received" and exits 0.
# If the eBPF VERIFIER rejects a program, the load error lands in the datapath log (captured
# below); this script surfaces it and exits 1 so the controller can read the verifier output.
#
# Run inside the flake devShell (provides cargo + python3/scapy):
#   chmod +x test/tc-dhcp-netns.sh
#   nix develop --command ./test/tc-dhcp-netns.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NS="tcdhcp$$"
TAP="tctap0"
GUEST_MAC="52:54:00:00:00:01"
GW_MAC="66:66:66:66:66:00"
GUEST_IP="10.0.0.1"
DP_LOG="/tmp/tc-dp.$$.log"
DP_PID=""

cleanup() {
    set +e
    if [[ -n "$DP_PID" ]] && kill -0 "$DP_PID" 2>/dev/null; then
        sudo kill "$DP_PID" 2>/dev/null
        wait "$DP_PID" 2>/dev/null
    fi
    # Belt-and-suspenders: kill any stray bringup in our netns, then delete the netns (which
    # also tears down the tap living inside it).
    sudo pkill -f "tc-bringup --tap $TAP" 2>/dev/null
    sudo ip netns del "$NS" 2>/dev/null
}
trap cleanup EXIT

echo "== build release binary =="
cargo build --release -p flowplane
BIN="$ROOT/target/release/flowplane"
[[ -x "$BIN" ]] || { echo "FAIL: $BIN missing after build"; exit 1; }

echo "== create netns $NS + tap $TAP =="
sudo ip netns add "$NS"
sudo ip netns exec "$NS" ip link set lo up
sudo ip netns exec "$NS" ip tuntap add dev "$TAP" mode tap
sudo ip netns exec "$NS" ip link set dev "$TAP" address "$GW_MAC"
sudo ip netns exec "$NS" ip link set dev "$TAP" up

echo "== run tc-bringup inside $NS (verifier loads tc_guest_tx + tc_guest_dhcp here) =="
sudo ip netns exec "$NS" env FLOWPLANE_DEBUG=1 "$BIN" tc-bringup \
    --tap "$TAP" \
    --guest-ipv4 "$GUEST_IP" \
    --gateway-ipv4 "$GUEST_IP" \
    --guest-mac "$GUEST_MAC" \
    --gateway-mac "$GW_MAC" \
    --gateway6 fe80::1 \
    --guest6 2001:db8:1::1 \
    --dhcp-dns 8.8.8.8 \
    > "$DP_LOG" 2>&1 &
DP_PID=$!

# Give aya time to load (verify) + attach the programs.
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

echo "== send DHCP DISCOVER on $TAP (client MAC $GUEST_MAC), expect OFFER for $GUEST_IP =="
PYBIN="$(command -v python3)"
set +e
sudo ip netns exec "$NS" "$PYBIN" "$ROOT/test/tap-dhcp-probe.py" \
    --client-only --tap "$TAP" --client-mac "$GUEST_MAC" --expect-ip "$GUEST_IP" --timeout 4
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
    echo "FAIL: no valid OFFER for $GUEST_IP (probe rc=$RC). Datapath log tail:"
    echo "------------------------------------------------------------------------"
    tail -n 40 "$DP_LOG" || true
    echo "------------------------------------------------------------------------"
    exit 1
fi
echo "DHCP OFFER OK"

echo "== send ARP who-has $GUEST_IP on $TAP, expect reply from $GUEST_MAC =="
set +e
sudo ip netns exec "$NS" "$PYBIN" "$ROOT/test/tap-dhcp-probe.py" \
    --client-only --probe arp --tap "$TAP" --client-mac "$GUEST_MAC" \
    --expect-ip "$GUEST_IP" --timeout 4
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
    echo "FAIL: no valid ARP reply for $GUEST_IP (probe rc=$RC). Datapath log tail:"
    echo "------------------------------------------------------------------------"
    tail -n 40 "$DP_LOG" || true
    echo "------------------------------------------------------------------------"
    exit 1
fi

echo "== send ICMPv6 NS for fe80::1 on $TAP, expect NA with target-LL $GUEST_MAC =="
set +e
sudo ip netns exec "$NS" "$PYBIN" "$ROOT/test/tap-dhcp-probe.py" \
    --client-only --probe nd --tap "$TAP" --client-mac "$GUEST_MAC" \
    --gateway6 fe80::1 --timeout 4
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
    echo "FAIL: no valid ND NA for fe80::1 (probe rc=$RC). Datapath log tail:"
    echo "------------------------------------------------------------------------"
    tail -n 40 "$DP_LOG" || true
    echo "------------------------------------------------------------------------"
    exit 1
fi

echo "== send DHCPv6 SOLICIT on $TAP (client MAC $GUEST_MAC), expect ADVERTISE for 2001:db8:1::1 =="
set +e
sudo ip netns exec "$NS" "$PYBIN" "$ROOT/test/tap-dhcp-probe.py" \
    --client-only --probe dhcpv6 --tap "$TAP" --client-mac "$GUEST_MAC" \
    --guest6 2001:db8:1::1 --timeout 4
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
    echo "FAIL: no valid DHCPv6 ADVERTISE for 2001:db8:1::1 (probe rc=$RC). Datapath log tail:"
    echo "------------------------------------------------------------------------"
    tail -n 40 "$DP_LOG" || true
    echo "------------------------------------------------------------------------"
    exit 1
fi

echo "PASS: tc DHCP + ARP + ND + DHCPv6 OK"
exit 0
