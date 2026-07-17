#!/usr/bin/env bash
# test/two-endpoint-netns.sh — datapath e2e for TWO endpoints attached via the
# DataplaneNode.AttachInterface gRPC, proving they reach each other over the LOCAL fast path.
#
# Modeled closely on test/attach-netns.sh (same idioms: a root-netns dummy with a global ULA /64
# for underlay inference, `flowplane serve` bringing up the datapath + gRPC listener, AttachInterface
# via grpcurl, an EXIT-trap cleanup). Differs by attaching TWO endpoints in two netns and pinging
# between them.
#
# Topology (no KubeVirt/k8s/fabric — pure veth/netns):
#   ep-a(10.0.0.1) --veth-a0-- [ flowplane serve datapath ] --veth-b0-- ep-b(10.0.0.2)     (vni 100)
#
# AttachInterface creates a veth pair per endpoint (host end named veth-<id>, guest end named <id>
# moved into the target netns), allocates an underlay /128 out of fd00:db8:0:7::/64, and programs
# PORT_META / INTERFACES / UNDERLAY + a local /32 self-route. tc_guest_tx (the default guest edge)
# on the host-side veth encaps, resolves the peer's LOCAL underlay via the /32 self-route, and
# bpf_redirects straight to the peer's host-side veth — the same-host fast path, no wire round trip.
#
# The test does TWO things:
#   1. DHCP: bring the guest iface up and try a DHCP client (udhcpc/dhclient/busybox) to obtain the
#      overlay IP from the datapath's DHCPv4 responder. The DHCPv4 yiaddr is meta.guest_ipv4 from
#      PORT_META (which AttachInterface programs), so an OFFER for the requested IP is expected.
#      If NO DHCP client is installed, or DHCP does not hand out the right IP, the test falls back
#      to STATIC addressing and reports the gap — it never fakes a DHCP pass.
#   2. PING: guests use the dpservice model (/32 + link route to the gateway + default via gateway),
#      so they ARP only for 10.0.0.1, which the datapath answers in-kernel. Then ep-a->10.0.0.2 and
#      ep-b->10.0.0.1 must be 0% loss over the local fast path.
#
# Run inside the flake devShell (provides cargo + grpcurl + ip):
#   nix develop --command sh -c 'sudo env "PATH=$PATH" bash test/two-endpoint-netns.sh'
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DUMMY="dp-dummy"
ULA64="fd00:db8:0:7::/64"
ULA_ADDR="fd00:db8:0:7::1/64"
UPLINK="dp-upl"
UPLINK_PEER="dp-uplp"
ADDR="127.0.0.1:1337"
GW_MAC="aa:aa:aa:aa:aa:aa"
# The overlay gateway the datapath answers ARP/ND for. MUST be distinct from the endpoint IPs
# (dpservice uses the link-local-style 169.254.0.1) — otherwise a guest's default gateway is another
# guest's address and routing/ARP breaks.
GW="169.254.0.1"
VNI=100

# Endpoint A / B: {interface_id, netns, overlay IPv4}. The guest iface inside the netns keeps the
# interface_id as its name (the CNI contract AttachInterface implements); the host end is veth-<id>.
NS_A="ep-a"; ID_A="a0"; IP_A="10.0.0.1"
NS_B="ep-b"; ID_B="b0"; IP_B="10.0.0.2"

DP_LOG="/tmp/two-endpoint-dp.$$.log"
DP_PID=""

fail() { echo "FAIL: $*"; echo "---- datapath log ----"; cat "$DP_LOG" 2>/dev/null || true; echo "----------------------"; exit 1; }

cleanup() {
    set +e
    if [[ -n "$DP_PID" ]] && kill -0 "$DP_PID" 2>/dev/null; then
        kill "$DP_PID" 2>/dev/null
        wait "$DP_PID" 2>/dev/null
    fi
    pkill -f "flowplane serve --addr $ADDR" 2>/dev/null
    ip netns del "$NS_A" 2>/dev/null
    ip netns del "$NS_B" 2>/dev/null
    ip link del "$DUMMY" 2>/dev/null
    ip link del "$UPLINK" 2>/dev/null
    ip link del "veth-$ID_A" 2>/dev/null
    ip link del "veth-$ID_B" 2>/dev/null
}
trap cleanup EXIT

echo "== build flowplane =="
nix develop --command cargo build -p flowplane || fail "cargo build failed"
BIN="$ROOT/target/debug/flowplane"
[[ -x "$BIN" ]] || fail "$BIN missing after build"

GRPCURL="$(command -v grpcurl)" || fail "grpcurl not on PATH (run inside nix develop)"

# Detect an available DHCP client (best-effort; static is the fallback).
DHCP_CLIENT=""
if command -v udhcpc >/dev/null 2>&1; then DHCP_CLIENT="udhcpc"
elif command -v dhclient >/dev/null 2>&1; then DHCP_CLIENT="dhclient"
elif command -v busybox >/dev/null 2>&1 && busybox udhcpc --help >/dev/null 2>&1; then DHCP_CLIENT="busybox-udhcpc"
fi
echo "DHCP client detected: ${DHCP_CLIENT:-none (will use static fallback)}"

echo "== root-netns dummy $DUMMY with $ULA_ADDR (underlay inference /64) =="
ip link del "$DUMMY" 2>/dev/null
ip link add "$DUMMY" type dummy || fail "add dummy"
ip addr add "$ULA_ADDR" dev "$DUMMY" || fail "addr add dummy"
ip link set "$DUMMY" up || fail "dummy up"

echo "== endpoint netns $NS_A, $NS_B =="
for ns in "$NS_A" "$NS_B"; do
    ip netns del "$ns" 2>/dev/null
    ip netns add "$ns" || fail "netns add $ns"
    ip netns exec "$ns" ip link set lo up
done

echo "== uplink veth $UPLINK (uplink_rx attaches here) =="
ip link del "$UPLINK" 2>/dev/null
ip link add "$UPLINK" type veth peer name "$UPLINK_PEER" || fail "add uplink veth"
ip link set "$UPLINK" up
ip link set "$UPLINK_PEER" up

echo "== start flowplane serve on $ADDR (SKB mode; DHCP DNS/MTU set for the responder) =="
FLOWPLANE_SKB_MODE=1 "$BIN" serve \
    --addr "$ADDR" \
    --uplink "$UPLINK" \
    --local-underlay "fd00:db8:0:7::1" \
    --gateway "$GW" \
    --gateway-mac "$GW_MAC" \
    --dhcp-mtu 1400 \
    --dhcp-dns 8.8.8.8 \
    > "$DP_LOG" 2>&1 &
DP_PID=$!

# Wait for the gRPC listener to come up.
for _ in $(seq 1 50); do
    if ! kill -0 "$DP_PID" 2>/dev/null; then
        fail "serve died during startup"
    fi
    if grep -q "serving DPDKironcore on" "$DP_LOG" 2>/dev/null; then
        break
    fi
    sleep 0.2
done
grep -q "serving DPDKironcore on" "$DP_LOG" 2>/dev/null || fail "serve did not start listening"

# ---------------------------------------------------------------------------
# attach <interface_id> <netns> <overlay_ip> — fire the AttachInterface RPC and assert the veth
# landed inside the netns and the INTERFACES read-back confirmation appears in the daemon log.
attach() {
    local id="$1" ns="$2" ip="$3"
    echo "== AttachInterface {id:$id, netns:$ns, vni:$VNI, ip:$ip} =="
    local req resp rc
    req="{\"interface_id\":\"$id\",\"netns_path\":\"/var/run/netns/$ns\",\"vni\":$VNI,\"requested_ips\":[\"$ip\"]}"
    resp="$("$GRPCURL" -plaintext -d "$req" -import-path "$ROOT/api/proto" -proto dataplane/v1/dataplane.proto \
        "$ADDR" dataplane.v1.DataplaneNode/AttachInterface 2>"$DP_LOG.rpc.$id")"
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "grpcurl stderr:"; cat "$DP_LOG.rpc.$id"
        fail "AttachInterface RPC for $id failed (rc=$rc)"
    fi
    echo "response: $resp"

    # underlay_route must be a /128 inside the inferred /64.
    local ur
    ur="$(echo "$resp" | grep -o '"underlayRoute"[^,}]*' | sed 's/.*: *"\([^"]*\)".*/\1/')"
    [[ -n "$ur" ]] || fail "no underlay_route in response for $id"
    case "$ur" in
        fd00:db8:0:7:*) echo "underlay_route($id) = $ur (inside $ULA64)" ;;
        *) fail "underlay_route $ur for $id not inside $ULA64" ;;
    esac

    # The guest iface (named after interface_id) must now exist in the netns.
    if ! ip netns exec "$ns" ip -o link show | grep -qw "$id"; then
        echo "netns links:"; ip netns exec "$ns" ip -o link show
        fail "no interface named $id inside netns $ns"
    fi

    # The daemon reads INTERFACES back out of the live map and logs a greppable confirmation only
    # when the endpoint is really resident (no bpftool in the dev shell).
    grep -q "INTERFACES readback vni=$VNI ip=$ip" "$DP_LOG" 2>/dev/null \
        || fail "no INTERFACES read-back confirmation for {vni:$VNI, ip:$ip} in daemon log"
    echo "endpoint $id: veth in $ns + INTERFACES{vni:$VNI,ip:$ip} confirmed"
}

detach() {
    local id="$1"
    "$GRPCURL" -plaintext -d "{\"interface_id\":\"$id\"}" \
        -import-path "$ROOT/api/proto" -proto dataplane/v1/dataplane.proto \
        "$ADDR" dataplane.v1.DataplaneNode/DetachInterface >/dev/null 2>&1 \
        || echo "WARN: DetachInterface RPC for $id failed (non-fatal)"
}

attach "$ID_A" "$NS_A" "$IP_A"
attach "$ID_B" "$NS_B" "$IP_B"

# ---------------------------------------------------------------------------
# Address each guest. Try DHCP first (proves the datapath DHCPv4 responder hands out the overlay
# IP). If DHCP is unavailable or hands out the wrong IP, fall back to a STATIC dpservice-style
# config and record the gap. Either way the guest ends up with the dpservice routing model:
#   ip addr add <ip>/32 ; ip route add <gw>/32 dev <if> ; ip route add default via <gw>
# so it ARPs only for the gateway (answered in-kernel by the datapath).
DHCP_OK=1   # becomes 0 if any endpoint had to fall back to static
DHCP_NOTE=""

setup_static() {
    local ns="$1" id="$2" ip="$3"
    ip netns exec "$ns" ip addr flush dev "$id" 2>/dev/null
    ip netns exec "$ns" ip addr add "$ip/32" dev "$id" || fail "static addr add $ip in $ns"
    ip netns exec "$ns" ip route add "$GW/32" dev "$id" 2>/dev/null
    ip netns exec "$ns" ip route add default via "$GW" 2>/dev/null
}

# try_dhcp <ns> <id> <expected_ip> -> 0 if the guest ended up with expected_ip via DHCP, else 1.
try_dhcp() {
    local ns="$1" id="$2" ip="$3" rc=1
    case "$DHCP_CLIENT" in
        udhcpc)
            ip netns exec "$ns" udhcpc -i "$id" -q -f -n -t 5 >/dev/null 2>&1 && rc=0 ;;
        busybox-udhcpc)
            ip netns exec "$ns" busybox udhcpc -i "$id" -q -f -n -t 5 >/dev/null 2>&1 && rc=0 ;;
        dhclient)
            ip netns exec "$ns" dhclient -1 "$id" >/dev/null 2>&1 && rc=0 ;;
        *)
            return 1 ;;
    esac
    [[ $rc -ne 0 ]] && return 1
    # Assert the client actually configured the expected overlay IP.
    if ip netns exec "$ns" ip -4 addr show dev "$id" | grep -qw "$ip"; then
        # DHCP gives a /24 with a default route; add the gateway link route the datapath expects.
        ip netns exec "$ns" ip route add "$GW/32" dev "$id" 2>/dev/null
        return 0
    fi
    return 1
}

for pair in "$NS_A $ID_A $IP_A" "$NS_B $ID_B $IP_B"; do
    set -- $pair
    ns="$1"; id="$2"; ip="$3"
    ip netns exec "$ns" ip link set "$id" up || fail "link up $id in $ns"
    if [[ -n "$DHCP_CLIENT" ]] && try_dhcp "$ns" "$id" "$ip"; then
        echo "DHCP: $id got $ip in $ns"
    else
        if [[ -n "$DHCP_CLIENT" ]]; then
            DHCP_NOTE="DHCP client '$DHCP_CLIENT' did not yield the expected IP for $id"
        else
            DHCP_NOTE="no DHCP client installed"
        fi
        echo "DHCP fallback -> STATIC for $id ($DHCP_NOTE)"
        setup_static "$ns" "$id" "$ip"
        DHCP_OK=0
    fi
done

if [[ "$DHCP_OK" -eq 1 ]]; then
    echo "ADDRESSING: DHCP handed out both overlay IPs"
else
    echo "ADDRESSING: STATIC fallback used ($DHCP_NOTE)"
fi


# ---------------------------------------------------------------------------
echo "== LOCAL fast-path ping ep-a($IP_A) -> ep-b($IP_B) =="
PING_FAIL=0
if ip netns exec "$NS_A" ping -c2 -W2 "$IP_B" >/tmp/two-ep-ping-ab.$$ 2>&1; then
    echo "ping ep-a -> $IP_B: 0% loss"
    grep -E 'packets transmitted|packet loss' /tmp/two-ep-ping-ab.$$ || true
else
    echo "ping ep-a -> $IP_B FAILED:"; cat /tmp/two-ep-ping-ab.$$
    PING_FAIL=1
fi
rm -f /tmp/two-ep-ping-ab.$$

echo "== LOCAL fast-path ping ep-b($IP_B) -> ep-a($IP_A) =="
if ip netns exec "$NS_B" ping -c2 -W2 "$IP_A" >/tmp/two-ep-ping-ba.$$ 2>&1; then
    echo "ping ep-b -> $IP_A: 0% loss"
    grep -E 'packets transmitted|packet loss' /tmp/two-ep-ping-ba.$$ || true
else
    echo "ping ep-b -> $IP_A FAILED:"; cat /tmp/two-ep-ping-ba.$$
    PING_FAIL=1
fi
rm -f /tmp/two-ep-ping-ba.$$

echo "== DetachInterface both endpoints =="
detach "$ID_A"
detach "$ID_B"

if [[ "$PING_FAIL" -ne 0 ]]; then
    echo "---- datapath log ----"; cat "$DP_LOG" 2>/dev/null || true; echo "----------------------"
    echo "FAIL: local fast-path ping between the two AttachInterface endpoints did not pass"
    exit 1
fi

if [[ "$DHCP_OK" -eq 1 ]]; then
    echo "PASS: two AttachInterface endpoints got their overlay IPs via DHCP and ping over the local fast path"
else
    echo "PASS: two AttachInterface endpoints ping over the local fast path (STATIC IPs; DHCP gap: $DHCP_NOTE)"
fi
exit 0
