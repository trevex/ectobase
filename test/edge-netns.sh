#!/usr/bin/env bash
# test/edge-netns.sh — WAN-edge datapath harness (D7). Proves the `flowplane serve --role edge`
# sidecar forwards BOTH directions of North-South egress WITHOUT the fabric/k8s, using pure
# veth/netns + crafted packets (scapy) + capture (tcpdump).
#
# The edge = VyOS + an flowplane sidecar sharing a netns. Here `edge` netns stands in for that shared
# netns: `fab` is the fabric-facing uplink (uplink_rx) and `wan` is the WAN-facing uplink (wan_rx).
# `fabpeer` stands in for the owning hypervisor (captures the return encap / injects egress encap);
# `wanpeer` stands in for the internet + VyOS's real WAN next-hop (injects the return / captures
# the masqueraded egress).
#
#   fabpeer(owner hv)                 edge (flowplane sidecar)                 wanpeer(internet/WAN)
#     fabp-eth <===veth===> fab  [uplink_rx]        [wan_rx]  wan <===veth===> wanp-eth
#
# RETURN (WAN -> fabric): wanpeer sends a plain IPv4 to nat_ip:nat_port. wan_rx matches the
#   NEIGHBOR_NAT block (nat_ip,dport) and encaps IP-in-IPv6 toward the owner underlay, redirecting
#   out `fab`. Asserted by capturing the encapped IPv6 (nh=IPIP, dst=owner_ul, inner dst=nat_ip)
#   on fabp-eth.
# EGRESS (fabric -> WAN): fabpeer sends an IP-in-IPv6 packet (outer dst = the edge underlay, inner
#   src=nat_ip dst=<internet>). uplink_rx matches the local-deliver UNDERLAY entry, decaps, and
#   XDP_PASSes the inner IPv4 to the local kernel, which routes/masquerades it out `wan`. Asserted
#   by capturing the inner IPv4 (dst=<internet>) on wanp-eth.
#
# Run inside the flake devShell; needs sudo for netns/eBPF/scapy:
#   nix develop --command sh -c 'sudo env "PATH=$PATH" bash test/edge-netns.sh'
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

ADDR="127.0.0.1:1337"; VNI=100
EDGE_NS="edge"; FAB_NS="fabpeer"; WAN_NS="wanpeer"
FAB="fab"; FABP="fabp-eth"; WAN="wan"; WANP="wanp-eth"
GW="169.254.0.1"; GW_MAC="02:00:00:00:00:01"
EDGE_UL="fd00:db8:0:ed::1"           # the edge's own underlay /128 (LOCAL + local-deliver key)
OWNER_UL="fd00:db8:0:9::a"           # the owning hypervisor's underlay /128 (return encap dst)
NAT_IP="203.0.113.10"; PMIN=1024; PMAX=2048; DPORT=1500   # dport in [PMIN,PMAX)
EXT_RET="198.51.100.7"               # the internet peer sending the return (TEST-NET-2; != nat_ip)
EXT_DST="192.0.2.200"                # the egress target on the internet (TEST-NET-1; != nat_ip)
# IPv4 transit between the edge kernel and the WAN next-hop (VyOS's last hop to the real host).
WAN4_EDGE="100.64.0.1"; WAN4_PEER="100.64.0.2"; WAN4_MASK=24
LOG="$(mktemp)"; RET_PCAP="$(mktemp --suffix=.pcap)"; EGR_PCAP="$(mktemp --suffix=.pcap)"
BIN="$ROOT/target/debug/flowplane"
GRPCURL="$(command -v grpcurl)"
SERVE_PID=""; PASS_PID=""; TCPDUMP_PID=""

fail() { echo "FAIL: $*"; echo "---- edge datapath log ----"; cat "$LOG" 2>/dev/null; echo "---------------------------"; exit 1; }

cleanup() {
  set +e
  [ -n "$SERVE_PID" ] && kill -9 "$SERVE_PID" 2>/dev/null
  [ -n "$PASS_PID" ] && kill -9 "$PASS_PID" 2>/dev/null
  [ -n "$TCPDUMP_PID" ] && kill -9 "$TCPDUMP_PID" 2>/dev/null
  pkill -f "flowplane serve --addr $ADDR" 2>/dev/null
  pkill -f "flowplane pass --iface $FABP" 2>/dev/null
  ip netns del "$EDGE_NS" 2>/dev/null
  ip netns del "$FAB_NS" 2>/dev/null
  ip netns del "$WAN_NS" 2>/dev/null
  rm -f "$LOG" "$RET_PCAP" "$EGR_PCAP"
}
trap cleanup EXIT

echo "== build flowplane =="
cargo build -p flowplane 2>&1 | tail -1
[ -x "$BIN" ] || fail "$BIN missing after build"

echo "== build netprobe (pure-Go pcap verifier) =="
NETPROBE="${ROOT}/test/e2e/netprobe.bin"
( cd "${ROOT}/test/e2e" && CGO_ENABLED=0 go build -o "$NETPROBE" ./cmd/netprobe ) \
  || fail "failed to build netprobe"

echo "== netns: $EDGE_NS (sidecar), $FAB_NS (owner hv), $WAN_NS (internet/WAN) =="
for ns in "$EDGE_NS" "$FAB_NS" "$WAN_NS"; do
  ip netns del "$ns" 2>/dev/null
  ip netns add "$ns" || fail "netns add $ns"
  ip netns exec "$ns" ip link set lo up
done

echo "== veths: $FAB<->$FABP (fabric side), $WAN<->$WANP (WAN side) =="
# fab lives in the edge netns; fabp-eth in the owner (fabpeer) netns.
ip link add "$FAB" netns "$EDGE_NS" type veth peer name "$FABP" netns "$FAB_NS" || fail "add fab veth"
ip link add "$WAN" netns "$EDGE_NS" type veth peer name "$WANP" netns "$WAN_NS" || fail "add wan veth"
ip netns exec "$EDGE_NS" ip link set "$FAB" up
ip netns exec "$EDGE_NS" ip link set "$WAN" up
ip netns exec "$FAB_NS" ip link set "$FABP" up
ip netns exec "$WAN_NS" ip link set "$WANP" up

# Underlay /128 on the edge's fabric side so the netns has the address (also aids ND if any).
ip netns exec "$EDGE_NS" ip -6 addr add "$EDGE_UL/64" dev "$FAB"
# IPv4 transit on the WAN side so the edge kernel can forward decapped egress to the WAN next-hop.
ip netns exec "$EDGE_NS" ip addr add "$WAN4_EDGE/$WAN4_MASK" dev "$WAN"
ip netns exec "$WAN_NS"  ip addr add "$WAN4_PEER/$WAN4_MASK" dev "$WANP"

echo "== edge kernel forwards decapped egress to the WAN next-hop (stands in for VyOS routing) =="
ip netns exec "$EDGE_NS" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$EDGE_NS" sysctl -qw net.ipv4.conf.all.forwarding=1
ip netns exec "$EDGE_NS" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$EDGE_NS" sysctl -qw net.ipv4.conf."$FAB".rp_filter=0
ip netns exec "$EDGE_NS" sysctl -qw net.ipv4.conf."$WAN".rp_filter=0
# Route the egress target to the WAN next-hop. (VyOS would masquerade nat_ip->host here; the
# capture on wanp-eth proves the inner IPv4 made it out the WAN uplink.)
ip netns exec "$EDGE_NS" ip route add "$EXT_DST/32" via "$WAN4_PEER" dev "$WAN"
# Static neigh so the edge doesn't need to ARP-resolve the WAN next-hop.
WANP_MAC="$(ip netns exec "$WAN_NS" cat /sys/class/net/"$WANP"/address)"
ip netns exec "$EDGE_NS" ip neigh replace "$WAN4_PEER" lladdr "$WANP_MAC" dev "$WAN" nud permanent

echo "== xdp_pass on $FABP (redirect-target enabler for wan_rx -> $FAB) =="
ip netns exec "$FAB_NS" env FLOWPLANE_SKB_MODE=1 "$BIN" pass --iface "$FABP" >/dev/null 2>&1 &
PASS_PID=$!
sleep 0.5

echo "== start flowplane serve --role edge in $EDGE_NS (uplink_rx on $FAB, wan_rx on $WAN) =="
ip netns exec "$EDGE_NS" env FLOWPLANE_SKB_MODE=1 "$BIN" serve \
  --addr "$ADDR" \
  --role edge \
  --uplink "$FAB" \
  --wan-uplink "$WAN" \
  --local-underlay "$EDGE_UL" \
  --gateway "$GW" \
  --gateway-mac "$GW_MAC" \
  >"$LOG" 2>&1 &
SERVE_PID=$!

for _ in $(seq 1 50); do
  kill -0 "$SERVE_PID" 2>/dev/null || fail "serve --role edge died during startup (verifier?)"
  grep -q "serving DataplaneNode on" "$LOG" 2>/dev/null && break
  sleep 0.2
done
grep -q "serving DataplaneNode on" "$LOG" 2>/dev/null || fail "serve --role edge did not start listening"
grep -q "edge role: wan_rx attached" "$LOG" 2>/dev/null || fail "no 'edge role: wan_rx attached' confirmation (wan_rx not wired)"
echo "PASS: edge role loaded (eBPF verified, wan_rx + local-deliver attached)"

grpc() { ip netns exec "$EDGE_NS" "$GRPCURL" -plaintext -import-path "$ROOT/api/proto" -proto dataplane/v1/dataplane.proto "$@"; }

echo "== AddNeighborNat: nat_ip=$NAT_IP ports=$PMIN..$PMAX -> owner=$OWNER_UL =="
grpc -d "{\"vni\":$VNI,\"nat_ip\":\"$NAT_IP\",\"port_min\":$PMIN,\"port_max\":$PMAX,\"owner_underlay\":\"$OWNER_UL\"}" \
  "$ADDR" dataplane.v1.DataplaneNode/AddNeighborNat \
  || fail "AddNeighborNat RPC failed"
grep -q "NEIGHBOR_NAT add vni=$VNI nat_ip=$NAT_IP ports=$PMIN..$PMAX -> owner=$OWNER_UL" "$LOG" \
  || fail "no NEIGHBOR_NAT confirmation in log"

# ---------------------------------------------------------------------------
# RETURN: WAN -> fabric. Capture the encap on fabp-eth, inject the plain return on wanp-eth.
echo "== RETURN: capture on $FABP, inject plain IPv4 return on $WANP =="
FAB_MAC="$(ip netns exec "$EDGE_NS" cat /sys/class/net/"$FAB"/address)"
WAN_MAC="$(ip netns exec "$EDGE_NS" cat /sys/class/net/"$WAN"/address)"

# Filter precisely on the owner underlay so fresh-veth ND/MLD chatter never fills the -c budget.
ip netns exec "$FAB_NS" tcpdump -i "$FABP" -w "$RET_PCAP" -c 1 -U "ip6 dst $OWNER_UL" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 0.8
ip netns exec "$WAN_NS" python3 - "$WANP" "$WAN_MAC" "$EXT_RET" "$NAT_IP" "$DPORT" <<'PY'
import sys
from scapy.all import Ether, IP, TCP, sendp
iface, dmac, src, dst, dport = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
pkt = Ether(dst=dmac)/IP(src=src, dst=dst)/TCP(sport=80, dport=dport, flags="A")/b"return"
sendp(pkt, iface=iface, count=3, verbose=False)
PY
sleep 0.8
kill -9 "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null; TCPDUMP_PID=""

"$NETPROBE" pcap-verify --pcap "$RET_PCAP" \
  --want-outer-ipv6-dst "$OWNER_UL" \
  --want-outer-ipv6-nh 4 \
  --want-inner-ip-dst "$NAT_IP" \
  || fail "RETURN not encapped to owner (see above)"

# ---------------------------------------------------------------------------
# EGRESS: fabric -> WAN. Capture inner IPv4 on wanp-eth, inject encapped egress on fabp-eth.
echo "== EGRESS: capture on $WANP, inject IP-in-IPv6 egress on $FABP =="
ip netns exec "$WAN_NS" tcpdump -i "$WANP" -w "$EGR_PCAP" -c 1 -U "ip dst $EXT_DST" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 0.8
ip netns exec "$FAB_NS" python3 - "$FABP" "$FAB_MAC" "$OWNER_UL" "$EDGE_UL" "$NAT_IP" "$EXT_DST" <<'PY'
import sys
from scapy.all import Ether, IPv6, IP, TCP, sendp
iface, dmac, outer_src, outer_dst, nat_ip, ext_dst = sys.argv[1:7]
# IP-in-IPv6: outer IPv6 nh=4 (IPPROTO_IPIP) carrying the inner IPv4 directly (no inner eth).
pkt = (Ether(dst=dmac)/IPv6(src=outer_src, dst=outer_dst, nh=4)
       /IP(src=nat_ip, dst=ext_dst)/TCP(sport=1500, dport=80, flags="A")/b"egress")
sendp(pkt, iface=iface, count=3, verbose=False)
PY
sleep 0.8
kill -9 "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null; TCPDUMP_PID=""

"$NETPROBE" pcap-verify --pcap "$EGR_PCAP" \
  --want-inner-ip-src "$NAT_IP" \
  --want-inner-ip-dst "$EXT_DST" \
  --want-no-ipv6 \
  || fail "EGRESS inner IPv4 did not reach the WAN (decap/local-deliver broken)"

echo "PASS: WAN-edge datapath forwards egress + return both ways"
