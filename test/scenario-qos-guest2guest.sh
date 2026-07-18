#!/usr/bin/env bash
# test/scenario-qos-guest2guest.sh — QoS shaping/policing measured OVERLAY-INTERNAL, guest<->guest,
# cross-node. This is the clean way to get a real throughput number in clab: it avoids the WAN edge,
# SNAT, and the clabwan sink entirely (all of which have flaky return paths in clab). Two guests in
# the SAME VPC on DIFFERENT nodes talk over the IP-in-IPv6 overlay (symmetric conntrack return).
#
#   A (sender) on k01-worker 10.0.0.5   -->   B (receiver/iperf3 server) on k01-control-plane 10.0.0.6
#
# Because the flow is internal (is_external=false), it isolates the EDT total lane (the public policer
# never engages). A and B are cross-node, so A's egress ENCAPS -> A's uplink `fq` paces it (EDT), and
# B's `uplink_rx` can policing-drop on ingress. iperf3 UDP at a rate ABOVE the cap distinguishes them:
#   - EDT shaping   (A egress.rateMbps=C): B receives ~C Mbps, LOW loss (fq paces, no drops)
#   - Ingress police (B ingress.rateMbps=C): B receives ~C Mbps, HIGH loss (token-bucket drops)
# (Same-node would hit the Deliver::Local tap->tap fast path, which is unshaped by design — hence
# cross-node.) The public egress policer is NOT covered here (needs external egress; see
# scenario-qos-pacing.sh for that lane).
#
# PREREQ: fabric up + netplane stack on k01 (images from THIS tree) + a static iperf3
#   (nix build nixpkgs#pkgsStatic.iperf3). Needs root + kubectl + grpcurl image.
#   sudo -E env "PATH=/run/wrappers/bin:$HOME/go/bin:/run/current-system/sw/bin:$PATH" bash test/scenario-qos-guest2guest.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

VNI=100
NODE_A=k01-worker;        NIC_A=qos-a; IP_A=10.0.0.5
NODE_B=k01-control-plane; NIC_B=qos-b; IP_B=10.0.0.6
CAP_MBPS="${CAP_MBPS:-20}"; UDP_TARGET="${UDP_TARGET:-100}"; IPERF_T="${IPERF_T:-8}"
PROTO="$ROOT/api/proto"
K1=$(mktemp); RESULT=0
fail() { echo "FAIL: $*"; RESULT=1; }
kc() { kubectl --kubeconfig "$K1" "$@"; }
grpc() { sudo docker run --rm --network "container:$1" -v "$PROTO":/proto:ro fullstorydev/grpcurl:latest \
  -plaintext -import-path /proto/dataplane/v1 -proto dataplane.proto -d "$2" 127.0.0.1:1337 "dataplane.v1.DataplaneNode/$3" 2>&1; }

attach_guest() { # node nic ip
  local node=$1 nic=$2 ip=$3 out ul
  grpc "$node" "{\"interface_id\":\"$nic\"}" DetachInterface >/dev/null 2>&1 || true
  sudo docker exec "$node" ip netns add "$nic" 2>/dev/null || true
  out=$(grpc "$node" "{\"interface_id\":\"$nic\",\"netns_path\":\"/var/run/netns/$nic\",\"vni\":$VNI,\"requested_ips\":[\"$ip\"]}" AttachInterface)
  ul=$(echo "$out" | grep -o 'fd00:[0-9a-f:]*' | head -1)
  [ -n "$ul" ] || { echo "FAIL: attach $nic: $out"; return 1; }
  sudo docker exec "$node" sh -c "ip netns exec $nic ip addr add $ip/32 dev $nic 2>/dev/null; \
    ip netns exec $nic ip route add 169.254.0.1/32 dev $nic 2>/dev/null; \
    ip netns exec $nic ip route add default via 169.254.0.1 dev $nic 2>/dev/null"
  kc patch networkinterface "$nic" --subresource=status --type=merge \
    -p "{\"status\":{\"vni\":$VNI,\"underlayRoute\":\"$ul\",\"state\":\"Ready\"}}" >/dev/null
  echo "  $nic @ $node underlay=$ul"
}
set_qos() { # nic egress_mbps public_mbps ingress_mbps  — PATCH ONLY (call apply_qos after both NICs)
  kc patch networkinterface "$1" --type=merge \
    -p "{\"spec\":{\"qos\":{\"egress\":{\"rateMbps\":$2,\"publicMbps\":$3},\"ingress\":{\"rateMbps\":$4}}}}" >/dev/null
}
apply_qos() { # ONE agent restart after both NICs are patched (per-call restarts race the reconcile)
  kc -n ectobase-system rollout restart ds/netplane-agent >/dev/null 2>&1
  kc -n ectobase-system rollout status ds/netplane-agent --timeout=60s >/dev/null 2>&1
  sleep 5
}
udp_run() { # iperf3 UDP A->B; echo "<recv_mbps> <loss_pct>" from the SERVER's received view.
  # NOTE: for UDP the authoritative server stats are in end.sum_received (end.sum is malformed:
  # bytes=0). Reading end.sum was the bug that made every run look like 0.0 recv.
  sudo docker exec "$NODE_B" ip netns exec "$NIC_B" /iperf3 -s --one-off -J >/tmp/g2g.json 2>/dev/null &
  local srv=$!; sleep 1
  sudo docker exec "$NODE_A" ip netns exec "$NIC_A" /iperf3 -u -b "${UDP_TARGET}M" -t "$IPERF_T" -l 1200 -c "$IP_B" >/dev/null 2>&1 || true
  wait $srv 2>/dev/null || true
  python3 - <<'PY' 2>/dev/null || echo "0 0"
import json
try:
    r=json.load(open("/tmp/g2g.json"))["end"]["sum_received"]
    print("%.1f %.1f" % (r["bits_per_second"]/1e6, r.get("lost_percent",0.0)))
except Exception:
    print("0 0")
PY
}
in_band() { awk "BEGIN{exit !($1>=$2*0.5 && $1<=$2*1.6)}"; }  # measured within [0.5x,1.6x] of cap

echo "== [0] kubeconfig + stack + iperf3 =="
sudo -E env "PATH=$PATH" kind get kubeconfig --name k01 > "$K1" 2>/dev/null
kc -n ectobase-system get ds flowplane >/dev/null 2>&1 || { echo "FAIL: stack not on k01"; exit 1; }
IPERF3=$(cat /tmp/iperf3_bin.txt 2>/dev/null); [ -x "$IPERF3" ] || IPERF3=$(nix build --no-link --print-out-paths nixpkgs#pkgsStatic.iperf3 2>/dev/null | grep '/nix/store' | grep -v -- '-man' | head -1)/bin/iperf3
[ -x "$IPERF3" ] || { echo "FAIL: no static iperf3"; exit 1; }
sudo docker cp "$IPERF3" "$NODE_A":/iperf3 >/dev/null 2>&1
sudo docker cp "$IPERF3" "$NODE_B":/iperf3 >/dev/null 2>&1
echo "  iperf3 staged into both nodes"

echo "== [1] CRDs: VPC + 2 cross-node NICs + allow-VPC NetworkPolicy (both dirs) =="
cat <<YAML | kc apply -f - >/dev/null || { echo "FAIL: apply CRs"; exit 1; }
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: blue, namespace: default}
spec: {vni: $VNI}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: $NIC_A, namespace: default, labels: {app: qosg2g}}
spec: {vpcRef: {name: blue}, ips: [$IP_A], nodeName: $NODE_A, qos: {egress: {rateMbps: 0, publicMbps: 0}, ingress: {rateMbps: 0}}}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: $NIC_B, namespace: default, labels: {app: qosg2g}}
spec: {vpcRef: {name: blue}, ips: [$IP_B], nodeName: $NODE_B, qos: {egress: {rateMbps: 0, publicMbps: 0}, ingress: {rateMbps: 0}}}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkPolicy
metadata: {name: qosg2g-allow, namespace: default}
spec:
  interfaceSelector: {matchLabels: {app: qosg2g}}
  ingress:
    - {cidr: "10.0.0.0/24", proto: TCP, action: Allow}
    - {cidr: "10.0.0.0/24", proto: UDP, action: Allow}
    - {cidr: "10.0.0.0/24", proto: ICMP, action: Allow}
  egress:
    - {cidr: "10.0.0.0/24", proto: TCP, action: Allow}
    - {cidr: "10.0.0.0/24", proto: UDP, action: Allow}
    - {cidr: "10.0.0.0/24", proto: ICMP, action: Allow}
YAML
kc patch vpc blue --subresource=status --type=merge -p "{\"status\":{\"vni\":$VNI,\"state\":\"Ready\"}}" >/dev/null

echo "== [2] attach both guests (interface_id == NIC name), on their nodes =="
attach_guest "$NODE_A" "$NIC_A" "$IP_A" || exit 1
attach_guest "$NODE_B" "$NIC_B" "$IP_B" || exit 1
kc -n ectobase-system rollout restart ds/netplane-agent >/dev/null 2>&1
kc -n ectobase-system rollout status ds/netplane-agent --timeout=60s >/dev/null 2>&1
sleep 5   # let routebus distribute A<->B overlay routes + firewall program

echo "== [3] CONNECTIVITY: A -> B over the overlay (proves cross-node routing + firewall) =="
CID=$(sudo docker create busybox:musl 2>/dev/null); sudo docker cp "$CID":/bin/busybox /tmp/busybox-musl >/dev/null 2>&1; sudo docker rm "$CID" >/dev/null 2>&1
sudo docker cp /tmp/busybox-musl "$NODE_A":/busybox 2>/dev/null
PING=$(sudo docker exec "$NODE_A" ip netns exec "$NIC_A" /busybox ping -c 3 -W 2 "$IP_B" 2>&1 | grep -E "transmitted")
echo "  $PING"
echo "$PING" | grep -q " 0% packet loss" && echo "  [conn] PASS" || fail "[conn] A cannot reach B over the overlay — routing/firewall not ready"

echo "== [E0] BASELINE: no caps — path ceiling (offer=${UDP_TARGET}M) =="
set_qos "$NIC_A" 0 0 0; set_qos "$NIC_B" 0 0 0; apply_qos
read -r B_R B_L <<<"$(udp_run)"; echo "  A->B recv=${B_R} Mbps loss=${B_L}%"

echo "== [E1] EDT SHAPING: A egress.rateMbps=$CAP_MBPS (B unlimited) — expect recv~$CAP_MBPS, LOW loss (paced) =="
set_qos "$NIC_A" "$CAP_MBPS" 0 0; set_qos "$NIC_B" 0 0 0; apply_qos
read -r E1_R E1_L <<<"$(udp_run)"; echo "  A->B recv=${E1_R} Mbps loss=${E1_L}%"
in_band "$E1_R" "$CAP_MBPS" && echo "  [E1] recv bound to cap: PASS" || fail "[E1] EDT recv=${E1_R} not near cap $CAP_MBPS"
awk "BEGIN{exit !($E1_L < 40)}" && echo "  [E1] low loss (shaping/pacing): PASS" || fail "[E1] EDT loss ${E1_L}% too high for a shaper"

echo "== [E2] INGRESS POLICE: B ingress.rateMbps=$CAP_MBPS (A unlimited) — expect recv~$CAP_MBPS, HIGH loss (dropped) =="
set_qos "$NIC_A" 0 0 0; set_qos "$NIC_B" 0 0 "$CAP_MBPS"; apply_qos
read -r E2_R E2_L <<<"$(udp_run)"; echo "  A->B recv=${E2_R} Mbps loss=${E2_L}%"
in_band "$E2_R" "$CAP_MBPS" && echo "  [E2] recv bound to cap: PASS" || fail "[E2] ingress recv=${E2_R} not near cap $CAP_MBPS"
awk "BEGIN{exit !($E2_L > 40)}" && echo "  [E2] high loss (policing/drops): PASS" || fail "[E2] ingress loss ${E2_L}% too low for a policer"

echo "== summary =="
if [ "$RESULT" = 0 ]; then
  echo "PASS: baseline=${B_R}M; EDT egress cap $CAP_MBPS -> ${E1_R}M @ ${E1_L}% loss (paced); ingress cap $CAP_MBPS -> ${E2_R}M @ ${E2_L}% loss (dropped)."
  echo "The 0%-loss-shaping vs high-loss-policing contrast at the same rate is the live proof EDT + the fq qdisc work."
else echo "SOME CHECKS FAILED (see FAIL lines)"; fi
exit $RESULT
