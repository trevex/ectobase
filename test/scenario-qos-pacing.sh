#!/usr/bin/env bash
# test/scenario-qos-pacing.sh — QoS / traffic-shaping validation on the live clab fabric.
#
# WHAT CLAB CAN vs CANNOT VALIDATE (learned empirically — see the header of the paired spec):
#   HARD asserts (clab-reliable):
#     A. CONFIG -> MAP : spec.qos -> ReconcileQoS -> ConfigureQoS gRPC -> flowplane "QOS configure"
#                        log (proves the cap reached set_qos / the METER map).
#     B. FQ QDISC      : the loader ran `tc qdisc replace dev <uplink> root fq` (the EDT pacer).
#     C. DATAPATH LOAD : the flowplane pods are Ready (uplink_rx + tc_guest_tx pass the kernel
#                        verifier) — this is where a real regression was caught: the 96-byte
#                        MeterState blew the 512-byte BPF stack until the meter wrappers switched to
#                        pointer-based in-place map access.
#     D. EGRESS WORKS  : with a cap programmed, a guest TCP flow still egresses (wget an external
#                        host through SNAT + the WAN edge) — proves the QoS-programmed tcx datapath
#                        forwards, not drops-all.
#   BEST-EFFORT (informational, NOT a hard assert — clab still can't PROVE veth EDT pacing):
#     E. THROUGHPUT    : iperf3 UDP from the guest at a target rate ABOVE the cap, received-rate +
#                        loss measured at a DEDICATED sink on the clabwan "internet" bridge
#                        (172.29.0.100 in its own netns) — NOT the host-self IP (172.29.0.1), whose
#                        double-NAT/host-local return path silently drops bulk TCP uploads (an
#                        earlier busybox+socat attempt hit exactly that; ICMP + real-internet egress
#                        DO work). UDP-at-target-rate is the textbook shaper-vs-policer probe: it
#                        removes the TCP-congestion-control confound. Expected at cap=C:
#                          - EDT egress (egress.rateMbps=C): received ~C Mbps, LOW loss (fq paces)
#                          - Policing  (publicMbps=C):       received ~C Mbps, HIGH loss (drops)
#                        Reported, not asserted, until validated on real hardware (Task 15). Falls
#                        back to a note if iperf3 can't be staged.
#
# PREREQ: fabric up (hack/clab-up.sh) + netplane stack on k01 built from THIS tree (the QoS code) +
#   images kind-loaded. Needs root + kubectl + grpcurl image + socat (flake devShell). For [E], a
#   static iperf3 is fetched via `nix build nixpkgs#pkgsStatic.iperf3` (portable across the host netns
#   + the kind node); if that's unavailable [E] is skipped with a note.
#   sudo -E env "PATH=/run/wrappers/bin:$HOME/go/bin:/run/current-system/sw/bin:$PATH" bash test/scenario-qos-pacing.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

VNI=100; NIC=qospod; SRC_NODE=k01-worker; SRC_IP=10.0.0.5
NAT_IP=203.0.113.1
CAP_MBPS="${CAP_MBPS:-20}"
INET_HTTP="${INET_HTTP:-1.1.1.1}"   # a real external host reachable through the WAN edge (egress proof)
# [E] iperf3 UDP throughput: dedicated sink on the clabwan bridge (its own netns + IP), NOT host-self.
SINK_NS=qossink; SINK_IP=172.29.0.100; SINK_BR=clabwan; SINK_PORT=5201
UDP_TARGET="${UDP_TARGET:-100}"     # UDP offered load (Mbps), well above CAP_MBPS so the cap binds
IPERF_T="${IPERF_T:-8}"             # test duration (s)
PROTO="$ROOT/api/proto"
K1=$(mktemp)
RESULT=0
fail() { echo "FAIL: $*"; RESULT=1; }
kc() { kubectl --kubeconfig "$K1" "$@"; }
grpc() { sudo docker run --rm --network "container:$1" -v "$PROTO":/proto:ro fullstorydev/grpcurl:latest \
  -plaintext -import-path /proto/dataplane/v1 -proto dataplane.proto -d "$2" 127.0.0.1:1337 "dataplane.v1.DataplaneNode/$3" 2>&1; }
xw() { sudo docker exec "$SRC_NODE" crictl ps 2>/dev/null | grep ' flowplane ' | awk '{print $1}' | head -1; }

# --- [E] iperf3 sink helpers -------------------------------------------------------------------
IPERF3=""   # resolved host path to a portable (static) iperf3, if available
stage_iperf3() {
  # A fully-static iperf3 runs unmodified in both the host netns sink AND the debian kind node.
  IPERF3=$(nix build --no-link --print-out-paths nixpkgs#pkgsStatic.iperf3 2>/dev/null)/bin/iperf3
  [ -x "$IPERF3" ] || { IPERF3=""; return 1; }
  sudo docker cp "$IPERF3" "$SRC_NODE":/iperf3 >/dev/null 2>&1 || return 1
}
sink_up() {
  # A dedicated iperf3 endpoint on the clabwan "internet" bridge in its own netns (172.29.0.100),
  # with a return route to the guest's NAT block via the two edges — behaves like a real external
  # host (the wget-to-1.1.1.1 path), unlike the host-self IP whose masquerade eats bulk TCP uploads.
  sudo ip netns del "$SINK_NS" 2>/dev/null || true
  sudo ip link del "${SINK_NS}0" 2>/dev/null || true
  sudo ip netns add "$SINK_NS"
  sudo ip link add "${SINK_NS}0" type veth peer name "${SINK_NS}1"
  sudo ip link set "${SINK_NS}0" master "$SINK_BR" up
  sudo ip link set "${SINK_NS}1" netns "$SINK_NS"
  sudo ip netns exec "$SINK_NS" ip addr add "$SINK_IP/24" dev "${SINK_NS}1"
  sudo ip netns exec "$SINK_NS" ip link set "${SINK_NS}1" up
  sudo ip netns exec "$SINK_NS" ip link set lo up
  sudo ip netns exec "$SINK_NS" ip route replace 203.0.113.0/28 \
    nexthop via 172.29.0.11 dev "${SINK_NS}1" nexthop via 172.29.0.12 dev "${SINK_NS}1"
}
sink_down() { sudo ip netns del "$SINK_NS" 2>/dev/null || true; sudo ip link del "${SINK_NS}0" 2>/dev/null || true; }
set_qos_via_cr() { # egress_mbps public_mbps ingress_mbps — patch spec.qos + re-trigger ReconcileQoS
  kc patch networkinterface "$NIC" --type=merge \
    -p "{\"spec\":{\"qos\":{\"egress\":{\"rateMbps\":$1,\"publicMbps\":$2},\"ingress\":{\"rateMbps\":$3}}}}" >/dev/null
  kc -n ectobase-system rollout restart ds/netplane-agent >/dev/null 2>&1
  kc -n ectobase-system rollout status ds/netplane-agent --timeout=60s >/dev/null 2>&1
  sleep 3
}
trap 'sink_down' EXIT   # always tear the [E] sink netns/veth down, even on early exit
udp_run() { # $1 = qos-lane label (for logging); server received-rate + loss via iperf3 -J at the sink
  local out srv
  sudo ip netns exec "$SINK_NS" "$IPERF3" -s --one-off -J >/tmp/qos-iperf.json 2>/dev/null &
  srv=$!; sleep 1
  sudo docker exec "$SRC_NODE" ip netns exec "$NIC" /iperf3 -u -b "${UDP_TARGET}M" -t "$IPERF_T" -l 1200 \
    -c "$SINK_IP" >/dev/null 2>&1 || true
  wait $srv 2>/dev/null || true
  # Parse the server's received throughput + loss from iperf3 JSON (python3 from the flake pythonEnv).
  python3 - <<'PY' 2>/dev/null || echo "parse-failed"
import json,sys
try:
    d=json.load(open("/tmp/qos-iperf.json")); s=d["end"]["sum"]
    print("%.1f Mbit/s, %.1f%% loss" % (s["bits_per_second"]/1e6, s.get("lost_percent",0.0)))
except Exception:
    print("no-data")
PY
}

echo "== [0] kubeconfig + stack =="
sudo -E env "PATH=$PATH" kind get kubeconfig --name k01 > "$K1" 2>/dev/null
kc -n ectobase-system get ds flowplane >/dev/null 2>&1 || { echo "FAIL: netplane stack not on k01"; exit 1; }

echo "== [C] DATAPATH LOAD: flowplane pods Ready (uplink_rx + tc_guest_tx pass the verifier) =="
if kc -n ectobase-system rollout status ds/flowplane --timeout=90s >/dev/null 2>&1; then
  echo "  flowplane DaemonSet Ready on all nodes"; echo "  [C] PASS"
else
  fail "[C] flowplane not Ready — check logs for 'combined stack size ... Too large' (BPF verifier)"; fi

echo "== [1] CRDs: VPC + NIC (spec.qos egress=$CAP_MBPS) + NATGateway + EGRESS NetworkPolicy =="
cat <<YAML | kc apply -f - >/dev/null || { echo "FAIL: apply CRs"; exit 1; }
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: blue, namespace: default}
spec: {vni: $VNI}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: $NIC, namespace: default, labels: {app: qospod}}
spec:
  vpcRef: {name: blue}
  ips: [$SRC_IP]
  nodeName: $SRC_NODE
  qos: {egress: {rateMbps: $CAP_MBPS, publicMbps: 0}, ingress: {rateMbps: 0}}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NATGateway
metadata: {name: egress-gw, namespace: default}
spec: {vpcRef: {name: blue}, publicIPs: [$NAT_IP], portsPerSource: 1024}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkPolicy
metadata: {name: qospod-egress, namespace: default}
spec:
  interfaceSelector: {matchLabels: {app: qospod}}
  egress:
    - {cidr: "0.0.0.0/0", proto: TCP, action: Allow}
    - {cidr: "0.0.0.0/0", proto: ICMP, action: Allow}
YAML
kc patch vpc blue --subresource=status --type=merge -p "{\"status\":{\"vni\":$VNI,\"state\":\"Ready\"}}" >/dev/null
for _ in $(seq 1 30); do kc get natgateway egress-gw -o jsonpath='{.status.allocations}' 2>/dev/null | grep -q "$SRC_IP" && break; sleep 1; done

echo "== [2] attach endpoint (interface_id == NIC name) + netns route to dataplane gw =="
grpc "$SRC_NODE" "{\"interface_id\":\"$NIC\"}" DetachInterface >/dev/null 2>&1 || true
sudo docker exec "$SRC_NODE" ip netns add "$NIC" 2>/dev/null || true
OUT=$(grpc "$SRC_NODE" "{\"interface_id\":\"$NIC\",\"netns_path\":\"/var/run/netns/$NIC\",\"vni\":$VNI,\"requested_ips\":[\"$SRC_IP\"]}" AttachInterface)
UL=$(echo "$OUT" | grep -o 'fd00:[0-9a-f:]*' | head -1)
[ -n "$UL" ] || { echo "FAIL: attach: $OUT"; exit 1; }
echo "  underlay=$UL"
sudo docker exec "$SRC_NODE" sh -c "ip netns exec $NIC ip addr add $SRC_IP/32 dev $NIC 2>/dev/null; \
  ip netns exec $NIC ip route add 169.254.0.1/32 dev $NIC 2>/dev/null; \
  ip netns exec $NIC ip route add default via 169.254.0.1 dev $NIC 2>/dev/null"
kc patch networkinterface "$NIC" --subresource=status --type=merge -p "{\"status\":{\"vni\":$VNI,\"underlayRoute\":\"$UL\",\"state\":\"Ready\"}}" >/dev/null
kc -n ectobase-system rollout restart ds/netplane-agent >/dev/null 2>&1
kc -n ectobase-system rollout status ds/netplane-agent --timeout=60s >/dev/null 2>&1

echo "== [3] WAN edge + VyOS default + host return route (harness quirks) =="
bash "$ROOT/hack/clab/edge-agents-up.sh" >/dev/null 2>&1 || true
for e in edge1 edge2; do sudo docker exec clab-xdp-ipv6-fabric-$e ip route replace default via 172.29.0.1 dev eth2 >/dev/null 2>&1; done
sudo ip route replace 203.0.113.0/28 nexthop via 172.29.0.11 dev clabwan nexthop via 172.29.0.12 dev clabwan 2>/dev/null || true
CID=$(sudo docker create busybox:musl 2>/dev/null); sudo docker cp "$CID":/bin/busybox /tmp/busybox-musl >/dev/null 2>&1; sudo docker rm "$CID" >/dev/null 2>&1
sudo docker cp /tmp/busybox-musl "$SRC_NODE":/busybox 2>/dev/null
sleep 4

echo "== [A] CONFIG -> MAP: agent logs 'QOS configure' for $NIC =="
XW=$(xw); OK_A=0
for _ in $(seq 1 30); do
  if sudo docker exec "$SRC_NODE" crictl logs "$XW" 2>&1 | grep -q "QOS configure iface=$NIC .*egress_mbps=$CAP_MBPS"; then OK_A=1; break; fi
  sleep 2
done
if [ "$OK_A" = 1 ]; then
  sudo docker exec "$SRC_NODE" crictl logs "$XW" 2>&1 | grep "QOS configure iface=$NIC" | tail -1 | sed 's/^/  /'; echo "  [A] PASS"
else fail "[A] no 'QOS configure iface=$NIC egress_mbps=$CAP_MBPS' log"; fi

echo "== [B] FQ QDISC on the uplink of $SRC_NODE =="
QD=$(sudo docker exec "$SRC_NODE" tc qdisc show 2>/dev/null | grep -E 'qdisc fq ' | head -1)
if [ -n "$QD" ]; then echo "  $QD"; echo "  [B] PASS"; else fail "[B] no 'fq' root qdisc on $SRC_NODE uplink"; fi

echo "== [D] EGRESS WORKS through the QoS-programmed datapath: guest wget http://$INET_HTTP/ =="
RESP=$(sudo docker exec "$SRC_NODE" ip netns exec "$NIC" /busybox wget -T 8 -S -O /dev/null "http://$INET_HTTP/" 2>&1 | grep -iE "HTTP/" | head -1)
if echo "$RESP" | grep -qiE "HTTP/"; then echo "  $RESP"; echo "  [D] PASS"; else fail "[D] guest TCP egress failed (no HTTP response from $INET_HTTP)"; fi

echo "== [E] THROUGHPUT via iperf3 UDP -> clabwan sink (informational; shaper-vs-policer probe) =="
if stage_iperf3; then
  sink_up
  echo "  sink up: iperf3 -s @ $SINK_IP (netns $SINK_NS on $SINK_BR); UDP offered=${UDP_TARGET}M, cap=${CAP_MBPS}"
  # EDT lane: egress.rateMbps=cap, public unlimited -> fq should pace to ~cap with LOW loss.
  set_qos_via_cr "$CAP_MBPS" 0 0
  echo "  EDT egress=${CAP_MBPS}M   -> $(udp_run edt)   (expect ~${CAP_MBPS} Mbit/s, low loss = pacing)"
  # Public lane: publicMbps=cap, egress unlimited -> token-bucket drops -> ~cap with HIGH loss.
  set_qos_via_cr 0 "$CAP_MBPS" 0
  echo "  POLICE public=${CAP_MBPS}M -> $(udp_run police)   (expect ~${CAP_MBPS} Mbit/s, high loss = policing)"
  sink_down
  echo "  [E] informational — assert on real hardware (clab veth EDT pacing is not yet proven)."
else
  echo "  iperf3 unavailable (nix build nixpkgs#pkgsStatic.iperf3 failed) — [E] skipped."
  echo "  Datapath egress itself is proven by [D]. Precise pacing rate is a real-hardware measurement."
fi

echo "== summary =="
if [ "$RESULT" = 0 ]; then
  echo "HARD CHECKS PASS: [C] datapath loads, [A] config->METER, [B] fq qdisc, [D] egress works. [E] throughput informational."
else echo "SOME HARD CHECKS FAILED (see FAIL lines)"; fi
exit $RESULT
