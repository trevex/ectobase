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
#   BEST-EFFORT (informational, NOT a hard assert — clab CANNOT reliably measure it):
#     E. THROUGHPUT    : a bulk guest upload measured at a sink. In clab the only easy sink is the
#                        clabwan HOST IP (172.29.0.1), and a bulk TCP upload to the host-self through
#                        the double-NAT return path does not land reliably (ICMP + real-internet
#                        egress DO). So the achieved-rate-vs-cap number — the actual proof of EDT
#                        pacing vs policing — remains a REAL-HARDWARE measurement (Task 15). This
#                        step measures + reports what it can and never fails the run.
#
# PREREQ: fabric up (hack/clab-up.sh) + netplane stack on k01 built from THIS tree (the QoS code) +
#   images kind-loaded. Needs root + kubectl + grpcurl image + socat (flake devShell).
#   sudo -E env "PATH=/run/wrappers/bin:$HOME/go/bin:/run/current-system/sw/bin:$PATH" bash test/scenario-qos-pacing.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

VNI=100; NIC=qospod; SRC_NODE=k01-worker; SRC_IP=10.0.0.5
NAT_IP=203.0.113.1
CAP_MBPS="${CAP_MBPS:-20}"
INET_HTTP="${INET_HTTP:-1.1.1.1}"   # a real external host reachable through the WAN edge (egress proof)
SINK_HOST=172.29.0.1; SINK_PORT=5206; WIN=10   # best-effort upload sink (clabwan host)
PROTO="$ROOT/api/proto"
K1=$(mktemp)
RESULT=0
fail() { echo "FAIL: $*"; RESULT=1; }
kc() { kubectl --kubeconfig "$K1" "$@"; }
grpc() { sudo docker run --rm --network "container:$1" -v "$PROTO":/proto:ro fullstorydev/grpcurl:latest \
  -plaintext -import-path /proto/dataplane/v1 -proto dataplane.proto -d "$2" 127.0.0.1:1337 "dataplane.v1.DataplaneNode/$3" 2>&1; }
xw() { sudo docker exec "$SRC_NODE" crictl ps 2>/dev/null | grep ' flowplane ' | awk '{print $1}' | head -1; }

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

echo "== [E] THROUGHPUT (best-effort, NOT asserted — clab host-sink return path is unreliable) =="
# Fixed-window upload to a non-sudo socat sink on the clabwan host (sudo strips the nix socat PATH).
rm -f /tmp/qos-sink.bin; pkill -f "socat.*TCP-LISTEN:$SINK_PORT" 2>/dev/null || true
timeout $((WIN+2)) socat -u TCP-LISTEN:$SINK_PORT,reuseaddr,fork OPEN:/tmp/qos-sink.bin,creat,append >/dev/null 2>&1 &
SP=$!; sleep 1
sudo docker exec "$SRC_NODE" ip netns exec "$NIC" sh -c \
  "timeout $WIN sh -c 'dd if=/dev/zero bs=64k 2>/dev/null | /busybox nc $SINK_HOST $SINK_PORT'" >/dev/null 2>&1 || true
sleep 1; kill $SP 2>/dev/null || true; pkill -f "socat.*TCP-LISTEN:$SINK_PORT" 2>/dev/null || true
BYTES=$(stat -c%s /tmp/qos-sink.bin 2>/dev/null || echo 0)
MBPS=$(awk "BEGIN{printf \"%.1f\", ($BYTES*8)/$WIN/1000000}")
if [ "$BYTES" -gt 0 ]; then
  echo "  measured egress = ${MBPS} Mbit/s over ${WIN}s (cap=$CAP_MBPS)  [informational]"
else
  echo "  no bytes at sink — clab host-sink upload path did not land (expected; ICMP + real-internet"
  echo "  egress DO work — see [D]). Precise EDT pacing rate is a real-hardware measurement."
fi

echo "== summary =="
if [ "$RESULT" = 0 ]; then
  echo "HARD CHECKS PASS: [C] datapath loads, [A] config->METER, [B] fq qdisc, [D] egress works. [E] throughput informational."
else echo "SOME HARD CHECKS FAILED (see FAIL lines)"; fi
exit $RESULT
