#!/usr/bin/env bash
# test/scenario-restart.sh — Graceful datapath restart kill-test (hardening item #1).
#
# Proves that an xdp-dp PROCESS restart (crictl stop -> kubelet restarts the container; the pod
# sandbox, guest netns, and host veths stay up) does NOT drop the node's overlay datapath STATE and
# does NOT reissue a live guest underlay /128. This is the acceptance test for the pinned-maps +
# adopt work:
#   - state maps are declared `pinned` (survive the restart on bpffs),
#   - Serve adopts them (map_pin_path reuse), rebuilds bookkeeping from the IFACE_META journal,
#     re-attaches each guest program, and reseeds UnderlayIpam from the surviving UNDERLAY map.
#
# It is deliberately node-local and self-contained (attaches a pod directly via the DataplaneNode
# gRPC), so it does NOT depend on the WAN-edge / SNAT return path.
#
# KNOWN FABRIC LIMITATION: on the containerlab kind SKB fabric, aya's tc-clsact filter attach on a
# guest veth silently no-ops (see the `clab-container-datapath-gaps` note), so the guest EGRESS
# program never actually forwards here — for EITHER the original attach or the restart re-attach.
# End-to-end packet egress is therefore NOT a reliable signal on this fabric; this test asserts the
# datapath STATE survival + IPAM correctness (which are fabric-independent) and reports the egress
# check as informational. On a native-XDP fabric the egress assertion becomes meaningful.
#
# PREREQ: fabric up (hack/clab-up.sh) + netplane stack on k01, running an image built from THIS
# branch (make image TAG=dev && kind load docker-image ghcr.io/trevex/dpservice-xdp:dev --name k01
# && kubectl -n ectobase-system rollout restart ds/xdp-dp).
#   sudo -E env "PATH=/run/wrappers/bin:$HOME/go/bin:/run/current-system/sw/bin:$PATH" bash test/scenario-restart.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

SRC_NODE=k01-worker; VNI=100; PIN=/sys/fs/bpf/xdp-dp
# Dedicated overlay IPs so this test never collides with a pod left attached by another scenario
# (create_interface rejects a duplicate (vni, ipv4) with ROUTE_EXISTS).
NIC=rpod; SRC_IP=10.0.0.31
NIC2=rpod2; SRC_IP2=10.0.0.32                                # second pod, attached AFTER the restart
PROTO="$ROOT/api/proto"
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; exit 1; }
grpc() { sudo docker run --rm --network "container:$SRC_NODE" -v "$PROTO":/proto:ro fullstorydev/grpcurl:latest \
  -plaintext -import-path /proto/dataplane/v1 -proto dataplane.proto -d "$1" 127.0.0.1:1337 "dataplane.v1.DataplaneNode/$2" 2>&1; }
DUMP() { sudo docker exec "$SRC_NODE" bpftool map dump pinned "$PIN/$1" 2>/dev/null; }
COUNT() { DUMP "$1" | grep -c '^key:'; }
xdp_cid() { sudo docker exec "$SRC_NODE" crictl ps 2>/dev/null | grep ' xdp-dp ' | awk '{print $1}' | head -1; }

echo "== [0] attach a pod directly via the DataplaneNode gRPC (node-local, no WAN deps) =="
grpc "{\"interface_id\":\"$NIC\"}" DetachInterface >/dev/null 2>&1
sudo docker exec "$SRC_NODE" ip netns add "$NIC" 2>/dev/null || true
OUT=$(grpc "{\"interface_id\":\"$NIC\",\"netns_path\":\"/var/run/netns/$NIC\",\"vni\":$VNI,\"requested_ips\":[\"$SRC_IP\"]}" AttachInterface)
UL1=$(echo "$OUT" | grep -o 'fd00:[0-9a-f:]*' | head -1)
[ -n "$UL1" ] || fail "attach failed: $OUT"
pass "attached $NIC; underlay=$UL1"

echo "== [1] datapath is PINNED + programmed before the kill =="
sudo docker exec "$SRC_NODE" ls "$PIN/INTERFACES" "$PIN/UNDERLAY" "$PIN/IFACE_META" >/dev/null 2>&1 \
  || fail "state maps not pinned under $PIN — is the DS running the branch image?"
[ "$(COUNT UNDERLAY)" -ge 1 ] || fail "UNDERLAY empty before kill"
[ "$(COUNT IFACE_META)" -ge 1 ] || fail "IFACE_META (journal) empty before kill"
CID_OLD=$(xdp_cid); pass "pins present; UNDERLAY=$(COUNT UNDERLAY) IFACE_META=$(COUNT IFACE_META); xdp-dp=$CID_OLD"

echo "== [2] KILL the xdp-dp container (crictl stop) — kubelet restarts it, Serve adopts =="
sudo docker exec "$SRC_NODE" crictl stop "$CID_OLD" >/dev/null 2>&1 || fail "crictl stop failed"
CID_NEW=""; ADOPTED=""
for _ in $(seq 1 45); do
  CID_NEW=$(xdp_cid)
  if [ -n "$CID_NEW" ] && [ "$CID_NEW" != "$CID_OLD" ]; then
    sudo docker exec "$SRC_NODE" crictl logs "$CID_NEW" 2>&1 | grep -qi "adopt: recovered" && { ADOPTED=1; break; }
  fi
  sleep 2
done
[ -n "$CID_NEW" ] && [ "$CID_NEW" != "$CID_OLD" ] || fail "no new xdp-dp container appeared"
[ -n "$ADOPTED" ] || fail "new container ($CID_NEW) did not log an adopt recovery line"
sudo docker exec "$SRC_NODE" crictl logs "$CID_NEW" 2>&1 | grep -iE "adopt|recovered|re-attach" | sed 's/^/    | /'
pass "restarted: $CID_OLD -> $CID_NEW adopted the pinned datapath"

echo "== [3] STATE SURVIVED: the pinned maps still describe the pod =="
[ "$(COUNT UNDERLAY)" -ge 1 ] || fail "UNDERLAY empty after restart — state lost"
[ "$(COUNT INTERFACES)" -ge 1 ] || fail "INTERFACES empty after restart — state lost"
[ "$(COUNT IFACE_META)" -ge 1 ] || fail "IFACE_META empty after restart — journal lost"
# Compare space-stripped hex: bpftool prints the 16-byte key as two 8-byte groups (double space).
UL1_HEX=$(python3 -c "import ipaddress; print(''.join(f'{b:02x}' for b in ipaddress.IPv6Address('$UL1').packed))" 2>/dev/null)
if [ -n "$UL1_HEX" ]; then
  DUMP UNDERLAY | tr -d ' \n' | grep -qi "$UL1_HEX" && pass "pod /128 ($UL1) still present in pinned UNDERLAY" \
    || fail "pod /128 ($UL1) missing from UNDERLAY after restart"
else
  pass "UNDERLAY non-empty after restart (python3 missing; skipped exact /128 match)"
fi

echo "== [4] guest program re-attach (best-effort on clab; informational) =="
if sudo docker exec "$SRC_NODE" tc filter show dev "veth-$NIC" ingress 2>/dev/null | grep -qi bpf; then
  pass "guest tc program re-attached to veth-$NIC"
else
  echo "    INFO: no tc bpf filter on veth-$NIC after restart. On the clab kind SKB fabric aya's"
  echo "    tc-clsact attach silently no-ops (affects the ORIGINAL attach identically), so this is a"
  echo "    fabric limitation, not a restart regression. The adopt log above shows re-attach was run."
fi

echo "== [5] IPAM did NOT reissue the live /128: a NEW pod gets a DIFFERENT /128 =="
grpc "{\"interface_id\":\"$NIC2\"}" DetachInterface >/dev/null 2>&1
sudo docker exec "$SRC_NODE" ip netns add "$NIC2" 2>/dev/null || true
OUT2=$(grpc "{\"interface_id\":\"$NIC2\",\"netns_path\":\"/var/run/netns/$NIC2\",\"vni\":$VNI,\"requested_ips\":[\"$SRC_IP2\"]}" AttachInterface)
UL2=$(echo "$OUT2" | grep -o 'fd00:[0-9a-f:]*' | head -1)
[ -n "$UL2" ] || fail "second attach failed: $OUT2"
echo "    $NIC=$UL1   $NIC2=$UL2"
[ "$UL2" != "$UL1" ] || fail "REISSUE BUG: $NIC2 got the live /128 $UL1 — mark_used rebuild failed"
pass "$NIC2 got a distinct /128 — used-set rebuilt from surviving UNDERLAY (no live /128 reissued)"

echo "== [6] cleanup =="
grpc "{\"interface_id\":\"$NIC2\"}" DetachInterface >/dev/null 2>&1
sudo docker exec "$SRC_NODE" ip netns del "$NIC2" 2>/dev/null || true

echo "== ALL DETERMINISTIC CHECKS PASSED: state survived an xdp-dp restart; no live /128 reissued =="
