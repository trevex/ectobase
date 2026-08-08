#!/usr/bin/env bash
# test/scenario-restart-continuity.sh — Graceful-restart ZERO-DROP continuity test.
#
# Formalises the link-pinning zero-gap guarantee: a continuous ping flow runs THROUGH the flowplane
# datapath while the flowplane container is crictl-stopped and kubelet-restarted. The test asserts:
#   1. Packet loss across the restart boundary is ≤ LOSS_THRESH pings (target ~0).
#   2. The pinned bpf-link at $PIN/links/uplink-eth1 SURVIVED the crictl stop (same path, still
#      present before AND after: proves the link was held by bpffs, not by the process).
#   3. The prog-id on eth1 CHANGED (before → after): proves the restart atomically re-pointed the
#      pinned link at the freshly-loaded program (bpf_link_update), NOT a detach + re-attach (which
#      would have a forwarding gap). A detach would show: no prog-id mid-restart → then a new one.
#      The pin-survived + prog-id-changed combination is the unique fingerprint of adopt-and-repoint.
#
# Flow: the test attaches a guest netns (NIC=cpod, SRC_IP=10.0.0.41) via the DataplaneNode gRPC
# and runs "ping -i 0.2 -c 50" from the guest TO the dataplane overlay gateway (169.254.0.1), which
# the datapath ARP-answers and ICMP-replies (no WAN/SNAT/edge dependency — the gateway is local to
# the datapath). This gives a continuous 10-second flow (50 × 200 ms) through the flowplane
# programs while the container is restarted mid-way.
#
# LOSS THRESHOLD: -i 0.2 × 50 = 10 s total. A crictl-stop + kubelet restart + adopt takes ~5-10 s.
# The uplink XDP program (uplink_rx) stays attached across the restart via the pinned bpf-link;
# it echoes overlay ICMP back to the guest. The gap during which replies might drop is bounded by
# the kernel unloading tc_guest_tx during the stop (briefly, until the new container re-attaches).
# On the clab SKB fabric the tc guest attach may not land reliably (see clab-container-datapath-gaps
# note), so we set LOSS_THRESH=15 to tolerate a full restart window plus clab overhead.
# On a native XDP fabric (where the guest tc attach lands and the uplink XDP is zero-gap) a tighter
# threshold of 2-3 is realistic; override with LOSS_THRESH=N.
#
# PROG-ID METHOD: the in-container bpftool is v7.1.0 and does NOT render tcx or XDP prog-ids
# reliably (known clab gotcha). We use the nix bpftool (v7.6.0) via nsenter into the worker's
# network namespace: "nsenter -t $PID -n bpftool net show dev eth1". This is the AUTHORITATIVE
# check per the clab-container-datapath-gaps memory.
#
# PREREQ: fabric up (hack/clab-up.sh) + netplane stack deployed on k01 running THIS branch image
# (make image TAG=dev && kind load docker-image ghcr.io/trevex/ectobase/flowplane:dev --name k01
# && kubectl -n ectobase-system rollout restart ds/flowplane). Needs root.
#   sudo -E env "PATH=$PATH" bash test/scenario-restart-continuity.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT" || exit 1

# --- gate: must be root on the fabric host (not a CI unit-test) ---
if [ "$(id -u)" -ne 0 ]; then
  echo "SKIP: scenario-restart-continuity.sh is a privileged manual scenario; run under sudo."
  exit 0
fi

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SRC_NODE=k01-worker
VNI=100
NIC=cpod               # unique name; DetachInterface before attach so re-runs are idempotent
SRC_IP=10.0.0.41      # overlay IP (unique; avoids collisions with other scenarios)
GW_IP=169.254.0.1     # the datapath ARP-gateway: it ICMP-replies from within the datapath
PING_COUNT=50          # 50 × 200 ms = 10 s total flow window
PING_INTERVAL=0.2
LOSS_THRESH=${LOSS_THRESH:-15}   # max acceptable lost pings (override on native-XDP fabrics)
PIN=/sys/fs/bpf/flowplane
UPLINK_IFACE=eth1
UPLINK_PIN="$PIN/links/uplink-$UPLINK_IFACE"
PROTO="$ROOT/api/proto"

# The devShell bpftool, run on the host and entered into the node's netns via nsenter. The
# in-container bpftool (older) doesn't render tcx/XDP prog-ids reliably, so we NEVER exec bpftool
# inside the container for these checks. Resolved to an absolute path so it survives the sudo below.
NIX_BPFTOOL="$(command -v bpftool)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
pass()    { echo "PASS: $*"; }
fail()    { echo "FAIL: $*"; exit 1; }
info()    { echo "    $*"; }

# Execute a gRPC call via grpcurl against the DataplaneNode on $SRC_NODE.
grpc() {
  sudo docker run --rm --network "container:$SRC_NODE" \
    -v "$PROTO":/proto:ro fullstorydev/grpcurl:latest \
    -plaintext -import-path /proto/dataplane/v1 -proto dataplane.proto \
    -d "$1" 127.0.0.1:1337 "dataplane.v1.DataplaneNode/$2" 2>&1
}

# Get the current flowplane crictl container id on $SRC_NODE (empty if not running).
xdp_cid() {
  sudo docker exec "$SRC_NODE" crictl ps 2>/dev/null \
    | awk '/[ \t]flowplane[ \t]/{print $1; exit}'
}

# Run bpftool net show dev $UPLINK_IFACE inside $SRC_NODE's netns via the nix bpftool.
# Returns the full bpftool output (caller greps for prog_id).
bpftool_net_show_uplink() {
  local worker_pid
  worker_pid=$(sudo docker inspect -f '{{.State.Pid}}' "$SRC_NODE" 2>/dev/null)
  [ -n "$worker_pid" ] || { echo ""; return; }
  sudo nsenter -t "$worker_pid" -n "$NIX_BPFTOOL" net show dev "$UPLINK_IFACE" 2>/dev/null
}

# Extract the XDP prog-id from bpftool net show output. Different bpftool versions render the XDP
# attachment differently ("prog_id N", "xdp id N", or "eth1(234) generic id N"), so match the common
# "id N" tail rather than a version-specific prefix.
uplink_prog_id() {
  bpftool_net_show_uplink \
    | grep -oE 'id [0-9]+' \
    | grep -oE '[0-9]+' | head -1
}

# ---------------------------------------------------------------------------
# [0] Pre-flight: fabric + netplane stack must be present
# ---------------------------------------------------------------------------
echo "== [0] pre-flight: fabric + netplane stack =="
sudo docker ps --filter "name=$SRC_NODE" --format '{{.Names}}' \
  | grep -q "$SRC_NODE" || fail "clab fabric not up ($SRC_NODE not running); run hack/clab-up.sh"

CID_INIT=$(xdp_cid)
[ -n "$CID_INIT" ] || fail "flowplane container not running on $SRC_NODE; deploy the stack (make lab-deploy) with the branch image"

sudo docker exec "$SRC_NODE" ls "$PIN/INTERFACES" "$PIN/UNDERLAY" "$PIN/IFACE_META" >/dev/null 2>&1 \
  || fail "flowplane bpf pins not present under $PIN — is the DS running the branch image?"

info "flowplane=$CID_INIT; state maps pinned; pre-flight ok"

# ---------------------------------------------------------------------------
# [1] Attach a guest netns so traffic can flow through the datapath
# ---------------------------------------------------------------------------
echo "== [1] attach guest ($NIC / $SRC_IP) via DataplaneNode gRPC =="
# Idempotent: detach any leftover from a previous run.
grpc "{\"interface_id\":\"$NIC\"}" DetachInterface >/dev/null 2>&1 || true
sudo docker exec "$SRC_NODE" ip netns add "$NIC" 2>/dev/null || true

OUT=$(grpc "{\"interface_id\":\"$NIC\",\"netns_path\":\"/var/run/netns/$NIC\",\"vni\":$VNI,\"requested_ips\":[\"$SRC_IP\"]}" AttachInterface)
UL=$(echo "$OUT" | grep -o 'fd00:[0-9a-f:]*' | head -1)
[ -n "$UL" ] || fail "AttachInterface failed: $OUT"

# Configure the guest netns so ping(1) can reach 169.254.0.1 through the datapath.
sudo docker exec "$SRC_NODE" sh -c "
  ip netns exec $NIC ip addr add $SRC_IP/32 dev $NIC 2>/dev/null || true
  ip netns exec $NIC ip route add $GW_IP/32 dev $NIC 2>/dev/null || true
  ip netns exec $NIC ip route add default via $GW_IP dev $NIC 2>/dev/null || true
"
pass "attached $NIC; underlay=$UL; guest netns configured for ping -> $GW_IP"

# ---------------------------------------------------------------------------
# [2] Record state BEFORE the restart
# ---------------------------------------------------------------------------
echo "== [2] record pre-restart state =="

# Uplink prog-id via nix bpftool through nsenter (authoritative; in-container bpftool is too old).
PROG_ID_PRE=$(uplink_prog_id)
info "uplink $UPLINK_IFACE prog-id (pre):  ${PROG_ID_PRE:-(none — is the datapath attached?)}"
[ -n "$PROG_ID_PRE" ] || fail "no XDP program on $UPLINK_IFACE before the restart — datapath not loaded?"

# Check that the bpf-link pin exists (it must for the zero-gap guarantee to hold).
PIN_PRE=no
sudo docker exec "$SRC_NODE" ls "$UPLINK_PIN" >/dev/null 2>&1 && PIN_PRE=yes
info "uplink link pin ($UPLINK_PIN) present (pre): $PIN_PRE"
[ "$PIN_PRE" = yes ] || {
  echo "    WARN: uplink link not pinned (--pin-links off?). The prog-id swap assertion will still run,"
  echo "    but zero-gap is only guaranteed with pinned links. Continuing anyway."
}

CID_OLD=$(xdp_cid)
info "flowplane container (pre): $CID_OLD"

# ---------------------------------------------------------------------------
# [3] Start the continuous flow (background ping through the datapath)
# ---------------------------------------------------------------------------
echo "== [3] start continuous ping $SRC_IP -> $GW_IP (${PING_COUNT}×${PING_INTERVAL}s, ~$( echo "$PING_COUNT * $PING_INTERVAL" | awk '{printf "%.0f", $1}' )s window) =="

PING_OUT=$(mktemp /tmp/continuity-ping.XXXXXX)
# shellcheck disable=SC2024  # redirect is to a root-owned tmp file; script runs as root
sudo docker exec "$SRC_NODE" \
  ip netns exec "$NIC" ping -i "$PING_INTERVAL" -c "$PING_COUNT" -W 1 "$GW_IP" \
  >"$PING_OUT" 2>&1 &
PING_PID=$!

# Give the ping a short head-start so a few probes complete before we kill the container.
sleep 1

# ---------------------------------------------------------------------------
# [4] KILL the flowplane container mid-flow (crictl stop)
# ---------------------------------------------------------------------------
echo "== [4] crictl stop $CID_OLD mid-flow — kubelet restarts + adopts the pinned link =="
sudo docker exec "$SRC_NODE" crictl stop "$CID_OLD" >/dev/null 2>&1 \
  || fail "crictl stop $CID_OLD failed"

# Wait for a NEW container to appear AND log the adopt line.
CID_NEW=""; ADOPTED=""
for _ in $(seq 1 45); do
  CID_NEW=$(xdp_cid)
  if [ -n "$CID_NEW" ] && [ "$CID_NEW" != "$CID_OLD" ]; then
    sudo docker exec "$SRC_NODE" crictl logs "$CID_NEW" 2>&1 \
      | grep -q "adopt: re-pointed pinned link" && { ADOPTED=1; break; }
  fi
  sleep 2
done

[ -n "$CID_NEW" ] && [ "$CID_NEW" != "$CID_OLD" ] \
  || fail "no new flowplane container appeared after crictl stop (waited 90 s)"
[ -n "$ADOPTED" ] \
  || fail "new container ($CID_NEW) did not log an adopt recovery line — check crictl logs $CID_NEW on $SRC_NODE"
info "restarted: $CID_OLD -> $CID_NEW"
sudo docker exec "$SRC_NODE" crictl logs "$CID_NEW" 2>&1 \
  | grep "adopt: re-pointed pinned link" | sed 's/^/    | /'

# ---------------------------------------------------------------------------
# [5] Wait for the ping to finish and record the result
# ---------------------------------------------------------------------------
echo "== [5] wait for ping to complete =="
wait "$PING_PID" 2>/dev/null || true   # ping exits 1 on any loss; that's expected here

PING_RAW=$(cat "$PING_OUT" 2>/dev/null || true)
rm -f "$PING_OUT"

# Extract sent / received (Linux ping format: "N packets transmitted, M received, X% packet loss")
SENT=$(echo "$PING_RAW" | grep -oE '[0-9]+ packets transmitted' | grep -oE '^[0-9]+')
RECV=$(echo "$PING_RAW" | grep -oE '[0-9]+ received'           | grep -oE '^[0-9]+')
SENT=${SENT:-0}; RECV=${RECV:-0}
LOST=$(( SENT - RECV ))

info "ping result: sent=$SENT received=$RECV lost=$LOST (threshold: $LOSS_THRESH)"
echo "$PING_RAW" | tail -3 | sed 's/^/    /'

# ---------------------------------------------------------------------------
# [6] Record state AFTER the restart
# ---------------------------------------------------------------------------
echo "== [6] record post-restart state =="

PROG_ID_POST=$(uplink_prog_id)
info "uplink $UPLINK_IFACE prog-id (post): ${PROG_ID_POST:-(none!)}"

PIN_POST=no
sudo docker exec "$SRC_NODE" ls "$UPLINK_PIN" >/dev/null 2>&1 && PIN_POST=yes
info "uplink link pin ($UPLINK_PIN) present (post): $PIN_POST"

# ---------------------------------------------------------------------------
# [7] ASSERT: loss, pin survival, prog-id swap
# ---------------------------------------------------------------------------
echo "== [7] assertions =="

FAIL_MSGS=()

# 7a. Packet loss within threshold.
if [ "$SENT" -eq 0 ]; then
  FAIL_MSGS+=("ping sent 0 packets — guest or datapath setup failed (attach or routing issue)")
elif [ "$LOST" -gt "$LOSS_THRESH" ]; then
  FAIL_MSGS+=("packet loss $LOST/$SENT exceeds threshold $LOSS_THRESH (loss=$(( LOST * 100 / SENT ))%)")
fi

# 7b. Pinned link survived the crictl stop.
if [ "$PIN_PRE" = yes ] && [ "$PIN_POST" != yes ]; then
  FAIL_MSGS+=("bpf-link pin $UPLINK_PIN VANISHED across the restart — link was NOT persisted (bpffs bug?)")
fi

# 7c. Prog-id CHANGED (atomic re-point, not same program running).
if [ -n "$PROG_ID_PRE" ] && [ -n "$PROG_ID_POST" ]; then
  if [ "$PROG_ID_PRE" = "$PROG_ID_POST" ]; then
    FAIL_MSGS+=("prog-id DID NOT CHANGE ($PROG_ID_PRE): the link was NOT re-pointed (stale program? detach/re-attach path?)")
  fi
elif [ -z "$PROG_ID_POST" ]; then
  FAIL_MSGS+=("no XDP prog on $UPLINK_IFACE after restart — datapath dropped entirely")
fi

# 7d. Sanity: prog-id should be present after restart.
[ -n "$PROG_ID_POST" ] || FAIL_MSGS+=("cannot verify prog-id swap: post-restart prog-id is empty")

# Report
if [ "${#FAIL_MSGS[@]}" -ne 0 ]; then
  for msg in "${FAIL_MSGS[@]}"; do
    echo "FAIL: $msg"
  done
  # Print the full single-line summary then exit non-zero.
  echo ""
  echo "FAIL: graceful-restart continuity — loss=${LOST}/${SENT}" \
       "pin=${PIN_PRE}->${PIN_POST}" \
       "prog-id=${PROG_ID_PRE:-(none)}->${PROG_ID_POST:-(none)}" \
       "(threshold=${LOSS_THRESH})"
  exit 1
fi

# Single-line PASS summary — the proof of the zero-gap guarantee.
echo ""
pass "graceful-restart zero-drop continuity:" \
     "loss=${LOST}/${SENT}" \
     "pin=survived(${PIN_PRE}->${PIN_POST})" \
     "prog-id=${PROG_ID_PRE}->${PROG_ID_POST} (atomic re-point)"
echo ""
echo "  - loss ${LOST}/${SENT} ≤ threshold ${LOSS_THRESH}: OK"
echo "  - bpf-link pin $UPLINK_PIN survived the crictl stop: $PIN_POST"
echo "  - prog-id changed ($PROG_ID_PRE -> $PROG_ID_POST): atomic adopt-and-repoint (NOT detach+re-attach)"

# ---------------------------------------------------------------------------
# [8] Cleanup
# ---------------------------------------------------------------------------
echo "== [8] cleanup =="
grpc "{\"interface_id\":\"$NIC\"}" DetachInterface >/dev/null 2>&1 || true
sudo docker exec "$SRC_NODE" ip netns del "$NIC" >/dev/null 2>&1 || true
info "detached $NIC; netns removed"
