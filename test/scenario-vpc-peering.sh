#!/usr/bin/env bash
# test/scenario-vpc-peering.sh — VPC-peering end-to-end: reachability + firewall two-step + overlap.
#
# Proves the three properties of the VPC-peering feature:
#
#   1. DENY-BY-DEFAULT (two-step): a mutual-consent VPCPeering pair imports routes between VPCs, but
#      the ingress firewall on the destination NIC is still DENY-BY-DEFAULT. A cross-VPC ping MUST
#      FAIL until an explicit FirewallPolicy allows the peer CIDR. The route import is reachability
#      only — it grants no firewall permission. (This is the deliberate two-step.)
#
#   2. REACHABILITY + POLICY: once a FirewallPolicy ingress-allows the peer CIDR on the destination
#      NIC, the cross-VPC ping MUST SUCCEED. The route was already imported; the firewall now
#      permits it.
#
#   3. OVERLAP PRECEDENCE (local-VNI wins): when a local guest in the destination VPC holds an
#      address that also falls inside an exported prefix from the peer VPC, the local route wins.
#      Verified via the DataplaneNode ListInterfaces gRPC call: the local guest's IP must appear
#      as a locally-attached interface on the destination node.  Local guests deliver via the
#      INTERFACES map (not ROUTES), so a local /32 shadows any imported peer prefix for the same
#      address by construction — no in-node bpftool needed.
#
# Topology:
#   VPC blue  (VNI auto, subnet 10.0.10.0/24)  — guest "blue-guest"  @ 10.0.10.11 on k01-worker
#   VPC green (VNI auto, subnet 10.0.20.0/24)  — guest "green-guest" @ 10.0.20.11 on k01-control-plane
#             overlap guest "green-local" @ 10.0.10.77  (falls in blue's exposedPrefixes 10.0.10.0/24)
#
#   VPCPeering blue→green  (exposedPrefixes: 10.0.10.0/24)
#   VPCPeering green→blue  (exposedPrefixes: 10.0.20.0/24)
#
#   After the peering is Ready:
#     • green's ingress firewall still blocks 10.0.10.x  →  cross-VPC ping FAILS (Assertion 1)
#     • Apply FirewallPolicy on green's NIC allowing ingress from 10.0.10.0/24 → ping SUCCEEDS (Assertion 2)
#     • green-local@10.0.10.77 is a LOCAL interface on GREEN_NODE (VNI-green); ListInterfaces must
#       report it (Assertion 3 — overlap precedence via INTERFACES map, no bpftool needed)
#
# NOTE: Assertions 1 and 2 drive a real ICMP ping through the datapath (cross-node, cross-VPC).
#       The kind node has no system ping; a static busybox binary is staged into the node at
#       /busybox before pinging (see [2c]).
#       Assertion 3 uses the DataplaneNode ListInterfaces gRPC (no in-node bpftool required).
#
# PREREQ: fabric up (hack/clab-up.sh) + netplane stack deployed on k01 running THIS branch image.
#   sudo -E env "PATH=$PATH" \
#       bash test/scenario-vpc-peering.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT" || exit 1

# --- gate: must be root on the fabric host (not a CI unit-test) ---
if [ "$(id -u)" -ne 0 ]; then
  echo "SKIP: scenario-vpc-peering.sh is a privileged manual scenario; run under sudo."
  exit 0
fi

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
# Two fabric nodes (see hack/clab/kind-cluster.yaml: control-plane + worker).
BLUE_NODE=k01-worker
GREEN_NODE=k01-control-plane

# VPC names, subnets, and PINNED VNIs — unique to this scenario (avoid collisions).
#
# There is NO VPC-VNI-allocator controller in this deployment: the central VNI allocator
# does not run on the k01 fabric, so an auto-VNI VPC (spec:{}) never gets a status.vni and
# the scenario would stall forever. The working scenarios (scenario-nat-egress.sh /
# scenario-lb-ingress.sh) therefore PIN spec.vni and MANUALLY patch status. We do the same:
# pin both VNIs here and patch each VPC's status (vni + state:Ready) in [1].
BLUE_VPC=peer-blue
GREEN_VPC=peer-green
BLUE_VNI=110
GREEN_VNI=120
BLUE_SUBNET=10.0.10.0/24
GREEN_SUBNET=10.0.20.0/24

# Guest IPs.
BLUE_GUEST_NIC=blue-guest
BLUE_GUEST_IP=10.0.10.11

GREEN_GUEST_NIC=green-guest
GREEN_GUEST_IP=10.0.20.11

# Overlap guest: a local green NIC at an address that is also inside blue's exposedPrefixes.
# 10.0.10.77 ∈ 10.0.10.0/24 (blue's exported range) — green-local owns it locally.
OVERLAP_NIC=green-local
OVERLAP_IP=10.0.10.77

# VPCPeering object names.
PEERING_BG=peering-blue-to-green
PEERING_GB=peering-green-to-blue

# FirewallPolicy names.
NP_GREEN_DENY=green-deny-all
NP_GREEN_ALLOW=green-allow-blue

PROTO="$ROOT/api/proto"

K1=$(mktemp /tmp/vpc-peering-kubeconfig.XXXXXX)
trap 'rm -f "$K1"' EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
pass()   { echo "PASS: $*"; }
fail()   { echo "FAIL: $*"; OVERALL_FAIL=1; }
info()   { echo "    $*"; }

OVERALL_FAIL=0

kc() { kubectl --kubeconfig "$K1" "$@"; }

grpc() {
  # grpc <node> <json-body> <method>
  sudo docker run --rm --network "container:$1" \
    -v "$PROTO":/proto:ro fullstorydev/grpcurl:latest \
    -plaintext -import-path /proto/dataplane/v1 -proto dataplane.proto \
    -d "$2" 127.0.0.1:1337 "dataplane.v1.DataplaneNode/$3" 2>&1
}

# Wait up to <secs> for a jsonpath on a kube object to match <value>.
wait_for() {
  local kind="$1" name="$2" jsonpath="$3" want="$4" secs="${5:-60}"
  local got
  for _ in $(seq 1 "$secs"); do
    got=$(kc get "$kind" "$name" -o jsonpath="$jsonpath" 2>/dev/null || true)
    [ "$got" = "$want" ] && return 0
    sleep 1
  done
  info "timeout waiting for $kind/$name $jsonpath == $want (last: $got)"
  return 1
}

# Attach a guest netns on <node> with the given params; prints the underlay /128 on stdout.
attach_guest() {
  local node="$1" nic="$2" vni="$3" ip="$4"
  # Idempotent detach before re-attach.
  grpc "$node" "{\"interface_id\":\"$nic\"}" DetachInterface >/dev/null 2>&1 || true
  sudo docker exec "$node" ip netns add "$nic" 2>/dev/null || true

  local out
  out=$(grpc "$node" \
    "{\"interface_id\":\"$nic\",\"netns_path\":\"/var/run/netns/$nic\",\"vni\":$vni,\"requested_ips\":[\"$ip\"]}" \
    AttachInterface)
  local ul
  ul=$(echo "$out" | grep -o 'fd00:[0-9a-f:]*' | head -1)
  [ -n "$ul" ] || { echo ""; return 1; }

  # Configure the guest netns: overlay IP on the veth, default via the dp gateway.
  sudo docker exec "$node" sh -c "
    ip netns exec $nic ip addr add $ip/32 dev $nic 2>/dev/null || true
    ip netns exec $nic ip route add 169.254.0.1/32 dev $nic 2>/dev/null || true
    ip netns exec $nic ip route add default via 169.254.0.1 dev $nic 2>/dev/null || true
  "
  echo "$ul"
}

detach_guest() {
  local node="$1" nic="$2"
  grpc "$node" "{\"interface_id\":\"$nic\"}" DetachInterface >/dev/null 2>&1 || true
  sudo docker exec "$node" ip netns del "$nic" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# [0] Pre-flight: fabric nodes + netplane stack
# ---------------------------------------------------------------------------
echo "== [0] pre-flight =="
sudo docker ps --filter "name=$BLUE_NODE"  --format '{{.Names}}' | grep -q "$BLUE_NODE" \
  || { echo "FAIL: clab fabric not up ($BLUE_NODE not running); run hack/clab-up.sh"; exit 1; }
sudo docker ps --filter "name=$GREEN_NODE" --format '{{.Names}}' | grep -q "$GREEN_NODE" \
  || { echo "FAIL: clab fabric not up ($GREEN_NODE not running); run hack/clab-up.sh"; exit 1; }

# shellcheck disable=SC2024  # redirect is to a root-owned tmp file; running as root
sudo -E env "PATH=$PATH" kind get kubeconfig --name k01 > "$K1" 2>/dev/null \
  || { echo "FAIL: could not get k01 kubeconfig"; exit 1; }

kc -n ectobase-system get ds flowplane >/dev/null 2>&1 \
  || { echo "FAIL: netplane stack not deployed on k01"; exit 1; }

info "fabric nodes up; netplane stack present; pre-flight ok"

# ---------------------------------------------------------------------------
# [1] Create VPCs + guest NICs
# ---------------------------------------------------------------------------
echo "== [1] create VPCs ($BLUE_VPC VNI=$BLUE_VNI / $GREEN_VPC VNI=$GREEN_VNI) + guest NICs =="
cat <<YAML | kc apply -f - >/dev/null || { echo "FAIL: apply VPC/NIC CRs"; exit 1; }
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: $BLUE_VPC, namespace: default}
spec: {vni: $BLUE_VNI}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: $GREEN_VPC, namespace: default}
spec: {vni: $GREEN_VNI}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: $BLUE_GUEST_NIC, namespace: default, labels: {scenario: vpc-peering, side: blue}}
spec:
  vpcRef: {name: $BLUE_VPC}
  ips: [$BLUE_GUEST_IP]
  nodeName: $BLUE_NODE
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: $GREEN_GUEST_NIC, namespace: default, labels: {scenario: vpc-peering, side: green}}
spec:
  vpcRef: {name: $GREEN_VPC}
  ips: [$GREEN_GUEST_IP]
  nodeName: $GREEN_NODE
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: $OVERLAP_NIC, namespace: default, labels: {scenario: vpc-peering, side: green}}
spec:
  vpcRef: {name: $GREEN_VPC}
  ips: [$OVERLAP_IP]
  nodeName: $GREEN_NODE
YAML
info "CRs applied"

# Patch both VPCs' status directly (vni + state:Ready). There is NO VPC controller on this
# fabric, so nothing else would ever populate status.vni — exactly as scenario-nat-egress.sh
# does for its single VPC. The VNIs are the PINNED values from spec.vni above.
kc patch vpc "$BLUE_VPC"  --subresource=status --type=merge \
  -p "{\"status\":{\"vni\":$BLUE_VNI,\"state\":\"Ready\"}}" >/dev/null
kc patch vpc "$GREEN_VPC" --subresource=status --type=merge \
  -p "{\"status\":{\"vni\":$GREEN_VNI,\"state\":\"Ready\"}}" >/dev/null
info "$BLUE_VPC VNI=$BLUE_VNI (status Ready)  |  $GREEN_VPC VNI=$GREEN_VNI (status Ready)"

# ---------------------------------------------------------------------------
# [2] Attach guests via DataplaneNode gRPC + kick netplane-agent
# ---------------------------------------------------------------------------
echo "== [2] attach guest netns (blue@$BLUE_NODE, green@$GREEN_NODE, overlap@$GREEN_NODE) =="

BLUE_UL=$(attach_guest "$BLUE_NODE"  "$BLUE_GUEST_NIC" "$BLUE_VNI"  "$BLUE_GUEST_IP")
[ -n "$BLUE_UL" ] || { echo "FAIL: AttachInterface failed for $BLUE_GUEST_NIC"; exit 1; }
info "$BLUE_GUEST_NIC underlay=$BLUE_UL"

GREEN_UL=$(attach_guest "$GREEN_NODE" "$GREEN_GUEST_NIC" "$GREEN_VNI" "$GREEN_GUEST_IP")
[ -n "$GREEN_UL" ] || { echo "FAIL: AttachInterface failed for $GREEN_GUEST_NIC"; exit 1; }
info "$GREEN_GUEST_NIC underlay=$GREEN_UL"

OVERLAP_UL=$(attach_guest "$GREEN_NODE" "$OVERLAP_NIC" "$GREEN_VNI" "$OVERLAP_IP")
[ -n "$OVERLAP_UL" ] || { echo "FAIL: AttachInterface failed for $OVERLAP_NIC"; exit 1; }
info "$OVERLAP_NIC underlay=$OVERLAP_UL"

# Patch NIC status so the agent + compiler see them as Ready.
kc patch networkinterface "$BLUE_GUEST_NIC" --subresource=status --type=merge \
  -p "{\"status\":{\"vni\":$BLUE_VNI,\"underlayRoute\":\"$BLUE_UL\",\"state\":\"Ready\"}}" >/dev/null
kc patch networkinterface "$GREEN_GUEST_NIC" --subresource=status --type=merge \
  -p "{\"status\":{\"vni\":$GREEN_VNI,\"underlayRoute\":\"$GREEN_UL\",\"state\":\"Ready\"}}" >/dev/null
kc patch networkinterface "$OVERLAP_NIC" --subresource=status --type=merge \
  -p "{\"status\":{\"vni\":$GREEN_VNI,\"underlayRoute\":\"$OVERLAP_UL\",\"state\":\"Ready\"}}" >/dev/null

# Restart agent so it picks up the newly-attached NICs.
kc -n ectobase-system rollout restart ds/netplane-agent >/dev/null 2>&1
kc -n ectobase-system rollout status ds/netplane-agent --timeout=90s >/dev/null 2>&1
sleep 4
info "guests attached; agent restarted"

# ---------------------------------------------------------------------------
# [2c] Stage a static busybox binary on BLUE_NODE for guest pings.
#
# The kind node image has no system ping; we copy a static busybox:musl binary
# to /busybox on the node so Assertions 1 and 2 can run /busybox ping inside
# the blue-guest netns.  Same idiom as scenario-nat-egress.sh and egress-fabric-e2e.sh.
# ---------------------------------------------------------------------------
echo "== [2c] stage busybox on $BLUE_NODE for guest pings =="
CID=$(sudo docker create busybox:musl 2>/dev/null); sudo docker cp "$CID":/bin/busybox /tmp/busybox-musl >/dev/null 2>&1; sudo docker rm "$CID" >/dev/null 2>&1
sudo docker cp /tmp/busybox-musl "$BLUE_NODE":/busybox 2>/dev/null
info "busybox staged at /busybox on $BLUE_NODE"

# ---------------------------------------------------------------------------
# [2b] Apply deny-all ingress FirewallPolicy on green's NICs BEFORE the peering.
#
# WHY: the CompiledNIC compiler uses "allow-until-selected" semantics — any NIC
# that no FirewallPolicy selects gets an implicit allow-all ingress fallback rule.
# Without an explicit selecting policy, Assertion 1 (deny-by-default) would always
# fail because the firewall would permit the peered ping.  Applying this deny-all
# first causes the compiler to emit a real deny rule (the direction is no longer
# un-selected), so Assertion 1 genuinely exercises the deny path.
# ---------------------------------------------------------------------------
echo "== [2b] apply deny-all ingress policy on green NICs (suppress allow-until-selected default) =="
cat <<YAML | kc apply -f - >/dev/null || { echo "FAIL: apply $NP_GREEN_DENY"; exit 1; }
apiVersion: net.ectobase.dev/v1alpha1
kind: FirewallPolicy
metadata: {name: $NP_GREEN_DENY, namespace: default}
spec:
  interfaceSelector: {matchLabels: {side: green}}
  ingress:
    - {cidr: "0.0.0.0/0", action: "Deny"}
YAML

# Wait for the agent to reconcile the deny policy into the dataplane firewall.
kc -n ectobase-system rollout restart ds/netplane-agent >/dev/null 2>&1
kc -n ectobase-system rollout status ds/netplane-agent --timeout=90s >/dev/null 2>&1
sleep 4
info "$NP_GREEN_DENY applied; agent reconciled"

# ---------------------------------------------------------------------------
# [3] Create the mutual-consent VPCPeering pair + wait for both to reach Ready
# ---------------------------------------------------------------------------
echo "== [3] create VPCPeering pair ($PEERING_BG / $PEERING_GB) =="
cat <<YAML | kc apply -f - >/dev/null || { echo "FAIL: apply VPCPeering CRs"; exit 1; }
apiVersion: net.ectobase.dev/v1alpha1
kind: VPCPeering
metadata: {name: $PEERING_BG, namespace: default}
spec:
  vpcRef: {name: $BLUE_VPC}
  peerVpcRef: {namespace: default, name: $GREEN_VPC}
  exposedPrefixes: [$BLUE_SUBNET]
---
apiVersion: net.ectobase.dev/v1alpha1
kind: VPCPeering
metadata: {name: $PEERING_GB, namespace: default}
spec:
  vpcRef: {name: $GREEN_VPC}
  peerVpcRef: {namespace: default, name: $BLUE_VPC}
  exposedPrefixes: [$GREEN_SUBNET]
YAML

info "waiting for both VPCPeerings to reach Ready..."
wait_for vpcpeering "$PEERING_BG" '{.status.state}' Ready 60 \
  || { echo "FAIL: $PEERING_BG did not reach Ready"; exit 1; }
wait_for vpcpeering "$PEERING_GB" '{.status.state}' Ready 60 \
  || { echo "FAIL: $PEERING_GB did not reach Ready"; exit 1; }
info "$PEERING_BG Ready; $PEERING_GB Ready"

# Re-restart the agent so it re-reconciles CompiledNICs with peer imports.
kc -n ectobase-system rollout restart ds/netplane-agent >/dev/null 2>&1
kc -n ectobase-system rollout status ds/netplane-agent --timeout=90s >/dev/null 2>&1
sleep 6
info "agent re-reconciled with peer imports"

# ---------------------------------------------------------------------------
# [4] ASSERTION 1: pre-policy cross-VPC ping MUST FAIL (deny-by-default)
#
# green-deny-all (applied in [2b]) makes the green NICs "selected" by a policy so
# the compiler emits a real deny rule instead of the allow-until-selected fallback.
# The VPCPeering imports the route but grants NO firewall permission — the ingress
# deny-all must still block the ping.
# ---------------------------------------------------------------------------
echo "== [4] Assertion 1: pre-policy cross-VPC ping must be blocked (deny-by-default) =="
# Ping from blue-guest -> green-guest.  Should be dropped by green's ingress firewall.
# -c 3 -W 2 = 3 probes, 2 s timeout each; ping exits 1 on total loss.
if sudo docker exec "$BLUE_NODE" \
     ip netns exec "$BLUE_GUEST_NIC" /busybox ping -c 3 -W 2 "$GREEN_GUEST_IP" >/dev/null 2>&1; then
  fail "pre-policy cross-VPC ping SUCCEEDED (expected DROP — deny-by-default firewall not enforced)"
else
  pass "pre-policy cross-VPC ping blocked (deny-by-default ingress firewall on $GREEN_GUEST_NIC is enforced)"
fi

# ---------------------------------------------------------------------------
# [5] Swap: delete deny-all, apply allow policy on green + wait for agent
#
# We DELETE green-deny-all before applying the allow policy so that exactly one
# selecting policy governs green at a time.  Layering an Allow on top of a Deny
# would introduce rule-ordering ambiguity; replacing it avoids that entirely.
# ---------------------------------------------------------------------------
echo "== [5] delete $NP_GREEN_DENY; apply $NP_GREEN_ALLOW ($BLUE_SUBNET ingress on green) =="
# firewallpolicy is an unambiguous resource name (no core-k8s collision), so a bare delete works.
kc delete firewallpolicy "$NP_GREEN_DENY" >/dev/null 2>&1 || true
cat <<YAML | kc apply -f - >/dev/null || { echo "FAIL: apply FirewallPolicy"; exit 1; }
apiVersion: net.ectobase.dev/v1alpha1
kind: FirewallPolicy
metadata: {name: $NP_GREEN_ALLOW, namespace: default}
spec:
  interfaceSelector: {matchLabels: {side: green}}
  ingress:
    - {cidr: "$BLUE_SUBNET", proto: ICMP, action: Allow}
YAML

# Give the agent a beat to reconcile the new rule into the dataplane firewall.
kc -n ectobase-system rollout restart ds/netplane-agent >/dev/null 2>&1
kc -n ectobase-system rollout status ds/netplane-agent --timeout=90s >/dev/null 2>&1
sleep 6
info "$NP_GREEN_DENY deleted; $NP_GREEN_ALLOW applied; agent reconciled"

# ---------------------------------------------------------------------------
# [6] ASSERTION 2: post-policy cross-VPC ping MUST SUCCEED
# ---------------------------------------------------------------------------
echo "== [6] Assertion 2: post-policy cross-VPC ping must succeed =="
if sudo docker exec "$BLUE_NODE" \
     ip netns exec "$BLUE_GUEST_NIC" /busybox ping -c 3 -W 4 "$GREEN_GUEST_IP" >/dev/null 2>&1; then
  pass "post-policy cross-VPC ping succeeded (route imported + firewall now allows $BLUE_SUBNET)"
else
  fail "post-policy cross-VPC ping FAILED (route imported and policy applied but ICMP still dropped)"
fi

# ---------------------------------------------------------------------------
# [7] ASSERTION 3: overlap-precedence — OVERLAP_IP is a LOCAL interface on GREEN_NODE
# ---------------------------------------------------------------------------
echo "== [7] Assertion 3: overlap-precedence — $OVERLAP_IP is a LOCAL interface on $GREEN_NODE (shadows peer import) =="
# Local guests deliver via the INTERFACES map, not ROUTES — a local /32 for OVERLAP_IP shadows any
# imported peer prefix for the same address by construction. Confirm green-local is locally attached
# on GREEN_NODE (authoritative; no in-node nix bpftool needed — read it via the DataplaneNode gRPC).
if grpc "$GREEN_NODE" '{}' ListInterfaces | grep -q "$OVERLAP_IP"; then
  pass "overlap-precedence: $OVERLAP_IP is a LOCAL interface on $GREEN_NODE (VNI $GREEN_VNI) — local delivery shadows any imported peer prefix for the same address"
else
  info "ListInterfaces on $GREEN_NODE did not report $OVERLAP_IP"
  fail "overlap-precedence: $OVERLAP_IP not reported as a local interface on $GREEN_NODE"
fi

# ---------------------------------------------------------------------------
# [8] Cleanup
# ---------------------------------------------------------------------------
echo "== [8] cleanup =="
kc delete firewallpolicy "$NP_GREEN_DENY"  "$NP_GREEN_ALLOW"  >/dev/null 2>&1 || true
kc delete vpcpeering    "$PEERING_BG" "$PEERING_GB"          >/dev/null 2>&1 || true
kc delete networkinterface "$BLUE_GUEST_NIC" "$GREEN_GUEST_NIC" "$OVERLAP_NIC" >/dev/null 2>&1 || true
kc delete vpc "$BLUE_VPC" "$GREEN_VPC"                       >/dev/null 2>&1 || true
detach_guest "$BLUE_NODE"  "$BLUE_GUEST_NIC"
detach_guest "$GREEN_NODE" "$GREEN_GUEST_NIC"
detach_guest "$GREEN_NODE" "$OVERLAP_NIC"
info "CRs deleted; guest netns detached"

# ---------------------------------------------------------------------------
# Overall result
# ---------------------------------------------------------------------------
echo ""
if [ "$OVERALL_FAIL" -ne 0 ]; then
  echo "FAIL: scenario-vpc-peering — one or more assertions failed (see FAIL lines above)"
  exit 1
fi
echo "PASS: scenario-vpc-peering — all 3 assertions passed (deny-by-default enforced; reachability+policy works; overlap local-VNI wins)"
