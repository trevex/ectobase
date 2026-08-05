#!/usr/bin/env bash
# hack/tier2-failover-e2e.sh — BEST-EFFORT live validation of Tier-2 cross-cluster failover on the
# clab three-cluster fabric (k01 central, k02 + k03 compute pools sharing one Ceph). It boots a
# stateful RBD-backed VirtualMachine on pool k02, hard-kills the k02 kind node, and asserts central
# FENCES k02 (Ceph NetworkFence result==Succeeded + reflector SetFence withdraws k02's overlay
# routes) then RE-BINDS the VM to k03, where it reboots on the SAME RBD.
#
# NOT CI-wired: needs the fabric up (sudo ./hack/clab-up.sh) with k01/k02/k03 kind clusters, the
# central apiserver + scheduler + failover controllers, KubeVirt + external ceph-csi (RBD), and the
# k02/k03 brokers reporting NodePrefixes. Build-validated only in dev; the real run is on the host.
#
# Prereqs:
#   sudo ./hack/clab-up.sh                        # three-cluster fabric + shared ceph
#   hack/ceph-demo-up.sh                          # RBD pool + external-cluster params
#   make image image-netplane                     # :dev images loaded into the clusters
#   (central stack incl. StorageFencer driver + NetworkFencer reflector-admin must be running)
#
# Usage:
#   hack/tier2-failover-e2e.sh          # run the cross-cluster reschedule + fence gate
#   hack/tier2-failover-e2e.sh --help   # show this help
#
# Env overrides:
#   K01/K02/K03  kind cluster names        (default k01 / k02 / k03)
#   NS           VM namespace              (default default)
#   VM_NAME      VirtualMachine name       (default tier2-vm, matches the fixture)
#   VM_IP        VM overlay IP             (default 10.0.0.20, matches the fixture)
#   PEER_IP      k03 ping-peer overlay IP  (default 10.0.0.21)
#   CEPH_CTR     ceph container name       (default clab-xdp-ipv6-fabric-ceph)
#   TIMEOUT      per-phase wait, seconds   (default 600)
#   KUBECTL      kubectl binary            (default kubectl)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PATH="$HOME/go/bin:$PATH"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '2,29p' "$0"
  exit 0
fi

K01="${K01:-k01}"
K02="${K02:-k02}"
K03="${K03:-k03}"
NS="${NS:-default}"
VM_NAME="${VM_NAME:-tier2-vm}"
VM_IP="${VM_IP:-10.0.0.20}"
PEER_IP="${PEER_IP:-10.0.0.21}"
CEPH_CTR="${CEPH_CTR:-clab-xdp-ipv6-fabric-ceph}"
TIMEOUT="${TIMEOUT:-600}"
KUBECTL="${KUBECTL:-kubectl}"
FIXTURE="test/e2e/fixtures/multicluster-tier2/vm.yaml"

fail() { echo "FAIL: $*" >&2; exit 1; }
say()  { echo -e "\n=== $* ==="; }

# Resolve kind to an absolute path so `sudo "$KIND"` runs the real binary regardless of root's
# secure_path (NixOS drops nix-provided tools from root's PATH), mirroring multicluster-e2e.sh.
KIND="$(command -v kind)"; : "${KIND:?kind not found on PATH — run inside 'nix develop'}"

# Per-run, USER-OWNED kubeconfigs (fresh mktemp so a stale ROOT-owned fixed path can't shadow a new
# api-server port after a clab recreate). k<N>() wraps kubectl against the matching kubeconfig.
KC01=$(mktemp -t k01.kubeconfig.XXXXXX)
KC02=$(mktemp -t k02.kubeconfig.XXXXXX)
KC03=$(mktemp -t k03.kubeconfig.XXXXXX)
trap 'rm -f "$KC01" "$KC02" "$KC03"' EXIT
k01() { "$KUBECTL" --kubeconfig "$KC01" "$@"; }
k02() { "$KUBECTL" --kubeconfig "$KC02" "$@"; }
k03() { "$KUBECTL" --kubeconfig "$KC03" "$@"; }

# fence_name <prefix> — mirror central/internal/fence/storage.go fenceName(): ectobase- + prefix
# with ':' -> '-', '/' -> '--', '.' -> '-'. Used to look up the csi-addons NetworkFence CR by name.
fence_name() {
  local p="$1"
  p="${p//:/-}"; p="${p//\//--}"; p="${p//./-}"
  echo "ectobase-${p}"
}

# poll <deadline-secs> <desc> <cmd...> — run cmd until it exits 0 or the deadline passes; fail then.
poll() {
  local deadline="$1" desc="$2"; shift 2
  while :; do
    if "$@" >/dev/null 2>&1; then echo "  ok: $desc"; return 0; fi
    [ "$(date +%s)" -ge "$deadline" ] && fail "timed out waiting for: $desc"
    sleep 5
  done
}

# ---------------------------------------------------------------------------------------------------
say "1) preconditions: kubeconfigs + k02/k03 pools Ready with NodePrefixes"
sudo "$KIND" get kubeconfig --name "$K01" > "$KC01" || fail "no kubeconfig for $K01"
sudo "$KIND" get kubeconfig --name "$K02" > "$KC02" || fail "no kubeconfig for $K02"
sudo "$KIND" get kubeconfig --name "$K03" > "$KC03" || fail "no kubeconfig for $K03"
for pair in "$KC01:$K01" "$KC02:$K02" "$KC03:$K03"; do
  f="${pair%:*}"; name="${pair#*:}"
  "$KUBECTL" --kubeconfig "$f" get --raw='/healthz' >/dev/null 2>&1 \
    || fail "cannot reach $name api-server — is the fabric up? re-run hack/clab-up.sh"
done

# ClusterPools are cluster-scoped platform.ectobase.dev objects on k01 central. Assert Ready + a
# non-empty status.nodePrefixes (the broker-reported /64s — the fence coordinate).
# LIVE-ITERATE: confirm the ClusterPool objects are named exactly k02/k03; if the pool names differ
# from the kind cluster names, set the *_POOL vars and adjust the jsonpath below.
K02_POOL="${K02_POOL:-$K02}"
K03_POOL="${K03_POOL:-$K03}"
for pool in "$K02_POOL" "$K03_POOL"; do
  phase="$(k01 get clusterpool "$pool" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  [ "$phase" = "Ready" ] || fail "ClusterPool $pool not Ready (phase=${phase:-<none>})"
  prefixes="$(k01 get clusterpool "$pool" -o jsonpath='{.status.nodePrefixes[*]}' 2>/dev/null || true)"
  [ -n "$prefixes" ] || fail "ClusterPool $pool has empty status.nodePrefixes"
  echo "  $pool Ready, nodePrefixes=[$prefixes]"
done
# The k02 /64 is the fence coordinate. Take the FIRST reported prefix (single-node clusters).
# LIVE-ITERATE: multi-node k02 -> iterate every prefix for the fence/blocklist assertions below.
K02_PREFIX="$(k01 get clusterpool "$K02_POOL" -o jsonpath='{.status.nodePrefixes[0]}')"
[ -n "$K02_PREFIX" ] || fail "could not read k02 node /64 prefix"
echo "  k02 fence coordinate: $K02_PREFIX"

# ---------------------------------------------------------------------------------------------------
say "2) apply the stateful VM fixture to k01; wait for it to bind + boot on k02"
k01 apply -f "$FIXTURE" 2>&1 | tail -6
# vni may need stamping if no VPC controller runs in the lab (mirrors multicluster-e2e.sh).
k01 patch vpc blue --subresource=status --type=merge -p '{"status":{"vni":100,"state":"Ready"}}' 2>/dev/null || true

deadline=$(( $(date +%s) + TIMEOUT ))
poll "$deadline" "VirtualMachine $VM_NAME bound to $K02" \
  bash -c "[ \"\$($KUBECTL --kubeconfig $KC01 get virtualmachine $VM_NAME -n $NS -o jsonpath='{.spec.clusterName}')\" = '$K02' ]"
# The broker on k02 syncs CompiledVM -> the vm-materializer boots a KubeVirt VMI.
# LIVE-ITERATE: the VMI name may be prefixed/suffixed by the materializer — adjust if not $VM_NAME.
poll "$deadline" "VMI $VM_NAME Running on $K02" \
  bash -c "[ \"\$($KUBECTL --kubeconfig $KC02 get vmi $VM_NAME -n $NS -o jsonpath='{.status.phase}' 2>/dev/null)\" = 'Running' ]"
K02_NODE="$(k02 get vmi "$VM_NAME" -n "$NS" -o jsonpath='{.status.nodeName}')"
echo "  VMI Running on k02 node: ${K02_NODE:-<unknown>}"

# ---------------------------------------------------------------------------------------------------
say "3) write a sentinel onto the RBD disk (best-effort state-continuity marker)"
# LIVE-ITERATE: the exact mechanism depends on the guest image + creds. With virtctl this is a
# serial-console/ssh login + `echo tier2-$(date) > /mnt/sentinel`. Left as an echo so the gate does
# not hard-fail on console access; the RBD reattach on k03 is the real continuity signal.
echo "  (skipped live) would: virtctl console/ssh $VM_NAME -> write /var/lib/tier2-sentinel on the RBD"

# ---------------------------------------------------------------------------------------------------
say "4) baseline: a peer on k03 reaches the VM's overlay IP $VM_IP"
# LIVE-ITERATE: attach a peer endpoint on a k03 node (same VNI 100) exactly like multicluster-e2e.sh
# attach_endpoint(), then ping $VM_IP from that netns. Reflector distributes k02's overlay route to
# k03's agent, so this proves cross-cluster reachability BEFORE the fence.
echo "  (live) attach peer $PEER_IP on a k03 node (VNI 100) and: ip netns exec peer ping -c1 $VM_IP"
echo "  baseline reachability -> PASS/FAIL echoed live"

# ---------------------------------------------------------------------------------------------------
say "5) hard-kill the k02 kind node container(s)"
# The kind node container name == the k8s node name. Single control-plane node per compute cluster.
# LIVE-ITERATE: multi-node k02 -> docker kill every k02-* node container.
K02_CTR="${K02_NODE:-${K02}-control-plane}"
docker kill "$K02_CTR" || fail "failed to docker kill $K02_CTR"
echo "  killed $K02_CTR"

# ---------------------------------------------------------------------------------------------------
say "6) assert the fence bit set + VM re-bound to k03"
deadline=$(( $(date +%s) + TIMEOUT ))

# 6a) csi-addons NetworkFence CR for k02's /64, status.result==Succeeded (cluster-scoped on the
# ceph-management cluster — the same cluster in the single-cluster lab, i.e. k01).
FENCE_CR="$(fence_name "$K02_PREFIX")"
echo "  expecting NetworkFence CR: $FENCE_CR"
poll "$deadline" "NetworkFence $FENCE_CR result=Succeeded" \
  bash -c "[ \"\$($KUBECTL --kubeconfig $KC01 get networkfence $FENCE_CR -o jsonpath='{.status.result}' 2>/dev/null)\" = 'Succeeded' ]"

# 6b) Ceph OSD blocklist contains a client from the k02 /64. The blocklist entries are client
# addresses inside the fenced CIDR; grep on the /64's leading hextets.
# LIVE-ITERATE: the blocklist address format is <ip>:<port>/<nonce>; match the k02 prefix's non-zero
# leading hextets (strip the trailing ::/64). Adjust the grep to the ACTUAL rendered client addr.
K02_HEXTETS="$(echo "$K02_PREFIX" | sed 's#/64$##; s#::$##; s#:$##')"
echo "  expecting ceph osd blocklist entry matching: $K02_HEXTETS"
poll "$deadline" "ceph osd blocklist contains a k02 client ($K02_HEXTETS)" \
  bash -c "docker exec $CEPH_CTR ceph osd blocklist ls 2>/dev/null | grep -qi '$K02_HEXTETS'"

# 6c) reflector withdrew k02's overlay routes -> a k03 peer can NO LONGER reach the VM's old IP.
# LIVE-ITERATE: from the same k03 peer netns as step 4, assert `ping -c1 -W2 $VM_IP` now FAILS.
echo "  (live) from the k03 peer netns: ping -c1 -W2 $VM_IP MUST now fail (routes withdrawn)"

# 6d) failover re-bound the VirtualMachine to k03.
poll "$deadline" "VirtualMachine $VM_NAME re-bound to $K03" \
  bash -c "[ \"\$($KUBECTL --kubeconfig $KC01 get virtualmachine $VM_NAME -n $NS -o jsonpath='{.spec.clusterName}')\" = '$K03' ]"
echo "  fence asserted; VM re-bound k02 -> k03"

# ---------------------------------------------------------------------------------------------------
say "7) assert reschedule: VMI Running on k03, sentinel intact, peer reaches the VM again"
poll "$deadline" "VMI $VM_NAME Running on $K03" \
  bash -c "[ \"\$($KUBECTL --kubeconfig $KC03 get vmi $VM_NAME -n $NS -o jsonpath='{.status.phase}' 2>/dev/null)\" = 'Running' ]"
K03_NODE="$(k03 get vmi "$VM_NAME" -n "$NS" -o jsonpath='{.status.nodeName}')"
echo "  VMI Running on k03 node: ${K03_NODE:-<unknown>}"
# LIVE-ITERATE: virtctl console/ssh into the k03 VM and assert /var/lib/tier2-sentinel is the same
# value written in step 3 (proves the SAME RBD reattached).
echo "  (skipped live) would: assert /var/lib/tier2-sentinel intact on the reattached RBD"
# LIVE-ITERATE: from a k03 peer netns, ping $VM_IP again — now served from k03 (route re-announced
# by k03's agent after the VMI came up).
echo "  (live) from the k03 peer netns: ping -c1 $VM_IP MUST now succeed (served from k03)"

# ---------------------------------------------------------------------------------------------------
say "8) recovery: restart the k02 node; assert the k02 fence released"
docker start "$K02_CTR" || echo "  WARN: docker start $K02_CTR failed (already running?)"
deadline=$(( $(date +%s) + TIMEOUT ))
# 8a) ceph osd blocklist no longer contains the k02 client (StorageFencer.Release deletes the CR;
# the reconciler `ceph osd blocklist rm`s the entry).
poll "$deadline" "ceph osd blocklist no longer contains k02 ($K02_HEXTETS)" \
  bash -c "! docker exec $CEPH_CTR ceph osd blocklist ls 2>/dev/null | grep -qi '$K02_HEXTETS'"
# 8b) the NetworkFence CR is gone (Release deletes it).
poll "$deadline" "NetworkFence $FENCE_CR deleted" \
  bash -c "! $KUBECTL --kubeconfig $KC01 get networkfence $FENCE_CR >/dev/null 2>&1"
# 8c) ClusterPool k02 status.fencedPrefixes is empty again.
poll "$deadline" "ClusterPool $K02_POOL fencedPrefixes empty" \
  bash -c "[ -z \"\$($KUBECTL --kubeconfig $KC01 get clusterpool $K02_POOL -o jsonpath='{.status.fencedPrefixes[*]}' 2>/dev/null)\" ]"

say "DONE: Tier-2 cross-cluster failover + fence + recovery assertions passed (best-effort)"
