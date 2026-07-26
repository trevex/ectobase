#!/usr/bin/env bash
# hack/multicluster-e2e.sh — deploy the route-distribution stack across TWO kind
# clusters on the shared containerlab IPv6 BGP fabric and prove CROSS-CLUSTER overlay
# connectivity.
#
# Topology (hack/clab/ipv6-fabric.clab.yml, already deployed by hack/clab-up.sh):
#   * k01 = CENTRAL cluster (2 nodes). Holds the reflector (on the control-plane node's
#     fabric loopback fd00:db8:0:1::1) and the VPC/NetworkInterface CRDs.
#   * k02 = COMPUTE cluster (1 node, /64 fd00:db8:0:3::1). Brokered to k01: its agent
#     peers k01's reflector AND reads the CRDs from k01's API, both over the fabric,
#     authenticating with a k01-issued ServiceAccount token.
#
# Endpoints: 10.0.0.1 on k01-control-plane, 10.0.0.3 on k02-control-plane (both in the
# same VPC vni 100). Success = 10.0.0.1 <-> 10.0.0.3 ping over the IP-in-IPv6 overlay,
# i.e. routes distributed by the central reflector to agents in a DIFFERENT cluster.
#
# Prereqs: the two-cluster fabric is up (sudo ./hack/clab-up.sh), and the images
# ghcr.io/trevex/ectobase/{flowplane,netplane}:dev are built. Run from the repo root.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/clab/env.sh"
export PATH="$HOME/go/bin:$PATH"

# Resolve external tools to ABSOLUTE paths ONCE, so `sudo "$TOOL"` runs the real
# binary regardless of root's secure_path (NixOS drops nix-provided tools from root's
# PATH). No sudo passthrough shim needed.
KIND="$(command -v kind)"       ; : "${KIND:?kind not found on PATH — run inside 'nix develop'}"
DOCKER="$(command -v docker)"   ; : "${DOCKER:?docker not found on PATH}"
KUBECTL="$(command -v kubectl)" ; : "${KUBECTL:?kubectl not found on PATH — run inside 'nix develop'}"

REFLECTOR6="${CLAB_FABRIC_REFLECTOR6}"  # k01 control-plane fabric loopback (default in hack/clab/env.sh)
APISERVER6="https://[${REFLECTOR6}]:6443"
# Per-run, USER-OWNED kubeconfig files. Do NOT use fixed /tmp paths: `sudo kind get kubeconfig > file`
# runs the redirect as the invoking user, so if a fixed path is left ROOT-owned by an earlier full-sudo
# run, the overwrite silently fails and kubectl then dials a STALE api-server port (the ports change
# every `clab-up`/kind recreate). mktemp gives a fresh user-writable file each run; trap-clean on exit.
K1=$(mktemp -t k01.kubeconfig.XXXXXX)
K2=$(mktemp -t k02.kubeconfig.XXXXXX)
trap 'rm -f "$K1" "$K2"' EXIT
GRPCURL_IMG="fullstorydev/grpcurl:latest"
PROTO_MNT="-v $(pwd)/api/proto:/proto:ro"
XDP="${CLAB_IMAGE_FLOWPLANE}"
NETPLANE="${CLAB_IMAGE_NETPLANE}"

say() { echo -e "\n=== $* ==="; }

say "kubeconfigs"
sudo "$KIND" get kubeconfig --name "$CLAB_KIND_CENTRAL" > "$K1"
sudo "$KIND" get kubeconfig --name "$CLAB_KIND_COMPUTE" > "$K2"
# Fail fast with a clear message if a kubeconfig points at a dead api-server (stale port etc.),
# instead of letting every later kubectl fail with a cryptic connection-refused.
for kc in "$K1:$CLAB_KIND_CENTRAL" "$K2:$CLAB_KIND_COMPUTE"; do
  f="${kc%:*}"; name="${kc#*:}"
  "$KUBECTL" --kubeconfig "$f" get --raw='/healthz' >/dev/null 2>&1 \
    || { echo "FATAL: cannot reach $name api-server ($(grep -oE 'server: .*' "$f")). Is the cluster up? Re-run hack/clab-up.sh." >&2; exit 1; }
done
"$KUBECTL" --kubeconfig "$K1" get nodes -o name
"$KUBECTL" --kubeconfig "$K2" get nodes -o name

say "load images into both clusters"
for c in "$CLAB_KIND_CENTRAL" "$CLAB_KIND_COMPUTE"; do
  sudo "$KIND" load docker-image "$XDP" --name "$c" 2>&1 | tail -1
  sudo "$KIND" load docker-image "$NETPLANE" --name "$c" 2>&1 | tail -1
done

say "k01 (central): CRDs + full stack (reflector + flowplane + agent)"
"$KUBECTL" --kubeconfig "$K1" apply -k config/crd 2>&1 | tail -1
"$KUBECTL" --kubeconfig "$K1" apply -k config/deploy 2>&1 | grep -E 'created|configured|unchanged' | tail -6

say "mint a k01 token for the k02 agent (cross-cluster brokering)"
"$KUBECTL" --kubeconfig "$K1" -n ectobase-system create serviceaccount netplane-agent 2>/dev/null || true
TOKEN=$("$KUBECTL" --kubeconfig "$K1" -n ectobase-system create token netplane-agent --duration=8760h)
[ -n "$TOKEN" ] && echo "token minted (${#TOKEN} chars)"

say "k02 (compute): namespace + flowplane DS + agent (points at k01 central over the fabric)"
"$KUBECTL" --kubeconfig "$K2" apply -f config/deploy/namespace.yaml
"$KUBECTL" --kubeconfig "$K2" apply -f config/deploy/rbac.yaml
"$KUBECTL" --kubeconfig "$K2" apply -f config/deploy/flowplane.yaml
# k02 agent kubeconfig: explicit k01 token (not the local SA), server = k01 API on the fabric.
# The kubeconfig CONTENT is runtime-generated (per-run k01 token + fabric apiserver addr), so it
# is materialised in a temp file and loaded via --from-file — that's data-from-a-file, not an inline
# manifest, which is acceptable (the heredoc-removal target is the STATIC CR/agent YAML, done below).
KCFG=$(mktemp -t netplane-agent.kubeconfig.XXXXXX)
trap 'rm -f "$K1" "$K2" "$KCFG"' EXIT
cat > "$KCFG" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: central
    cluster:
      server: ${APISERVER6}
      insecure-skip-tls-verify: true
users:
  - name: sa
    user:
      token: ${TOKEN}
contexts:
  - name: central
    context: {cluster: central, user: sa}
current-context: central
EOF
"$KUBECTL" --kubeconfig "$K2" -n ectobase-system create configmap netplane-agent-kubeconfig \
  --from-file=kubeconfig="$KCFG" --dry-run=client -o yaml | "$KUBECTL" --kubeconfig "$K2" apply -f -
# k02 agent DS: same image, reflector on the fabric, kubeconfig = the central one above. The
# reflector override lives in an all-kustomize overlay (test/e2e/fixtures/multicluster/agent-overlay,
# a JSON6902 replace on the --reflector args index — no regex-on-YAML). The reflector addr comes from
# env.sh at run time, so the patch is rendered from a .tmpl via envsubst (restricted to the two vars) first. We render
# via `kubectl kustomize | apply -f -` (not `apply -k`): the overlay references the shared base
# config/deploy/agent.yaml which lives OUTSIDE the overlay dir, so it needs --load-restrictor
# LoadRestrictionsNone, a flag `kubectl apply -k` does not accept but `kubectl kustomize` does. This
# keeps agent.yaml the single source of truth (no copy/drift).
AGENT_OVERLAY="test/e2e/fixtures/multicluster/agent-overlay"
envsubst '${CLAB_FABRIC_REFLECTOR6} ${CLAB_REFLECTOR_PORT}' \
    < "$AGENT_OVERLAY/patch.reflector.yaml.tmpl" > "$AGENT_OVERLAY/patch.reflector.yaml"
"$KUBECTL" kustomize --load-restrictor LoadRestrictionsNone "$AGENT_OVERLAY" \
  | "$KUBECTL" --kubeconfig "$K2" apply -f -
"$KUBECTL" --kubeconfig "$K2" -n ectobase-system rollout status ds/flowplane --timeout=90s 2>&1 | tail -1

say "VPC + NetworkInterfaces in k01 (central): 10.0.0.1 on k01-cp, 10.0.0.3 on k02-cp"
# The VPC + NetworkInterface CRs live in an all-kustomize fixture (was an inline heredoc).
"$KUBECTL" --kubeconfig "$K1" apply -k test/e2e/fixtures/multicluster/
"$KUBECTL" --kubeconfig "$K1" patch vpc blue --subresource=status --type=merge -p '{"status":{"vni":100,"state":"Ready"}}'

# attach_endpoint <node-container> <iface-id> <overlay-ip>  -> prints allocated underlay /128
attach_endpoint() {
  local node="$1" id="$2" ip="$3"
  sudo "$DOCKER" exec "$node" ip netns add "$id" 2>/dev/null || true
  local out ul
  out=$(sudo "$DOCKER" run --rm --network "container:$node" $PROTO_MNT "$GRPCURL_IMG" -plaintext \
    -import-path /proto/dataplane/v1 -proto dataplane.proto \
    -d "{\"interface_id\":\"$id\",\"netns_path\":\"/var/run/netns/$id\",\"vni\":${CLAB_VNI},\"requested_ips\":[\"$ip\"]}" \
    "127.0.0.1:${CLAB_DATAPLANE_PORT}" dataplane.v1.DataplaneNode/AttachInterface 2>&1)
  ul=$(echo "$out" | grep -o 'fd00:[0-9a-f:]*' | head -1)
  # dpservice-model addressing inside the endpoint netns
  sudo "$DOCKER" exec "$node" sh -c "ip netns exec $id ip addr add $ip/32 dev $id; \
    ip netns exec $id ip route add 169.254.0.1/32 dev $id; \
    ip netns exec $id ip route add default via 169.254.0.1 dev $id" 2>/dev/null
  echo "$ul"
}

say "attach endpoints on both clusters' nodes"
UL_A=$(attach_endpoint "$CLAB_NODE_A" nic-a "$CLAB_OVERLAY_IP_A"); echo "$CLAB_NODE_A nic-a underlay=$UL_A"
UL_C=$(attach_endpoint "$CLAB_NODE_C" nic-c "$CLAB_OVERLAY_IP_C"); echo "$CLAB_NODE_C nic-c underlay=$UL_C"

say "record allocated underlay /128s in the CRD status (agent announces these)"
"$KUBECTL" --kubeconfig "$K1" patch networkinterface nic-a --subresource=status --type=merge \
  -p "{\"status\":{\"vni\":${CLAB_VNI},\"underlayRoute\":\"$UL_A\",\"state\":\"Ready\"}}"
"$KUBECTL" --kubeconfig "$K1" patch networkinterface nic-c --subresource=status --type=merge \
  -p "{\"status\":{\"vni\":${CLAB_VNI},\"underlayRoute\":\"$UL_C\",\"state\":\"Ready\"}}"
"$KUBECTL" --kubeconfig "$K1" -n ectobase-system rollout restart ds/netplane-agent
"$KUBECTL" --kubeconfig "$K2" -n ectobase-system rollout restart ds/netplane-agent
sleep 18

say "routes learned cross-cluster? (k02's flowplane should have 10.0.0.1 via k01's underlay)"
K2X=$(sudo "$DOCKER" exec "$CLAB_NODE_C" crictl ps --name flowplane -o json 2>/dev/null | grep -o '"id": "[a-f0-9]*"' | head -1 | cut -d'"' -f4)
sudo "$DOCKER" exec "$CLAB_NODE_C" crictl logs "$K2X" 2>&1 | grep -i ROUTE | tail -4

say "stage busybox (musl) for ping"
CID=$(sudo "$DOCKER" create busybox:musl); sudo "$DOCKER" cp "$CID":/bin/busybox /tmp/busybox-musl >/dev/null; sudo "$DOCKER" rm "$CID" >/dev/null
sudo "$DOCKER" cp /tmp/busybox-musl "$CLAB_NODE_A":/busybox
sudo "$DOCKER" cp /tmp/busybox-musl "$CLAB_NODE_C":/busybox

say "CROSS-CLUSTER OVERLAY PING: $CLAB_NODE_A nic-a $CLAB_OVERLAY_IP_A  -->  $CLAB_NODE_C nic-c $CLAB_OVERLAY_IP_C"
sudo "$DOCKER" exec "$CLAB_NODE_A" ip netns exec nic-a /busybox ping -c 3 -W 2 "$CLAB_OVERLAY_IP_C" 2>&1 | tail -5
say "reverse: $CLAB_NODE_C nic-c $CLAB_OVERLAY_IP_C  -->  $CLAB_NODE_A nic-a $CLAB_OVERLAY_IP_A"
sudo "$DOCKER" exec "$CLAB_NODE_C" ip netns exec nic-c /busybox ping -c 3 -W 2 "$CLAB_OVERLAY_IP_A" 2>&1 | tail -5
