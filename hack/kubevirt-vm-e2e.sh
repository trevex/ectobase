#!/usr/bin/env bash
# hack/kubevirt-vm-e2e.sh — end-to-end: a KubeVirt VM whose PRIMARY NIC is the flowplane
# overlay via the pod-tap network binding. Runs on the k01 cluster of the clab fabric.
#
# Prereqs: the fabric is up (sudo ./hack/clab-up.sh); kind + kubectl + docker on PATH.
# Builds+loads the flowplane / netplane / cni images, installs KubeVirt+Multus+CDI, deploys
# our stack (+ CNI installer + binding NAD), then applies a VPC + NetworkInterface + a VMI and
# verifies: (1) the CNI+binding attach a tap0 in the launcher netns and program the datapath,
# (2) the VM boots, (3) a peer endpoint on the same node reaches the VM's overlay IP.
#
# Run from the repo root:  sudo -E env "PATH=$HOME/go/bin:$PATH" bash hack/kubevirt-vm-e2e.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PATH="$HOME/go/bin:$PATH"

CL=k01
# The VM's node: a WORKER (virt-handler only advertises the kvm/tun device plugins on untainted
# nodes, so the launcher can't land on the tainted control-plane). The peer endpoint attaches here
# too so the overlay ping uses the same-node local fast path.
NODE=k01-worker
XDP=ghcr.io/trevex/ectobase/flowplane:dev
NETPLANE=ghcr.io/trevex/ectobase/netplane:dev
CNI=ghcr.io/trevex/ectobase/cni:dev
VM_IP=10.0.0.50 ; VM_MAC=52:54:00:00:00:50
PEER_IP=10.0.0.51
GRPCURL_IMG=fullstorydev/grpcurl:latest
PROTO_MNT="-v $(pwd)/api/proto:/proto:ro"

KC=$(mktemp -t k01.kubeconfig.XXXXXX); trap 'rm -f "$KC"' EXIT
say() { echo -e "\n=== $* ==="; }
k() { kubectl --kubeconfig "$KC" "$@"; }
# `kind` lives in ~/go/bin; plain `sudo` resets PATH and can't find it, so preserve PATH.
KIND() { sudo env "PATH=$PATH" kind "$@"; }

say "kubeconfig + reachability"
KIND get kubeconfig --name "$CL" > "$KC"
k get --raw=/healthz >/dev/null || { echo "FATAL: $CL unreachable; run hack/clab-up.sh"; exit 1; }
k get nodes -o name

say "build + load images"
make image image-netplane image-cni >/tmp/kv-build.log 2>&1 || { echo "image build failed"; tail -20 /tmp/kv-build.log; exit 1; }
for img in "$XDP" "$NETPLANE" "$CNI"; do KIND load docker-image "$img" --name "$CL" 2>&1 | tail -1; done

say "CRDs + stack (flowplane + agent + CNI installer)"
k apply -k config/crd 2>&1 | tail -1
k apply -k config/deploy 2>&1 | grep -E 'created|configured|unchanged' | tail -8
k -n ectobase-system rollout status ds/flowplane --timeout=120s 2>&1 | tail -1
k -n ectobase-system rollout status ds/flowplane-cni-install --timeout=120s 2>&1 | tail -1

say "install KubeVirt + Multus + CDI + the flowplane binding (emulation)"
KUBECONFIG="$KC" bash hack/install-stack.sh
k apply -f config/deploy/kubevirt-binding.yaml

say "VPC + NetworkInterface (mac threaded) for the VM"
k apply -f - <<EOF
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: blue, namespace: default}
spec: {vni: 100}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: nic-vm, namespace: default}
spec: {vpcRef: {name: blue}, ips: ["$VM_IP"], mac: "$VM_MAC", nodeName: $NODE}
EOF
k patch vpc blue --subresource=status --type=merge -p '{"status":{"vni":100,"state":"Ready"}}'

say "attach a peer endpoint on $NODE (the VM's ping target, same VNI)"
sudo docker exec "$NODE" ip netns add peer 2>/dev/null || true
sudo docker run --rm --network "container:$NODE" $PROTO_MNT "$GRPCURL_IMG" -plaintext \
  -import-path /proto/dataplane/v1 -proto dataplane.proto \
  -d "{\"interface_id\":\"peer\",\"netns_path\":\"/var/run/netns/peer\",\"vni\":100,\"requested_ips\":[\"$PEER_IP\"]}" \
  127.0.0.1:1337 dataplane.v1.DataplaneNode/AttachInterface 2>&1 | grep -o 'fd00:[0-9a-f:]*' | head -1
sudo docker exec "$NODE" sh -c "ip netns exec peer ip addr add $PEER_IP/32 dev peer; \
  ip netns exec peer ip route add 169.254.0.1/32 dev peer; \
  ip netns exec peer ip route add default via 169.254.0.1 dev peer" 2>/dev/null || true

say "VMI on the overlay (binding=flowplane, mac=$VM_MAC, pinned to $NODE)"
k apply -f - <<EOF
apiVersion: kubevirt.io/v1
kind: VirtualMachineInstance
metadata:
  name: vm-a
  namespace: default
  annotations:
    net.ectobase.dev/network-interface: default/nic-vm
spec:
  nodeSelector:
    kubernetes.io/hostname: $NODE
  # $NODE is the control-plane node (where the peer + flowplane run); tolerate its taint.
  tolerations:
    - key: node-role.kubernetes.io/control-plane
      operator: Exists
      effect: NoSchedule
  domain:
    devices:
      disks: [{name: cd, disk: {bus: virtio}}]
      interfaces:
        - name: ovl
          binding: {name: flowplane}
          macAddress: "$VM_MAC"
    resources: {requests: {memory: 512Mi}}
  networks:
    - name: ovl
      pod: {}
  volumes:
    - name: cd
      containerDisk: {image: quay.io/kubevirt/cirros-container-disk-demo}
EOF

say "wait for the virt-launcher pod + the CNI/binding attach (tap0 in launcher netns)"
for _ in $(seq 1 60); do
  POD=$(k -n default get pod -l kubevirt.io=virt-launcher -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  [ -n "$POD" ] && break; sleep 2
done
echo "launcher pod: ${POD:-<none>}"
k -n default get pod "$POD" -o wide 2>/dev/null || true
say "did the CNI program the datapath? (flowplane INTERFACES readback for $VM_IP)"
FP=$(sudo docker exec "$NODE" crictl ps --name flowplane -o json 2>/dev/null | grep -o '"id": "[a-f0-9]*"' | head -1 | cut -d'"' -f4)
sudo docker exec "$NODE" crictl logs "$FP" 2>&1 | grep -iE "INTERFACES readback vni=100 ip=$VM_IP" | tail -2 || echo "  (no readback yet — see launcher pod events below)"
k -n default describe pod "$POD" 2>/dev/null | grep -A6 Events: | tail -8 || true

say "firewall allow for the VM + peer (datapath is deny-by-default; no CompiledNIC in this test)"
# grpc helper against the node's flowplane; VM interface_id = <launcher-pod-uid>/<multus-ifname>,
# discovered via ListInterfaces (matched on the overlay IP).
DP() { sudo docker run --rm --network "container:$NODE" -v "$(pwd)/api/proto:/proto:ro" "$GRPCURL_IMG" \
  -plaintext -import-path /proto/dataplane/v1 -proto dataplane.proto -d "$2" \
  127.0.0.1:1337 "dataplane.v1.DataplaneNode/$1" 2>&1; }
VM_ID=$(DP ListInterfaces '{}' | tr -d ' ",' | awk -F: '/interfaceId/{id=$2} /ipv4/{if($2=="'"$VM_IP"'")print id}' | head -1)
echo "VM interface_id=$VM_ID"
for pair in "$VM_ID vm" "peer peer"; do set -- $pair
  DP AddFwRule "{\"interface_id\":\"$1\",\"rule_id\":\"$2-eg\",\"proto\":0,\"allow\":true,\"egress\":true}"  >/dev/null
  DP AddFwRule "{\"interface_id\":\"$1\",\"rule_id\":\"$2-in\",\"proto\":0,\"allow\":true,\"egress\":false}" >/dev/null
done

say "wait for VMI Running, then ping the VM from the peer ($PEER_IP -> $VM_IP)"
k -n default wait vmi/vm-a --for=jsonpath='{.status.phase}'=Running --timeout=180s 2>&1 | tail -1
# kind nodes have no ping/tcpdump — stage a static busybox. The guest boots slowly under TCG emulation.
CID=$(sudo docker create busybox:musl); sudo docker cp "$CID":/bin/busybox /tmp/busybox-musl >/dev/null 2>&1; sudo docker rm "$CID" >/dev/null
sudo docker cp /tmp/busybox-musl "$NODE":/busybox
echo "waiting for the guest to boot + DHCP-self-configure, then pinging (up to ~4m)..."
for i in $(seq 1 20); do
  out=$(sudo docker exec "$NODE" ip netns exec peer /busybox ping -c 3 -W 2 "$VM_IP" 2>&1)
  echo "[$i] $(echo "$out" | grep -oE '[0-9]+% packet loss')"
  if echo "$out" | grep -q ' 0% packet loss'; then
    echo "$out" | grep -E 'bytes from|round-trip'
    echo "=== PASS: a KubeVirt VM self-configured on the flowplane overlay (pod-tap) + is reachable ==="
    exit 0
  fi
  sleep 12
done
echo "=== FAIL: no reply from the VM after boot window ==="; exit 1
