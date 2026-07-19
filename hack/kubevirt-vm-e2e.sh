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
NODE=k01-control-plane
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

say "kubeconfig + reachability"
sudo kind get kubeconfig --name "$CL" > "$KC"
k get --raw=/healthz >/dev/null || { echo "FATAL: $CL unreachable; run hack/clab-up.sh"; exit 1; }
k get nodes -o name

say "build + load images"
make image image-netplane image-cni >/tmp/kv-build.log 2>&1 || { echo "image build failed"; tail -20 /tmp/kv-build.log; exit 1; }
for img in "$XDP" "$NETPLANE" "$CNI"; do sudo kind load docker-image "$img" --name "$CL" 2>&1 | tail -1; done

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

say "wait for VMI Running, then ping the VM from the peer ($PEER_IP -> $VM_IP)"
k -n default wait vmi/vm-a --for=jsonpath='{.status.phase}'=Running --timeout=180s 2>&1 | tail -1
echo "give the guest ~90s to boot + DHCP under emulation..."
sleep 90
sudo docker exec "$NODE" ip netns exec peer ping -c 4 -W 3 "$VM_IP" 2>&1 | tail -5
echo ""
echo "=== if 0% loss above: a KubeVirt VM self-configured on the flowplane overlay via pod-tap ==="
