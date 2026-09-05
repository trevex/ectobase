//go:build live

package livetest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/config"
)

// Distinct VPC (vni 203) + 10.0.6.x IPs so this suite never collides on a datapath
// interface_id / overlay IP with the gRPC overlay_test (vni-less), pod_test (vni 201,
// 10.0.2.x), or the tier2 fixture (vni 100, 10.0.0.x).
const (
	vmOverlayVNI     = 203
	vmOverlayVMIP    = "10.0.6.10"
	vmOverlayPeerIP  = "10.0.6.11"
	vmOverlayVMMAC   = "52:54:00:00:06:0a"
	vmOverlayPeerMAC = "52:54:00:00:06:0b"
	vmOverlayVMName  = "vmov-vm"
	vmOverlayVMNIC   = "vmov-nic"
	vmOverlayPeerNIC = "vmov-peer-nic"
	// VMI name the pipeline produces: compiler namespace-prefixes the CompiledVM
	// (default-<vm>) and the vm-materializer names the KubeVirt VM after it.
	vmOverlayVMIName = "default-" + vmOverlayVMName
)

// TestVMOverlayConnectivity proves a KubeVirt VirtualMachine reaches the flowplane
// overlay END TO END: it materializes a real VM (unmanaged pod-tap via the `flowplane`
// domainAttachmentType:tap binding), boots it (cirros containerDisk), and pings the VM's
// overlay IP from a peer container on the SAME node + VNI.
//
// This exercises the full VM vertical the pod path can't: NetworkInterface -> CompiledNIC
// (broker-synced, resolved by the launcher's pinned MAC — the CompiledNIC-only contract),
// the KubeVirt binding NAD attached to the launcher, our CNI creating the pod-netns tap
// (`tap<hash>`) + pod link (`pod<hash>`) per virt-launcher's domainAttachmentType:tap
// discovery contract, and the guest self-configuring its overlay IP via the dataplane's
// DHCP/ARP responders. The peer is a container endpoint (reusing the pod_test Container
// path); the ping traverses the local (VNI, overlayIP) INTERFACES demux on one node.
//
// Requires KubeVirt on the target compute cluster (skips otherwise, like TestTier2Failover).
func TestVMOverlayConnectivity(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	// Target the first compute node whose cluster has KubeVirt installed (the lab installs
	// it on k02 via `lab tier2 up`). The VM and its peer share this node so the ping is a
	// local (VNI, overlayIP) delivery — deterministic, no cross-node route convergence.
	node, ok := kubeVirtComputeNode(ctx, cfg)
	if !ok {
		t.Skip("no compute cluster has KubeVirt installed (run `lab tier2 up`)")
	}
	cluster := node.Cluster

	// 1. VPC + two NICs on the DISPATCH (no placement on the NICs — the owning VM/Container
	//    stamp it). defaultPolicy Allow so guest egress isn't deny-by-default dropped.
	applyDispatch(t, ctx, cfg, vmOverlayDispatchFixture(cluster, nodeK8sName(node)))
	// The compiler gates on a Ready VPC/NIC carrying a vni.
	patchVMOverlayReady(t, ctx, cfg, "vpcs.net.ectobase.dev", "vmov-vpc")
	patchVMOverlayReady(t, ctx, cfg, "networkinterfaces.net.ectobase.dev", vmOverlayVMNIC)
	patchVMOverlayReady(t, ctx, cfg, "networkinterfaces.net.ectobase.dev", vmOverlayPeerNIC)

	// 2. The peer container's NAD (flowplane-cni secondary net) on the cluster. The VM's
	//    binding NAD (ectobase-system/flowplane) + the `flowplane` binding registration are
	//    shipped by the pool chart / lab KubeVirt deploy, so only the container NAD is applied
	//    here.
	require.NoError(t, applyCluster(ctx, cfg, cluster, podNADManifest()))
	t.Cleanup(func() {
		_, _ = kubectl(ctx, cfg, cluster, "delete", "net-attach-def", podNADName, "--ignore-not-found")
	})

	// 3. Both CompiledNICs land on the compute cluster (broker sync) — the CNI reads these.
	for _, nic := range []string{vmOverlayVMNIC, vmOverlayPeerNIC} {
		nic := nic
		eventually(t, 2*time.Minute, 5*time.Second, func() error {
			name, err := kubectl(ctx, cfg, cluster,
				"get", "compilednics.compiled.ectobase.dev", "default-"+nic,
				"-o", "jsonpath={.metadata.name}")
			if err != nil {
				return fmt.Errorf("get CompiledNIC default-%s on %s: %w", nic, cluster, err)
			}
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("CompiledNIC default-%s not synced yet on %s", nic, cluster)
			}
			return nil
		})
	}

	// 4. The VMI reaches Running (launcher sandbox stable = idempotent attach; domain boots =
	//    the pod-tap named per KubeVirt's contract). cirros boots under software emulation, so
	//    allow generous time.
	eventually(t, 5*time.Minute, 10*time.Second, func() error {
		phase, err := kubectl(ctx, cfg, cluster, "-n", "default",
			"get", "vmi", vmOverlayVMIName, "-o", "jsonpath={.status.phase}")
		if err != nil {
			return fmt.Errorf("get vmi %s on %s: %w", vmOverlayVMIName, cluster, err)
		}
		if strings.TrimSpace(phase) != "Running" {
			return fmt.Errorf("vmi %s on %s phase=%q, not Running", vmOverlayVMIName, cluster, strings.TrimSpace(phase))
		}
		return nil
	})

	// 5. The peer container Pod reaches Running (its overlay attach succeeded).
	var peerPod string
	eventually(t, 3*time.Minute, 5*time.Second, func() error {
		pod, err := podForContainer(ctx, cfg, cluster, compiledContainerName(vmOverlayPeerNIC))
		if err != nil {
			return err
		}
		phase, err := kubectl(ctx, cfg, cluster, "get", "pod", pod, "-o", "jsonpath={.status.phase}")
		if err != nil {
			return err
		}
		if strings.TrimSpace(phase) != "Running" {
			desc, _ := kubectl(ctx, cfg, cluster, "describe", "pod", pod)
			return fmt.Errorf("peer pod %s on %s phase=%q, not Running:\n%s",
				pod, cluster, strings.TrimSpace(phase), tail(desc, 25))
		}
		peerPod = pod
		return nil
	})

	// 6. The peer's overlay iface landed with its IP (net1) before we ping.
	eventually(t, 60*time.Second, 5*time.Second, func() error {
		out, err := kubectl(ctx, cfg, cluster, "exec", peerPod, "--", "ip", "-o", "addr")
		if err != nil {
			return fmt.Errorf("ip addr in %s: %w\n%s", peerPod, err, out)
		}
		if !strings.Contains(out, vmOverlayPeerIP) {
			return fmt.Errorf("peer %s overlay IP %s not present yet:\n%s", peerPod, vmOverlayPeerIP, out)
		}
		return nil
	})

	// 7. Ping the VM's overlay IP from the peer. Bounded-retry absorbs the guest's DHCP lease
	//    + boot after the VMI reports Running (cirros configures eth0 a few seconds later), and
	//    the agent firewall/route reconcile.
	eventually(t, 4*time.Minute, 5*time.Second, func() error {
		return podPing(ctx, cfg, cluster, peerPod, vmOverlayVMIP)
	})
}

// kubeVirtComputeNode returns the first compute node whose cluster has the KubeVirt CRD
// installed (the VM can only materialize there), and false if none do.
func kubeVirtComputeNode(ctx context.Context, cfg *config.Config) (config.DerivedNode, bool) {
	seen := map[string]bool{}
	for _, n := range computeNodes(cfg) {
		if seen[n.Cluster] {
			continue
		}
		seen[n.Cluster] = true
		if _, err := kubectl(ctx, cfg, n.Cluster, "get", "crd", "virtualmachines.kubevirt.io"); err == nil {
			return n, true
		}
	}
	return config.DerivedNode{}, false
}

// vmOverlayDispatchFixture renders the dispatch fixture: a VPC, a VM NIC + a peer NIC (no
// placement — the owning VM/Container stamp it), a compute.VirtualMachine that owns the VM
// NIC (pinned to cluster, ephemeral cirros containerDisk), and a Container that owns the
// peer NIC (pinned to the same cluster + node).
func vmOverlayDispatchFixture(cluster, node string) string {
	return fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: vmov-vpc}
spec: {vni: %d, defaultPolicy: Allow}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: %s}
spec: {vpcRef: {name: vmov-vpc}, ips: [%q], mac: %q}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: %s}
spec: {vpcRef: {name: vmov-vpc}, ips: [%q], mac: %q}
---
apiVersion: compute.ectobase.dev/v1alpha1
kind: VirtualMachine
metadata: {name: %s, namespace: default}
spec:
  clusterName: %q
  interfaceRefs: [{name: %s}]
  image: quay.io/kubevirt/cirros-container-disk-demo:latest
  runStrategy: RerunOnFailure
  resources: {requests: {cpu: "1", memory: 512Mi}}
---
apiVersion: compute.ectobase.dev/v1alpha1
kind: Container
metadata: {name: %s, namespace: default}
spec:
  clusterName: %q
  nodeName: %q
  interfaceRefs: [{name: %s}]
  image: busybox:1.36
  command: ["sleep", "3600"]
`,
		vmOverlayVNI,
		vmOverlayVMNIC, vmOverlayVMIP, vmOverlayVMMAC,
		vmOverlayPeerNIC, vmOverlayPeerIP, vmOverlayPeerMAC,
		vmOverlayVMName, cluster, vmOverlayVMNIC,
		containerName(vmOverlayPeerNIC), cluster, node, vmOverlayPeerNIC,
	)
}

// patchVMOverlayReady marks a net.ectobase.dev resource's status Ready with this suite's
// vni on the dispatch (the compiler gates on a Ready VPC/NIC with a vni).
func patchVMOverlayReady(t *testing.T, ctx context.Context, cfg *config.Config, resource, name string) {
	t.Helper()
	_, err := kubectl(ctx, cfg, "dispatch", "patch", resource, name,
		"--subresource=status", "--type=merge",
		"-p", fmt.Sprintf(`{"status":{"vni":%d,"state":"Ready"}}`, vmOverlayVNI))
	require.NoError(t, err, "patch %s/%s status", resource, name)
}
