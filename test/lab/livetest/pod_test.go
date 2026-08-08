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

// Control-plane-driven Pod-via-CNI overlay endpoints. Distinct VPC (vni 201) + IPs
// from the gRPC-driven overlay_test so the two suites don't collide on the same
// datapath interface_id / IP.
const (
	podVNI  = 201
	podIPA  = "10.0.2.1"
	podIPC  = "10.0.2.3"
	podMACA = "52:54:00:00:02:0a"
	podMACC = "52:54:00:00:02:0c"
)

// TestPodOverlayPing spawns TWO real Pods, one per compute cluster, each attached to
// our overlay via Multus -> flowplane-cni (a SECONDARY network), and pings across the
// encapsulated overlay both ways.
//
// This drives the REAL control-plane flow: a VPC + two NetworkInterfaces (each with a
// spec.clusterName placement + spec.nodeName) are applied to CENTRAL; the netplane
// compiler lowers them to per-cluster CompiledNICs (stamped with clusterName from the
// NIC placement + nodeName); the brokers sync each CompiledNIC to ITS compute cluster.
// The flowplane-cni then resolves the pod's overlay {vni, ips, mac} from the
// broker-synced CompiledNIC <ns>-<nic> (central policy) — NOT the raw NetworkInterface
// + VPC — and calls the node-local dataplane AttachInterface, which creates the veth in
// the pod netns, addresses it (overlay /32 + 169.254.0.1 gateway), programs the eBPF
// maps, and announces the underlay /128 to the reflector so the cross-cluster route is
// learned. No raw NIC/VPC is applied to the compute clusters.
func TestPodOverlayPing(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) < 2 {
		t.Skip("need >=2 compute nodes across clusters")
	}
	nodeA, nodeC := nodes[0], nodes[1]
	if nodeA.Cluster == nodeC.Cluster {
		t.Skip("need the two endpoints in different clusters")
	}

	type endpoint struct {
		node config.DerivedNode
		nic  string
		ip   string
		mac  string
	}
	epA := endpoint{nodeA, "pod-nic-a", podIPA, podMACA}
	epC := endpoint{nodeC, "pod-nic-c", podIPC, podMACC}

	// 1. VPC + two NICs on CENTRAL. Each NIC carries spec.clusterName (the pod's
	//    cluster placement — what stamps CompiledNIC.clusterName for the broker to
	//    select on) + spec.nodeName (what the agent's firewall reconcile gates on) +
	//    spec.mac. defaultPolicy Allow so guest egress isn't deny-by-default dropped.
	require.NoError(t, applyCentral(ctx, cfg, podCentralFixture(epA.nic, epA.ip, epA.mac, epA.node, epC.nic, epC.ip, epC.mac, epC.node)))
	// The compiler gates on a Ready VPC with a vni; mark VPC + both NICs Ready.
	patchPodVNIReady(t, ctx, cfg, "vpcs.net.ectobase.dev", "pod-vpc")
	patchPodVNIReady(t, ctx, cfg, "networkinterfaces.net.ectobase.dev", epA.nic)
	patchPodVNIReady(t, ctx, cfg, "networkinterfaces.net.ectobase.dev", epC.nic)
	t.Cleanup(func() {
		_, _ = kubectl(ctx, cfg, "central", "delete", "networkinterface.net.ectobase.dev", epA.nic, "--ignore-not-found", "--wait=false")
		_, _ = kubectl(ctx, cfg, "central", "delete", "networkinterface.net.ectobase.dev", epC.nic, "--ignore-not-found", "--wait=false")
		_, _ = kubectl(ctx, cfg, "central", "delete", "vpc.net.ectobase.dev", "pod-vpc", "--ignore-not-found", "--wait=false")
	})

	// 2. Each compute cluster's CompiledNIC lands (broker sync) with the expected node
	//    — the CNI reads THIS object, so it must be present before the pod attaches.
	for _, ep := range []endpoint{epA, epC} {
		ep := ep
		eventually(t, 2*time.Minute, 5*time.Second, func() error {
			nn, err := kubectl(ctx, cfg, ep.node.Cluster,
				"get", "compilednics.net.ectobase.dev", "default-"+ep.nic,
				"-o", "jsonpath={.spec.nodeName}")
			if err != nil {
				return fmt.Errorf("get CompiledNIC default-%s on %s: %w", ep.nic, ep.node.Cluster, err)
			}
			if strings.TrimSpace(nn) != nodeK8sName(ep.node) {
				return fmt.Errorf("CompiledNIC default-%s nodeName=%q, want %q (not synced/stamped yet)",
					ep.nic, strings.TrimSpace(nn), nodeK8sName(ep.node))
			}
			return nil
		})
	}

	// 3. NAD (flowplane-cni secondary net) + the Pod on EACH compute cluster.
	for _, ep := range []endpoint{epA, epC} {
		ep := ep
		require.NoError(t, applyCluster(ctx, cfg, ep.node.Cluster, podNADManifest()))
		require.NoError(t, applyCluster(ctx, cfg, ep.node.Cluster, podManifest(podName(ep.nic), ep.nic, nodeK8sName(ep.node))))
		t.Cleanup(func() {
			_, _ = kubectl(ctx, cfg, ep.node.Cluster, "delete", "pod", podName(ep.nic), "--ignore-not-found", "--force", "--grace-period=0")
			_, _ = kubectl(ctx, cfg, ep.node.Cluster, "delete", "net-attach-def", podNADName, "--ignore-not-found")
		})
	}

	// 4. Both pods Ready (the secondary attach ran = flowplane-cni resolved the
	//    CompiledNIC + AttachInterface succeeded).
	for _, ep := range []endpoint{epA, epC} {
		ep := ep
		eventually(t, 3*time.Minute, 5*time.Second, func() error {
			out, err := kubectl(ctx, cfg, ep.node.Cluster, "get", "pod", podName(ep.nic),
				"-o", "jsonpath={.status.phase}")
			if err != nil {
				return err
			}
			if strings.TrimSpace(out) != "Running" {
				desc, _ := kubectl(ctx, cfg, ep.node.Cluster, "describe", "pod", podName(ep.nic))
				return fmt.Errorf("pod %s on %s phase=%q, not Running:\n%s",
					podName(ep.nic), ep.node.Cluster, strings.TrimSpace(out), tail(desc, 25))
			}
			return nil
		})
	}

	// 5. Confirm the overlay iface landed inside each pod with the expected IP (net1).
	for _, ep := range []endpoint{epA, epC} {
		ep := ep
		eventually(t, 60*time.Second, 5*time.Second, func() error {
			out, err := kubectl(ctx, cfg, ep.node.Cluster, "exec", podName(ep.nic), "--", "ip", "-o", "addr")
			if err != nil {
				return fmt.Errorf("ip addr in %s: %w\n%s", podName(ep.nic), err, out)
			}
			if !strings.Contains(out, ep.ip) {
				return fmt.Errorf("pod %s overlay IP %s not present yet:\n%s", podName(ep.nic), ep.ip, out)
			}
			return nil
		})
	}

	// 6. Cross-cluster overlay ping both ways from inside the pods (bounded-retry to
	//    absorb the agent firewall/route reconcile + reflector propagation).
	eventually(t, 2*time.Minute, 5*time.Second, func() error {
		return podPing(ctx, cfg, epA.node.Cluster, podName(epA.nic), epC.ip)
	})
	eventually(t, 2*time.Minute, 5*time.Second, func() error {
		return podPing(ctx, cfg, epC.node.Cluster, podName(epC.nic), epA.ip)
	})
}

// podName is the Pod name for a NIC.
func podName(nic string) string { return "pod-" + nic }

const podNADName = "flowplane-overlay"

// podCentralFixture renders the central fixture for the two Pod endpoints: a VPC and
// two NetworkInterfaces, each with spec.clusterName (the pod's cluster — stamps the
// CompiledNIC.clusterName the broker selects on), spec.nodeName (the agent firewall
// reconcile gate), spec.ips, and spec.mac. The compiler lowers each to a per-cluster
// CompiledNIC default-<nic>. defaultPolicy Allow so guest egress isn't dropped.
func podCentralFixture(nicA, ipA, macA string, nodeA config.DerivedNode, nicC, ipC, macC string, nodeC config.DerivedNode) string {
	return fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: pod-vpc}
spec: {vni: %d, defaultPolicy: Allow}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: %s}
spec: {vpcRef: {name: pod-vpc}, ips: [%q], mac: %q, clusterName: %q, nodeName: %q}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: %s}
spec: {vpcRef: {name: pod-vpc}, ips: [%q], mac: %q, clusterName: %q, nodeName: %q}
`, podVNI,
		nicA, ipA, macA, nodeA.Cluster, nodeK8sName(nodeA),
		nicC, ipC, macC, nodeC.Cluster, nodeK8sName(nodeC))
}

// podNADManifest renders the NetworkAttachmentDefinition that references flowplane-cni.
// It matches cni/plugin/main.go's netConf: type flowplane-cni, kubeconfig +
// dataplaneAddr defaults are baked into the plugin so we only need the type here (the
// KubeVirt binding NAD is likewise minimal). deviceType is empty (= veth, container).
func podNADManifest() string {
	return fmt.Sprintf(`apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata: {name: %s, namespace: default}
spec:
  config: |
    {
      "cniVersion": "1.0.0",
      "name": "%s",
      "plugins": [
        {
          "type": "flowplane-cni",
          "kubeconfig": "/etc/cni/net.d/dataplane-kubeconfig",
          "dataplaneAddr": "127.0.0.1:1337"
        }
      ]
    }
`, podNADName, podNADName)
}

// podManifest renders a busybox Pod annotated onto our overlay: the flowplane-cni NIC
// ref (net.ectobase.dev/network-interface) + the Multus secondary-network annotation
// (k8s.v1.cni.cncf.io/networks) that runs flowplane-cni as net1. Pinned to the node.
func podManifest(name, nic, node string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: default
  annotations:
    net.ectobase.dev/network-interface: default/%s
    k8s.v1.cni.cncf.io/networks: %s
spec:
  terminationGracePeriodSeconds: 0
  nodeSelector: {kubernetes.io/hostname: %s}
  tolerations: [{operator: Exists}]
  containers:
    - name: c
      image: busybox:1.36
      command: ["sleep", "3600"]
`, name, nic, podNADName, node)
}

// patchPodVNIReady marks a net.ectobase.dev resource's status Ready with the pod
// overlay vni on central (the compiler gates on a Ready VPC/NIC with a vni).
func patchPodVNIReady(t *testing.T, ctx context.Context, cfg *config.Config, resource, name string) {
	t.Helper()
	_, err := kubectl(ctx, cfg, "central", "patch", resource, name,
		"--subresource=status", "--type=merge",
		"-p", fmt.Sprintf(`{"status":{"vni":%d,"state":"Ready"}}`, podVNI))
	require.NoError(t, err, "patch %s/%s status", resource, name)
}

// podPing runs `ping -c3 -W2 <dst>` from inside a pod via kubectl exec.
func podPing(ctx context.Context, cfg *config.Config, cluster, pod, dstIP string) error {
	out, err := kubectl(ctx, cfg, cluster, "exec", pod, "--", "ping", "-c3", "-W2", dstIP)
	if err != nil {
		return fmt.Errorf("overlay ping %s from %s/%s: %w\n%s", dstIP, cluster, pod, err, out)
	}
	return nil
}

// tail returns the last n lines of s (for compact diagnostics on failure).
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
