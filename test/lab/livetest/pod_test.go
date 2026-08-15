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
// This drives the REAL control-plane + container-workload flow END TO END: a VPC + two
// NetworkInterfaces (NO placement on the NICs) are applied to the DISPATCH, and a Container
// per endpoint (carrying the spec.clusterName + spec.nodeName placement and owning its
// NIC via interfaceRefs) is applied to the DISPATCH too. The netplane compiler is the placement
// authority: it stamps each CompiledNIC's clusterName + nodeName FROM the owning Container,
// and lowers the Container itself to a per-cluster CompiledContainer; the brokers sync both
// to ITS compute cluster; the pod-materializer turns each CompiledContainer into a real
// v1.Pod (with the Multus + flowplane-cni annotations). The flowplane-cni then resolves the
// pod's overlay {vni, ips, mac} from the broker-synced CompiledNIC <ns>-<nic> (central
// policy) and calls the node-local dataplane AttachInterface, which creates the veth in the
// pod netns, addresses it (overlay /32 + 169.254.0.1 gateway), programs the eBPF maps, and
// announces the underlay /128 to the reflector so the cross-cluster route is learned. No raw
// Pod/NIC/VPC is applied to the compute clusters — only the NAD.
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

	// 1. VPC + two NICs on the DISPATCH. The NICs carry NO placement: an owning Container is
	//    the placement authority (it stamps CompiledNIC.clusterName + nodeName). Just IPs +
	//    mac here. defaultPolicy Allow so guest egress isn't deny-by-default dropped.
	require.NoError(t, applyDispatch(ctx, cfg, podDispatchFixture(epA.nic, epA.ip, epA.mac, epC.nic, epC.ip, epC.mac)))
	// The compiler gates on a Ready VPC with a vni; mark VPC + both NICs Ready.
	patchPodVNIReady(t, ctx, cfg, "vpcs.net.ectobase.dev", "pod-vpc")
	patchPodVNIReady(t, ctx, cfg, "networkinterfaces.net.ectobase.dev", epA.nic)
	patchPodVNIReady(t, ctx, cfg, "networkinterfaces.net.ectobase.dev", epC.nic)
	t.Cleanup(func() {
		_, _ = kubectl(ctx, cfg, "dispatch", "delete", "networkinterface.net.ectobase.dev", epA.nic, "--ignore-not-found", "--wait=false")
		_, _ = kubectl(ctx, cfg, "dispatch", "delete", "networkinterface.net.ectobase.dev", epC.nic, "--ignore-not-found", "--wait=false")
		_, _ = kubectl(ctx, cfg, "dispatch", "delete", "vpc.net.ectobase.dev", "pod-vpc", "--ignore-not-found", "--wait=false")
	})

	// 2. NAD (flowplane-cni secondary net) on EACH cluster + a Container per endpoint on
	//    CENTRAL. The Container owns its NIC (interfaceRefs) and pins the placement
	//    (clusterName + nodeName); the compiler is the placement authority — it stamps those
	//    onto the owned CompiledNIC AND lowers the Container to a CompiledContainer that the
	//    broker syncs down and the pod-materializer turns into the real Pod (with the
	//    Multus/flowplane-cni annotations). We never create a raw Pod. GC on the Container
	//    cascades to the CompiledContainer + Pod. Applied BEFORE the CompiledNIC placement
	//    check below, since the placement now flows from the Container.
	for _, ep := range []endpoint{epA, epC} {
		ep := ep
		require.NoError(t, applyCluster(ctx, cfg, ep.node.Cluster, podNADManifest()))
		require.NoError(t, applyDispatch(ctx, cfg, containerFixture(containerName(ep.nic), ep.node.Cluster, nodeK8sName(ep.node), ep.nic)))
		t.Cleanup(func() {
			_, _ = kubectl(ctx, cfg, "dispatch", "delete", "container.net.ectobase.dev", containerName(ep.nic), "--ignore-not-found", "--wait=false")
			_, _ = kubectl(ctx, cfg, ep.node.Cluster, "delete", "net-attach-def", podNADName, "--ignore-not-found")
		})
	}

	// 3. Each compute cluster's CompiledNIC lands (broker sync) with the expected node
	//    (stamped from the owning Container) — the CNI reads THIS object, so it must be
	//    present before the pod attaches.
	for _, ep := range []endpoint{epA, epC} {
		ep := ep
		eventually(t, 2*time.Minute, 5*time.Second, func() error {
			name, err := kubectl(ctx, cfg, ep.node.Cluster,
				"get", "compilednics.compiled.ectobase.dev", "default-"+ep.nic,
				"-o", "jsonpath={.metadata.name}")
			if err != nil {
				return fmt.Errorf("get CompiledNIC default-%s on %s: %w", ep.nic, ep.node.Cluster, err)
			}
			// nodeName was removed from CompiledNIC (the agent self-locates by (VNI, overlayIP)),
			// so the pre-condition is simply that the broker-synced CompiledNIC is present.
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("CompiledNIC default-%s not synced yet on %s", ep.nic, ep.node.Cluster)
			}
			return nil
		})
	}

	// 4. Both pods Ready (materializer created the Pod + the secondary attach ran =
	//    flowplane-cni resolved the CompiledNIC + AttachInterface succeeded). The Pod name
	//    is the CompiledContainer name; we resolve it by the materializer's label to avoid
	//    coupling to the <ns>-<name> format.
	podByEP := map[string]string{}
	for _, ep := range []endpoint{epA, epC} {
		ep := ep
		eventually(t, 3*time.Minute, 5*time.Second, func() error {
			pod, err := podForContainer(ctx, cfg, ep.node.Cluster, compiledContainerName(ep.nic))
			if err != nil {
				return err
			}
			phase, err := kubectl(ctx, cfg, ep.node.Cluster, "get", "pod", pod, "-o", "jsonpath={.status.phase}")
			if err != nil {
				return err
			}
			if strings.TrimSpace(phase) != "Running" {
				desc, _ := kubectl(ctx, cfg, ep.node.Cluster, "describe", "pod", pod)
				return fmt.Errorf("pod %s on %s phase=%q, not Running:\n%s",
					pod, ep.node.Cluster, strings.TrimSpace(phase), tail(desc, 25))
			}
			podByEP[ep.nic] = pod
			return nil
		})
	}

	// 5. Confirm the overlay iface landed inside each pod with the expected IP (net1).
	for _, ep := range []endpoint{epA, epC} {
		ep := ep
		eventually(t, 60*time.Second, 5*time.Second, func() error {
			out, err := kubectl(ctx, cfg, ep.node.Cluster, "exec", podByEP[ep.nic], "--", "ip", "-o", "addr")
			if err != nil {
				return fmt.Errorf("ip addr in %s: %w\n%s", podByEP[ep.nic], err, out)
			}
			if !strings.Contains(out, ep.ip) {
				return fmt.Errorf("pod %s overlay IP %s not present yet:\n%s", podByEP[ep.nic], ep.ip, out)
			}
			return nil
		})
	}

	// 6. Cross-cluster overlay ping both ways from inside the pods (bounded-retry to
	//    absorb the agent firewall/route reconcile + reflector propagation).
	eventually(t, 2*time.Minute, 5*time.Second, func() error {
		return podPing(ctx, cfg, epA.node.Cluster, podByEP[epA.nic], epC.ip)
	})
	eventually(t, 2*time.Minute, 5*time.Second, func() error {
		return podPing(ctx, cfg, epC.node.Cluster, podByEP[epC.nic], epA.ip)
	})
}

// containerName is the Container name that owns a NIC.
func containerName(nic string) string { return "ctr-" + nic }

// compiledContainerName is the CompiledContainer (and materialized Pod) name for a NIC:
// the compiler names it <namespace>-<container> (all fixtures live in the default namespace).
func compiledContainerName(nic string) string { return "default-" + containerName(nic) }

const podNADName = "flowplane-overlay"

// podDispatchFixture renders the dispatch fixture for the two Pod endpoints: a VPC and
// two NetworkInterfaces with spec.ips + spec.mac and NO placement. The owning Container
// (applied separately) is the placement authority — it stamps the CompiledNIC's
// clusterName + nodeName. The compiler lowers each NIC to a per-cluster CompiledNIC
// default-<nic>. defaultPolicy Allow so guest egress isn't dropped.
func podDispatchFixture(nicA, ipA, macA, nicC, ipC, macC string) string {
	return fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: pod-vpc}
spec: {vni: %d, defaultPolicy: Allow}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: %s}
spec: {vpcRef: {name: pod-vpc}, ips: [%q], mac: %q}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: %s}
spec: {vpcRef: {name: pod-vpc}, ips: [%q], mac: %q}
`, podVNI, nicA, ipA, macA, nicC, ipC, macC)
}

// containerFixture renders a Container that owns nic and pins its placement (clusterName +
// nodeName). The compiler is the placement authority: it stamps those onto the owned
// CompiledNIC and lowers this Container to a CompiledContainer that the pod-materializer
// turns into the real Pod. name/node are the container name and the k8s hostname.
func containerFixture(name, cluster, node, nic string) string {
	return fmt.Sprintf(`apiVersion: compute.ectobase.dev/v1alpha1
kind: Container
metadata: {name: %s, namespace: default}
spec:
  clusterName: %q
  nodeName: %q
  interfaceRefs: [{name: %s}]
  image: busybox:1.36
  command: ["sleep", "3600"]
`, name, cluster, node, nic)
}

// podForContainer resolves the materialized Pod name for a CompiledContainer via the
// materializer's net.ectobase.dev/container label (avoids coupling to the pod's name
// format). Errors until exactly one matching pod exists.
func podForContainer(ctx context.Context, cfg *config.Config, cluster, compiledContainer string) (string, error) {
	out, err := kubectl(ctx, cfg, cluster, "get", "pod",
		"-l", "net.ectobase.dev/container="+compiledContainer,
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return "", fmt.Errorf("get pod for container %s on %s: %w", compiledContainer, cluster, err)
	}
	name := strings.TrimSpace(out)
	if name == "" {
		return "", fmt.Errorf("no Pod yet for container %s on %s (materializer not caught up?)", compiledContainer, cluster)
	}
	if strings.ContainsAny(name, " \t") {
		return "", fmt.Errorf("multiple Pods for container %s on %s: %q", compiledContainer, cluster, name)
	}
	return name, nil
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
          "dataplaneAddr": "unix:///run/flowplane/dataplane.sock"
        }
      ]
    }
`, podNADName, podNADName)
}

// patchPodVNIReady marks a net.ectobase.dev resource's status Ready with the pod
// overlay vni on the dispatch (the compiler gates on a Ready VPC/NIC with a vni).
func patchPodVNIReady(t *testing.T, ctx context.Context, cfg *config.Config, resource, name string) {
	t.Helper()
	_, err := kubectl(ctx, cfg, "dispatch", "patch", resource, name,
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
