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

// Control-plane-driven VPC-peering scenario, ported from test/scenario-vpc-peering.sh
// but driven end-to-end through the real control plane: VPCs / NICs / VPCPeerings /
// FirewallPolicies + a Container per endpoint are applied to the DISPATCH, the mesh
// compiler lowers them to per-cluster CompiledNICs (with PeerImports + firewall) and
// CompiledContainers, the brokers sync them to the compute clusters, and the
// pod-materializer spawns the REAL Pods (attached via Multus + flowplane-cni). No raw
// Pod and no direct dataplane AttachInterface: the owning Container is the placement
// authority and the materializer + CNI produce and attach each pod.
//
// Distinct VNIs (110/120) + IP ranges (10.0.10.x / 10.0.20.x) so it never collides
// with the overlay(100)/pod(201)/qos/dhcp/nat suites.
const (
	peerBlueVNI  = 110
	peerGreenVNI = 120

	peerBlueSubnet  = "10.0.10.0/24"
	peerGreenSubnet = "10.0.20.0/24"

	blueGuestIP  = "10.0.10.11"
	greenGuestIP = "10.0.20.11"
	// greenLocalIP falls inside blue's exposed 10.0.10.0/24 — the overlap-precedence case.
	greenLocalIP = "10.0.10.77"

	blueGuestMAC  = "52:54:00:00:0a:0b"
	greenGuestMAC = "52:54:00:00:14:0b"
	greenLocalMAC = "52:54:00:00:0a:4d"
)

// TestVPCPeering proves the three properties of the VPC-peering feature with pods
// attached via the CNI:
//
//  1. DENY-BY-DEFAULT (two-step): the mutual-consent VPCPeering pair imports the route
//     between the VPCs, but green's ingress firewall is deny-by-default — a cross-VPC
//     ping from blue-guest -> green-guest MUST FAIL until an explicit allow policy.
//  2. REACHABILITY + POLICY: after replacing green's deny-all with an ingress-allow of
//     blue's CIDR, the same cross-VPC ping MUST SUCCEED (route was already imported;
//     only the firewall changed).
//  3. OVERLAP PRECEDENCE (local wins): green-local@10.0.10.77 is a LOCAL green interface
//     whose IP falls inside blue's exposed 10.0.10.0/24. A local /32 delivers via the
//     INTERFACES map, shadowing the imported peer prefix — proven functionally by a
//     same-VPC ping green-guest -> green-local reaching the local pod.
func TestVPCPeering(t *testing.T) {
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

	// blue-guest -> nodeA (blue VPC); green-guest + green-local -> nodeC (green VPC).
	type endpoint struct {
		node config.DerivedNode
		nic  string
		ip   string
		mac  string
		vni  int
	}
	blue := endpoint{nodeA, "blue-guest", blueGuestIP, blueGuestMAC, peerBlueVNI}
	green := endpoint{nodeC, "green-guest", greenGuestIP, greenGuestMAC, peerGreenVNI}
	local := endpoint{nodeC, "green-local", greenLocalIP, greenLocalMAC, peerGreenVNI}
	all := []endpoint{blue, green, local}

	// 1. VPCs + NICs on the DISPATCH (NO placement on the NICs — the owning Containers, applied
	//    in step 5, are the placement authority). Green NICs carry label side=green so the
	//    FirewallPolicy selector governs them (replacing the compiler's allow-all fallback).
	require.NoError(t, applyDispatch(ctx, cfg, vpcPeeringCentralFixture(blue, green, local)))
	// The compiler gates on Ready VPCs/NICs with a vni; patch each with its own vni.
	patchVNIReadyN(t, ctx, cfg, "vpcs.net.ectobase.dev", "peer-blue", peerBlueVNI)
	patchVNIReadyN(t, ctx, cfg, "vpcs.net.ectobase.dev", "peer-green", peerGreenVNI)
	patchVNIReadyN(t, ctx, cfg, "networkinterfaces.net.ectobase.dev", blue.nic, blue.vni)
	patchVNIReadyN(t, ctx, cfg, "networkinterfaces.net.ectobase.dev", green.nic, green.vni)
	patchVNIReadyN(t, ctx, cfg, "networkinterfaces.net.ectobase.dev", local.nic, local.vni)

	t.Cleanup(func() {
		_, _ = kubectl(ctx, cfg, "dispatch", "delete", "vpcpeering.net.ectobase.dev", "blue-to-green", "green-to-blue", "--ignore-not-found", "--wait=false")
		_, _ = kubectl(ctx, cfg, "dispatch", "delete", "firewallpolicy.net.ectobase.dev", "green-deny-all", "green-allow-blue", "--ignore-not-found", "--wait=false")
		for _, ep := range all {
			_, _ = kubectl(ctx, cfg, "dispatch", "delete", "container.net.ectobase.dev", containerName(ep.nic), "--ignore-not-found", "--wait=false")
			_, _ = kubectl(ctx, cfg, "dispatch", "delete", "networkinterface.net.ectobase.dev", ep.nic, "--ignore-not-found", "--wait=false")
		}
		_, _ = kubectl(ctx, cfg, "dispatch", "delete", "vpc.net.ectobase.dev", "peer-blue", "peer-green", "--ignore-not-found", "--wait=false")
	})

	// A Container per endpoint on the DISPATCH owns its NIC and pins the placement (clusterName +
	// nodeName): the compiler stamps those onto the owned CompiledNIC and lowers the Container
	// to a CompiledContainer the pod-materializer turns into the real Pod. Apply the NADs too
	// (one per compute cluster). These must exist before the step-4 CompiledNIC placement check.
	appliedNADClusters := map[string]bool{}
	for _, ep := range all {
		ep := ep
		if !appliedNADClusters[ep.node.Cluster] {
			require.NoError(t, applyCluster(ctx, cfg, ep.node.Cluster, podNADManifest()))
			appliedNADClusters[ep.node.Cluster] = true
		}
		require.NoError(t, applyDispatch(ctx, cfg, containerFixture(containerName(ep.nic), ep.node.Cluster, nodeK8sName(ep.node), ep.nic)))
	}
	t.Cleanup(func() {
		for cl := range appliedNADClusters {
			_, _ = kubectl(ctx, cfg, cl, "delete", "net-attach-def", podNADName, "--ignore-not-found")
		}
	})

	// 2. Deny-all ingress policy on green BEFORE the peering. Without a selecting policy the
	//    compiler emits an allow-until-selected fallback and Assertion 1 could never deny.
	require.NoError(t, applyDispatch(ctx, cfg, `apiVersion: net.ectobase.dev/v1alpha1
kind: FirewallPolicy
metadata: {name: green-deny-all}
spec:
  interfaceSelector: {matchLabels: {side: green}}
  ingress:
    - {cidr: "0.0.0.0/0", action: "Deny"}
`))

	// 3. Mutual-consent VPCPeering pair. The VPCPeeringReconciler drives BOTH to Ready.
	require.NoError(t, applyDispatch(ctx, cfg, vpcPeeringPairFixture()))
	for _, name := range []string{"blue-to-green", "green-to-blue"} {
		name := name
		eventually(t, 2*time.Minute, 3*time.Second, func() error {
			st, err := kubectl(ctx, cfg, "dispatch", "get", "vpcpeering.net.ectobase.dev", name,
				"-o", "jsonpath={.status.state}")
			if err != nil {
				return err
			}
			if strings.TrimSpace(st) != "Ready" {
				return fmt.Errorf("vpcpeering %s state=%q, want Ready", name, strings.TrimSpace(st))
			}
			return nil
		})
	}

	// 4. Each compute cluster's CompiledNIC lands (broker sync) on the expected node — the
	//    CNI reads THIS object. Also require the peer import to be present on the guest NICs
	//    so we know the compiler lowered the Ready peering before we ping.
	for _, ep := range all {
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
	// Guest NICs must carry the imported peer prefix (blue imports green's subnet + vice-versa).
	requirePeerImport(t, ctx, cfg, blue.node.Cluster, "default-"+blue.nic, peerGreenSubnet)
	requirePeerImport(t, ctx, cfg, green.node.Cluster, "default-"+green.nic, peerBlueSubnet)

	// 5. The materializer turns each CompiledContainer into a real Pod: wait for all three
	//    Running (secondary attach ran = CNI resolved CompiledNIC + AttachInterface). Resolve
	//    the Pod name via the materializer's net.ectobase.dev/container label.
	podByNIC := map[string]string{}
	for _, ep := range all {
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
				return fmt.Errorf("pod %s on %s phase=%q, not Running:\n%s", pod, ep.node.Cluster, strings.TrimSpace(phase), tail(desc, 25))
			}
			podByNIC[ep.nic] = pod
			return nil
		})
	}

	// 6. Overlay iface landed inside each pod with the expected IP (net1).
	for _, ep := range all {
		ep := ep
		eventually(t, 60*time.Second, 5*time.Second, func() error {
			out, err := kubectl(ctx, cfg, ep.node.Cluster, "exec", podByNIC[ep.nic], "--", "ip", "-o", "addr")
			if err != nil {
				return fmt.Errorf("ip addr in %s: %w\n%s", podByNIC[ep.nic], err, out)
			}
			if !strings.Contains(out, ep.ip) {
				return fmt.Errorf("pod %s overlay IP %s not present yet:\n%s", podByNIC[ep.nic], ep.ip, out)
			}
			return nil
		})
	}

	// -----------------------------------------------------------------------
	// ASSERTION 1: pre-policy cross-VPC ping MUST FAIL (deny-by-default two-step).
	// green-deny-all makes green "selected" so the compiler emits a real deny; the
	// peering imported the route but grants NO firewall permission. Retry a few times
	// to confirm it's consistently denied (not just slow to converge).
	// -----------------------------------------------------------------------
	requireConsistentlyDenied(t, ctx, cfg, blue.node.Cluster, podByNIC[blue.nic], green.ip)
	t.Logf("Assertion 1 PASS: pre-policy cross-VPC ping blue-guest -> %s consistently blocked (deny-by-default)", green.ip)

	// -----------------------------------------------------------------------
	// ASSERTION 2: swap deny-all -> allow blue's CIDR; the same ping MUST SUCCEED.
	// Replace (not layer) so exactly one selecting policy governs green at a time.
	// -----------------------------------------------------------------------
	_, _ = kubectl(ctx, cfg, "dispatch", "delete", "firewallpolicy.net.ectobase.dev", "green-deny-all", "--ignore-not-found")
	require.NoError(t, applyDispatch(ctx, cfg, fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: FirewallPolicy
metadata: {name: green-allow-blue}
spec:
  interfaceSelector: {matchLabels: {side: green}}
  ingress:
    - {cidr: %q, proto: ICMP, action: Allow}
`, peerBlueSubnet)))

	eventually(t, 3*time.Minute, 5*time.Second, func() error {
		return podPing(ctx, cfg, blue.node.Cluster, podByNIC[blue.nic], green.ip)
	})
	t.Logf("Assertion 2 PASS: post-policy cross-VPC ping blue-guest -> %s succeeded", green.ip)

	// -----------------------------------------------------------------------
	// ASSERTION 3: overlap precedence — green-local@10.0.10.77 (local green /32) shadows
	// blue's imported 10.0.10.0/24. A same-VPC ping green-guest -> green-local reaches the
	// LOCAL green-local pod (local delivery via INTERFACES map, always allowed intra-VPC).
	// Cross-check via the dataplane: ListInterfaces on the green node reports 10.0.10.77.
	// -----------------------------------------------------------------------
	eventually(t, 2*time.Minute, 5*time.Second, func() error {
		return podPing(ctx, cfg, green.node.Cluster, podByNIC[green.nic], local.ip)
	})
	greenContainer := nodeContainer(cfg, green.node)
	out, err := dataplaneGRPC(t, ctx, greenContainer, "ListInterfaces", "")
	require.NoError(t, err, "ListInterfaces on green node: %s", out)
	require.Contains(t, out, greenLocalIP,
		"overlap-precedence: %s must be a LOCAL interface on the green node (shadows blue's imported %s)", greenLocalIP, peerBlueSubnet)
	t.Logf("Assertion 3 PASS: green-guest -> %s reaches the local green-local pod; ListInterfaces confirms %s is local on the green node",
		local.ip, greenLocalIP)
}

// vpcPeeringCentralFixture renders the two VPCs and three NICs (NO placement — the owning
// Containers are the placement authority). Green NICs get label side=green so the
// FirewallPolicy selector governs them. Each NIC carries spec.ips and spec.mac.
func vpcPeeringCentralFixture(blue, green, local struct {
	node config.DerivedNode
	nic  string
	ip   string
	mac  string
	vni  int
}) string {
	return fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: peer-blue}
spec: {vni: %d}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: peer-green}
spec: {vni: %d}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: %s, labels: {scenario: vpc-peering, side: blue}}
spec: {vpcRef: {name: peer-blue}, ips: [%q], mac: %q}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: %s, labels: {scenario: vpc-peering, side: green}}
spec: {vpcRef: {name: peer-green}, ips: [%q], mac: %q}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: %s, labels: {scenario: vpc-peering, side: green}}
spec: {vpcRef: {name: peer-green}, ips: [%q], mac: %q}
`,
		peerBlueVNI, peerGreenVNI,
		blue.nic, blue.ip, blue.mac,
		green.nic, green.ip, green.mac,
		local.nic, local.ip, local.mac,
	)
}

// vpcPeeringPairFixture renders the mutual-consent VPCPeering pair. Each side exposes its
// own subnet; the reciprocal presence drives both to status.state=Ready.
func vpcPeeringPairFixture() string {
	return fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: VPCPeering
metadata: {name: blue-to-green}
spec:
  vpcRef: {name: peer-blue}
  peerVpcRef: {namespace: default, name: peer-green}
  exposedPrefixes: [%q]
---
apiVersion: net.ectobase.dev/v1alpha1
kind: VPCPeering
metadata: {name: green-to-blue}
spec:
  vpcRef: {name: peer-green}
  peerVpcRef: {namespace: default, name: peer-blue}
  exposedPrefixes: [%q]
`, peerBlueSubnet, peerGreenSubnet)
}

// patchVNIReadyN marks a net.ectobase.dev resource's status Ready with an explicit vni
// (the vni-parameterized variant of patchPodVNIReady — the two VPCs use distinct vnis).
func patchVNIReadyN(t *testing.T, ctx context.Context, cfg *config.Config, resource, name string, vni int) {
	t.Helper()
	_, err := kubectl(ctx, cfg, "dispatch", "patch", resource, name,
		"--subresource=status", "--type=merge",
		"-p", fmt.Sprintf(`{"status":{"vni":%d,"state":"Ready"}}`, vni))
	require.NoError(t, err, "patch %s/%s status (vni %d)", resource, name, vni)
}

// requirePeerImport waits until the broker-synced CompiledNIC on a cluster carries the
// expected imported peer prefix, proving the compiler lowered the Ready VPCPeering.
func requirePeerImport(t *testing.T, ctx context.Context, cfg *config.Config, cluster, compiledNIC, prefix string) {
	t.Helper()
	eventually(t, 2*time.Minute, 5*time.Second, func() error {
		out, err := kubectl(ctx, cfg, cluster, "get", "compilednics.compiled.ectobase.dev", compiledNIC,
			"-o", "jsonpath={.spec.peerImports}")
		if err != nil {
			return fmt.Errorf("get %s peerImports on %s: %w", compiledNIC, cluster, err)
		}
		if !strings.Contains(out, prefix) {
			return fmt.Errorf("%s peerImports missing %s (got %q)", compiledNIC, prefix, strings.TrimSpace(out))
		}
		return nil
	})
}

// requireConsistentlyDenied asserts a ping is DENIED across several attempts spread over a
// short settle window, so a genuine deny is not confused with slow convergence. It first
// gives the agent a bounded window to program the deny (the ping may briefly succeed while
// the compiled deny is still reconciling), then requires N consecutive failures.
func requireConsistentlyDenied(t *testing.T, ctx context.Context, cfg *config.Config, cluster, pod, dstIP string) {
	t.Helper()
	// Bounded window for the deny to converge: require the ping to START failing.
	eventually(t, 2*time.Minute, 5*time.Second, func() error {
		if err := podPing(ctx, cfg, cluster, pod, dstIP); err == nil {
			return fmt.Errorf("ping %s from %s still SUCCEEDS (deny not yet converged)", dstIP, pod)
		}
		return nil
	})
	// Then confirm it stays denied: several consecutive failures.
	for i := 0; i < 3; i++ {
		if err := podPing(ctx, cfg, cluster, pod, dstIP); err == nil {
			t.Fatalf("pre-policy cross-VPC ping %s from %s SUCCEEDED on attempt %d (expected consistent DROP — deny-by-default not enforced)", dstIP, pod, i+1)
		}
		time.Sleep(2 * time.Second)
	}
}
