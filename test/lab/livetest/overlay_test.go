//go:build live

package livetest

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// Cross-cluster overlay endpoints: same VPC (vni 100), one per compute cluster.
const (
	overlayVNI    = 100
	overlayIPA    = "10.0.0.1"
	overlayIPC    = "10.0.0.3"
	overlayMACA   = "52:54:00:00:00:0a"
	overlayMACC   = "52:54:00:00:00:0c"
	dataplaneAddr = "127.0.0.1:1337"
)

// TestCrossClusterOverlayPing drives the FULL control pipeline and datapath: a VPC
// + two NetworkInterfaces on central compile (netplane compiler) to per-cluster
// CompiledNICs stamped with clusterName (from the anchor VMs) and nodeName (from
// the NIC, which is what a scheduled workload sets and what the agent's firewall
// reconcile gates on); the brokers sync them; the agents program the Allow firewall
// + learn the peer route via the reflector. The test then attaches an endpoint on
// each node's flowplane over the real dataplane AttachInterface (grpcurl at
// 127.0.0.1:1337 in the node netns), addresses the endpoint netns dpservice-style,
// and pings across the encapsulated overlay in both directions.
func TestCrossClusterOverlayPing(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) < 2 {
		t.Skip("need >=2 compute nodes across clusters")
	}
	// Distinct clusters for a genuine cross-cluster (per-/64) overlay.
	nodeA, nodeC := nodes[0], nodes[1]
	if nodeA.Cluster == nodeC.Cluster {
		t.Skip("need the two endpoints in different clusters")
	}

	// 1. VPC + two NICs (each pinned to a node via spec.nodeName) + two halted anchor
	//    VMs (which stamp CompiledNIC.clusterName). Applied to central.
	require.NoError(t, applyCentral(ctx, cfg, overlayFixture(nodeA, nodeC)))
	// The compiler gates on a Ready VPC with a vni; mark VPC + both NICs Ready.
	patchVNIReady(t, ctx, cfg, "vpcs.net.ectobase.dev", "blue")
	patchVNIReady(t, ctx, cfg, "networkinterfaces.net.ectobase.dev", "nic-a")
	patchVNIReady(t, ctx, cfg, "networkinterfaces.net.ectobase.dev", "nic-c")

	// 2. Each compute cluster's CompiledNIC lands (broker sync) with the expected node.
	for _, tc := range []struct {
		node config.DerivedNode
		nic  string
	}{{nodeA, "nic-a"}, {nodeC, "nic-c"}} {
		tc := tc
		eventually(t, 2*time.Minute, 5*time.Second, func() error {
			nn, err := kubectl(ctx, cfg, tc.node.Cluster,
				"get", "compilednics.compiled.ectobase.dev", "default-"+tc.nic,
				"-o", "jsonpath={.spec.nodeName}")
			if err != nil {
				return fmt.Errorf("get CompiledNIC default-%s on %s: %w", tc.nic, tc.node.Cluster, err)
			}
			if strings.TrimSpace(nn) != nodeK8sName(tc.node) {
				return fmt.Errorf("CompiledNIC default-%s nodeName=%q, want %q (not synced/stamped yet)",
					tc.nic, strings.TrimSpace(nn), nodeK8sName(tc.node))
			}
			return nil
		})
	}

	// 3. Attach an endpoint on each node's dataplane; the agent announces its underlay
	//    /128 (from ListInterfaces) to the reflector and programs the peer's route.
	ulA := attachEndpoint(t, ctx, cfg, nodeA, "nic-a", overlayIPA, overlayMACA)
	ulC := attachEndpoint(t, ctx, cfg, nodeC, "nic-c", overlayIPC, overlayMACC)
	require.NotEmpty(t, ulA, "nic-a underlay /128")
	require.NotEmpty(t, ulC, "nic-c underlay /128")

	// 4. Cross-cluster overlay ping both ways (the arbiter). Bounded-retry to absorb
	//    the agent's firewall/route reconcile + reflector propagation.
	eventually(t, 90*time.Second, 5*time.Second, func() error {
		return endpointPing(ctx, cfg, nodeA, "nic-a", overlayIPC)
	})
	eventually(t, 90*time.Second, 5*time.Second, func() error {
		return endpointPing(ctx, cfg, nodeC, "nic-c", overlayIPA)
	})
}

// overlayFixture renders the central fixture: a VPC, two NICs (each pinned to its
// node via spec.nodeName — the placement a scheduled workload would set, required
// for the agent to program the NIC's firewall), and two halted anchor VMs whose
// interfaceRefs stamp each CompiledNIC's clusterName.
func overlayFixture(a, c config.DerivedNode) string {
	return fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: blue}
spec: {vni: %d, defaultPolicy: Allow}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: nic-a}
spec: {vpcRef: {name: blue}, ips: [%q], nodeName: %q}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: nic-c}
spec: {vpcRef: {name: blue}, ips: [%q], nodeName: %q}
---
apiVersion: compute.ectobase.dev/v1alpha1
kind: VirtualMachine
metadata: {name: vm-a}
spec: {clusterName: %q, interfaceRefs: [{name: nic-a}], runStrategy: Halted}
---
apiVersion: compute.ectobase.dev/v1alpha1
kind: VirtualMachine
metadata: {name: vm-c}
spec: {clusterName: %q, interfaceRefs: [{name: nic-c}], runStrategy: Halted}
`, overlayVNI, overlayIPA, nodeK8sName(a), overlayIPC, nodeK8sName(c), a.Cluster, c.Cluster)
}

// nodeK8sName is a node's Kubernetes name, matching the agent's --node-id and
// CompiledNIC.spec.nodeName. With the kind substrate the k8s Node name is the kind
// container name (<cluster>-control-plane), not <cluster>-<index>.
func nodeK8sName(n config.DerivedNode) string { return n.KindContainer() }

// applyCentral applies a multi-doc YAML to central via `kubectl apply -f -`.
func applyCentral(ctx context.Context, cfg *config.Config, yaml string) error {
	return exec.SudoStdin(ctx, yaml,
		"kubectl", "--kubeconfig", kubeconfigPath(cfg, "central"), "apply", "-f", "-")
}

// patchVNIReady marks a net.ectobase.dev resource's status Ready with the overlay
// vni via the fully-qualified plural (short-name discovery on the aggregated API
// flakes).
func patchVNIReady(t *testing.T, ctx context.Context, cfg *config.Config, resource, name string) {
	t.Helper()
	_, err := kubectl(ctx, cfg, "central", "patch", resource, name,
		"--subresource=status", "--type=merge",
		"-p", fmt.Sprintf(`{"status":{"vni":%d,"state":"Ready"}}`, overlayVNI))
	require.NoError(t, err, "patch %s/%s status", resource, name)
}

// flowplanePod returns the flowplane DaemonSet pod name on a cluster (excluding the
// cni-install pod). The Talos node has no shell, so netns setup runs through this
// pod (it has iproute2 and hostPath-mounts the node's /var/run/netns).
func flowplanePod(ctx context.Context, cfg *config.Config, cluster string) (string, error) {
	out, err := kubectl(ctx, cfg, cluster, "-n", "ectobase-system", "get", "pods", "-o", "name")
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(out, "\n") {
		p := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "pod/"))
		if strings.HasPrefix(p, "flowplane-") && !strings.Contains(p, "cni") {
			return p, nil
		}
	}
	return "", fmt.Errorf("no flowplane pod on %s: %q", cluster, out)
}

// attachEndpoint creates a netns on the node (via the flowplane pod), calls the real
// dataplane AttachInterface over grpcurl in the node's network namespace, addresses
// the endpoint netns dpservice-style (/32 + 169.254.0.1 gateway), and returns the
// allocated underlay /128. Idempotent: re-running against an existing endpoint keeps
// the same underlay.
func attachEndpoint(t *testing.T, ctx context.Context, cfg *config.Config, node config.DerivedNode, id, ip, mac string) string {
	t.Helper()
	container := nodeContainer(cfg, node)
	pod, err := flowplanePod(ctx, cfg, node.Cluster)
	require.NoError(t, err)

	// Idempotent: if the endpoint is already attached (a prior run, or the IFACE_META
	// restart journal), reuse its underlay — AttachInterface is not re-entrant per id.
	if out, err := dataplaneGRPC(t, ctx, container, "ListInterfaces", ""); err == nil {
		if ul := underlayForID(out, id); ul != "" {
			return ul
		}
	}

	// Create the endpoint netns (best-effort: already-exists is fine).
	_, _ = kubectl(ctx, cfg, node.Cluster, "-n", "ectobase-system", "exec", pod, "--",
		"ip", "netns", "add", id)

	req := fmt.Sprintf(`{"interface_id":%q,"netns_path":"/var/run/netns/%s","vni":%d,"mac":%q,"requested_ips":[%q]}`,
		id, id, overlayVNI, mac, ip)
	out, err := dataplaneGRPC(t, ctx, container, "AttachInterface", req)
	require.NoError(t, err, "AttachInterface %s on %s: %s", id, node.Cluster, out)
	underlay := firstUnderlay(out)
	require.NotEmpty(t, underlay, "no underlay in AttachInterface response for %s: %s", id, out)

	// Address the endpoint netns (dpservice-style: overlay /32 + on-link gateway
	// 169.254.0.1 + default via it). Each step is best-effort (idempotent re-runs).
	sh := strings.Join([]string{
		fmt.Sprintf("ip netns exec %s ip addr add %s/32 dev %s", id, ip, id),
		fmt.Sprintf("ip netns exec %s ip link set %s up", id, id),
		fmt.Sprintf("ip netns exec %s ip route add 169.254.0.1/32 dev %s", id, id),
		fmt.Sprintf("ip netns exec %s ip route add default via 169.254.0.1", id),
		"true",
	}, " 2>/dev/null; ")
	_, _ = kubectl(ctx, cfg, node.Cluster, "-n", "ectobase-system", "exec", pod, "--", "sh", "-c", sh)
	return underlay
}

// dataplaneGRPC invokes a DataplaneNode method over grpcurl in the node's network
// namespace (via `docker run --network container:<node>`), mounting the repo's proto
// tree. `data` is the request JSON ("" for no-arg methods like ListInterfaces).
func dataplaneGRPC(t *testing.T, ctx context.Context, container, method, data string) (string, error) {
	t.Helper()
	args := []string{"docker", "run", "--rm", "--network", "container:" + container,
		"-v", repoRoot(t) + "/api/proto:/proto:ro",
		"fullstorydev/grpcurl:latest", "-plaintext",
		"-import-path", "/proto/dataplane/v1", "-proto", "dataplane.proto", "-max-time", "15"}
	if data != "" {
		args = append(args, "-d", data)
	}
	args = append(args, dataplaneAddr, "dataplane.v1.DataplaneNode/"+method)
	out, err := exec.SudoOutput(ctx, args...)
	return string(out), err
}

// underlayForID returns the underlay /128 of interface `id` in a ListInterfaces
// response, or "" if absent.
func underlayForID(listOut, id string) string {
	var resp struct {
		Interfaces []struct {
			InterfaceID   string `json:"interfaceId"`
			UnderlayRoute string `json:"underlayRoute"`
		} `json:"interfaces"`
	}
	if err := json.Unmarshal([]byte(listOut), &resp); err != nil {
		return ""
	}
	for _, i := range resp.Interfaces {
		if i.InterfaceID == id {
			return i.UnderlayRoute
		}
	}
	return ""
}

// firstUnderlay extracts the first fd00:cafe:… underlay token from a grpcurl
// AttachInterface response (the only overlay-underlay address in it; the overlay IP
// is v4 and the gateway is 169.254.0.1).
func firstUnderlay(s string) string {
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '"' || r == ' ' || r == '\n' || r == '\t' || r == ',' || r == '{' || r == '}'
	}) {
		if strings.HasPrefix(f, "fd00:cafe:") {
			return f
		}
	}
	return ""
}

// endpointPing pings dstIP from inside the endpoint netns on a node, via
// `nsenter --net=/proc/<nodePID>/root/run/netns/<id>` from the host (the endpoint
// netns is a child of the node container; the node itself has no ping).
func endpointPing(ctx context.Context, cfg *config.Config, node config.DerivedNode, id, dstIP string) error {
	pid, err := dockerPID(ctx, nodeContainer(cfg, node))
	if err != nil {
		return err
	}
	ns := fmt.Sprintf("/proc/%s/root/run/netns/%s", pid, id)
	out, err := exec.SudoOutput(ctx, "nsenter", "--net="+ns, "ping", "-c3", "-W2", dstIP)
	if err != nil {
		return fmt.Errorf("overlay ping %s from %s/%s: %w\n%s", dstIP, node.Cluster, id, err, out)
	}
	return nil
}

// repoRoot is the git repo root (<repo>/test/lab/lab.yaml -> three dirs up), for the
// grpcurl dataplane.proto mount.
func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(configPath())
	require.NoError(t, err)
	return filepath.Dir(filepath.Dir(filepath.Dir(abs)))
}
