//go:build live

package livetest

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/clab"
	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/exec"
)

const (
	// lbIntentVNI is this test's own VPC (distinct from overlayVNI/podVNI so it can run alongside
	// the rest of the suite).
	lbIntentVNI = 205
	// lbIntentVIP is a BRING-YOUR-OWN VIP inside fabric.PublicV4 (192.0.2.0/24, which both edges
	// advertise and the WAN routes back). Pinned rather than auto-allocated so it cannot collide
	// with TestLbDistributeSmokeV4's hardcoded 192.0.2.1 — the allocator's lowest-free would.
	lbIntentVIP     = "192.0.2.7"
	lbIntentNIC     = "lbi-nic"
	lbIntentIP      = "10.0.5.10"
	lbIntentMAC     = "52:54:00:00:05:10"
	lbIntentBody    = "hello-intent-lb"
	lbIntentTimeout = 4 * time.Minute
)

// TestLbFromIntentReachesTheWan is the North-South path driven by INTENT ALONE: apply a
// LoadBalancer on the dispatch and a WAN client reaches the VIP, with nobody calling the dataplane
// gRPC by hand anywhere in this test.
//
// This is what TestLbDistributeSmoke{,V4} could not cover. They hand-program AddLbVip +
// AddLbBackend on both edge sidecars over gRPC, precisely because nothing ran an agent on an edge;
// they remain the datapath tier, isolating Maglev/DSR from the control path above them.
//
// The backend is a real Pod, materialized from a Container — not a hand-attached guest — so the
// only dataplane gRPC in the whole flow is the CNI's own attach, exactly as in production.
//
// The chain under test, none of which existed end to end before:
//
//	LoadBalancer + LBPool          -> LBVIPReconciler assigns status.allocatedVIP
//	NetworkInterface (labelled)    -> compiler emits CompiledNIC.spec.lb (gated on Allocated)
//	broker                         -> syncs the CompiledNIC into the pool
//	BACKEND node's agent           -> desiredLB joins it to the node VTEP; announces an LB_VIP
//	                                  PublicPrefix carrying the VIP's service PORTS
//	reflector                      -> relays it to every session
//	EDGE agent (no apiserver)      -> applyPublic: AddLbVip(ports) then AddLbBackend
func TestLbFromIntentReachesTheWan(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("need at least one compute node")
	}
	backend := nodes[0]
	// The backend's VTEP: every interface on a node shares the node's one underlay address, which is
	// exactly what the LB_VIP record carries as owner_underlay and the edge stores as node_vtep.
	backendVTEP := backend.IdentityAddr
	wan := clab.ContainerName(cfg.Name, "wan")

	// 1. Intent on the dispatch: a VPC + Subnet, an LBPool covering the edge's public v4 prefix, a
	//    LoadBalancer pinned to our VIP and selecting by label, and the backend NIC carrying that
	//    label. No FirewallPolicy: the compiler materializes an explicit allow-all for every
	//    direction no policy governs, which is what a k8s default-allow lowers to.
	applyDispatch(t, ctx, cfg, lbIntentFixture(nodeK8sName(backend), backend.Cluster))
	patchLbIntentVPCReady(t, ctx, cfg)
	t.Cleanup(func() {
		for _, kind := range []string{
			"loadbalancer.net.ectobase.dev/lbi-lb", "lbpool.net.ectobase.dev/lbi-pool",
			"containers.compute.ectobase.dev/ctr-" + lbIntentNIC,
			"networkinterface.net.ectobase.dev/" + lbIntentNIC,
			"subnet.net.ectobase.dev/lbi-subnet", "vpc.net.ectobase.dev/lbi-vpc",
		} {
			_, _ = kubectl(ctx, cfg, "dispatch", "delete", kind, "--ignore-not-found", "--wait=false")
		}
	})

	// 2. The backend ENDPOINT: a real Pod, materialized from the Container above by the
	//    pod-materializer and attached to the overlay by flowplane-cni. Nothing in this test
	//    attaches it — that is the point. The backend is what makes the NIC an LB backend worth
	//    announcing: the agent decides a CompiledNIC is LOCAL by matching its (VNI, overlayIP)
	//    against the dataplane's attached interfaces.
	var pod string
	eventually(t, 3*time.Minute, 5*time.Second, func() error {
		p, err := podForContainer(ctx, cfg, backend.Cluster, "default-ctr-"+lbIntentNIC)
		if err != nil {
			return err
		}
		phase, err := kubectl(ctx, cfg, backend.Cluster, "get", "pod", p, "-o", "jsonpath={.status.phase}")
		if err != nil {
			return err
		}
		if strings.TrimSpace(phase) != "Running" {
			desc, _ := kubectl(ctx, cfg, backend.Cluster, "describe", "pod", p)
			return fmt.Errorf("backend pod %s phase=%q:\n%s", p, strings.TrimSpace(phase), tail(desc, 25))
		}
		pod = p
		return nil
	})
	// Serving on its OVERLAY address specifically: the Geneve-TLV DSR variant rewrites the inner
	// destination to the backend's own overlay IP, so a server bound only to loopback would never
	// see the request.
	eventually(t, 90*time.Second, 5*time.Second, func() error {
		out, err := kubectl(ctx, cfg, backend.Cluster, "exec", pod, "--",
			"wget", "-q", "-O", "-", "-T", "3", "http://"+lbIntentIP+"/")
		if err != nil {
			return fmt.Errorf("backend not serving on its overlay IP yet: %w\n%s", err, out)
		}
		if !strings.Contains(out, lbIntentBody) {
			return fmt.Errorf("backend returned %q, want %q", strings.TrimSpace(out), lbIntentBody)
		}
		return nil
	})

	// 3. The allocator finalizes the VIP. Everything downstream is gated on this: the compiler
	//    refuses to emit LB membership for a LoadBalancer that is not Allocated, so a VIP that
	//    never lands means an edge that never programs anything.
	eventually(t, 2*time.Minute, 3*time.Second, func() error {
		vip, err := kubectl(ctx, cfg, "dispatch", "get", "loadbalancer.net.ectobase.dev", "lbi-lb",
			"-o", "jsonpath={.status.allocatedVIP}")
		if err != nil {
			return fmt.Errorf("get LoadBalancer status: %w", err)
		}
		if strings.TrimSpace(vip) != lbIntentVIP {
			state, _ := kubectl(ctx, cfg, "dispatch", "get", "loadbalancer.net.ectobase.dev", "lbi-lb",
				"-o", "jsonpath={.status.state}")
			return fmt.Errorf("allocatedVIP = %q (state %q), want %s",
				strings.TrimSpace(vip), strings.TrimSpace(state), lbIntentVIP)
		}
		return nil
	})

	// 4. The compiled LB membership reaches the POOL — the backend agent's only source for the VIP
	//    and, since the proto change, for its service ports too.
	eventually(t, 2*time.Minute, 5*time.Second, func() error {
		out, err := kubectl(ctx, cfg, backend.Cluster, "get", "compilednics.compiled.ectobase.dev",
			"default-"+lbIntentNIC, "-o", "jsonpath={.spec.lb[0].vip} {.spec.lb[0].ports[0].port}")
		if err != nil {
			return fmt.Errorf("get CompiledNIC on %s: %w", backend.Cluster, err)
		}
		if got := strings.TrimSpace(out); got != lbIntentVIP+" 80" {
			return fmt.Errorf("CompiledNIC spec.lb = %q, want %q", got, lbIntentVIP+" 80")
		}
		return nil
	})

	// 5. Both edges programmed the load balancer — from the route bus alone, with nobody in this
	//    test calling AddLbVip or AddLbBackend.
	//
	//    Asserted on the edges' own BPF maps BEFORE the curl below, because it localizes a failure:
	//    if this passes and the curl does not, the control path is fine and the datapath is at
	//    fault. It also names exactly what it expects (VIP, port, proto, backend), which a curl
	//    cannot.
	//
	//    BOTH edges, because the public prefixes are anycast: the WAN ECMPs to either, so a VIP
	//    programmed on only one of them is a coin-flip outage the curl would catch only sometimes.
	for _, edge := range []string{"edge1", "edge2"} {
		edge := edge
		eventually(t, 2*time.Minute, 5*time.Second, func() error {
			return edgeHasLb(ctx, cfg, edge, lbIntentVIP, 80, 6, backendVTEP, lbIntentIP, lbIntentVNI)
		})
	}

	// 6. THE POINT. A WAN client curls the VIP and gets the backend's response. Nothing in this
	//    test called AddLbVip, AddLbBackend, AddRoute or AttachInterface — the LoadBalancer object
	//    and a Container are the entire input.
	//
	//    The return hop is intent-driven too: the edge agents originate 0.0.0.0/0 into the public
	//    VNI, and the backend node imports it into this VPC precisely because its NIC is an LB
	//    member — so the DSR reply finds its way back with no hand-installed route either.
	eventually(t, lbIntentTimeout, 5*time.Second, func() error {
		out := curlFromWanV4(ctx, wan, lbIntentVIP)
		if !strings.Contains(out, lbIntentBody) {
			return fmt.Errorf("curl http://%s/ from the WAN did not return %q:\n%s\n%s",
				lbIntentVIP, lbIntentBody, out, lbIntentDiagnostics(ctx, cfg))
		}
		return nil
	})
}

// edgeHasLb checks that an edge's datapath carries the VIP as a load balancer whose Maglev table
// resolves to the given backend. It decodes the LB + MAGLEV maps rather than trusting a log line,
// so a half-programmed edge (VIP registered, no backends — which can only blackhole) fails loudly.
func edgeHasLb(ctx context.Context, cfg *config.Config, edge, vip string, port, proto int, backendVTEP, overlayIP string, vni int) error {
	pinDir := "/sys/fs/bpf/flowplane-" + edge

	lbDump, err := exec.SudoOutput(ctx, "sh", "-c",
		fmt.Sprintf("bpftool -j map dump pinned %s/LB 2>&1", pinDir))
	if err != nil {
		return fmt.Errorf("dump %s LB map: %w", edge, err)
	}
	// The LB key is (vni, ipv4, port, proto). vni is 0 — the reserved public/WAN VNI the edge
	// registers every VIP under (create_lb skips the UNDERLAY write there so it cannot clobber
	// attach_edge's LOCAL_DELIVER entry).
	wantKey := lbKeyBytes(vip, port, proto)
	if !strings.Contains(normalizeHex(string(lbDump)), wantKey) {
		return fmt.Errorf("%s has no LB entry for %s:%d/proto%d (want key %s) in:\n%s",
			edge, vip, port, proto, wantKey, tail(string(lbDump), 10))
	}

	mgDump, err := exec.SudoOutput(ctx, "sh", "-c",
		fmt.Sprintf("bpftool -j map dump pinned %s/MAGLEV 2>&1", pinDir))
	if err != nil {
		return fmt.Errorf("dump %s MAGLEV map: %w", edge, err)
	}
	// An LbBackend is node_vtep[16] ++ overlay_ip[16] ++ vni[4] ++ is_v6 ++ pad[3]; a v4 overlay
	// address is left-justified in the first four bytes of overlay_ip.
	wantBackend := hexBytes(ipBytes(backendVTEP)) + hexBytes(ipBytes(overlayIP)) + hexBytes(le32(uint32(vni)))
	if !strings.Contains(normalizeHex(string(mgDump)), wantBackend) {
		return fmt.Errorf("%s Maglev table has no backend %s (overlay %s, vni %d)", edge, backendVTEP, overlayIP, vni)
	}
	return nil
}

// TestEdgeAgentsRunWithoutAnApiserver is the regression this design exists to prevent: the agent's
// per-tick reconcile used to abort entirely when its CompiledNIC read failed, so an agent with no
// apiserver announced NOTHING — not even its EDGE_UNDERLAY identity or the egress defaults, neither
// of which needs any API data. An edge has no apiserver by construction, so that would have been
// its steady state.
//
// Asserted from the outside, on the running edges: both agents are up, each minted its own
// route-bus leaf from the fleet intermediate (so the API-less PKI path worked), and neither is
// logging reconcile failures.
func TestEdgeAgentsRunWithoutAnApiserver(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	for _, edge := range []string{"edge1", "edge2"} {
		container := clab.ContainerName(cfg.Name, "mesh-agent-"+edge)

		state, err := exec.SudoOutput(ctx, "docker", "inspect", "-f", "{{.State.Status}}", container)
		require.NoError(t, err, "inspect %s — is the edge agent in the topology?", container)
		require.Equal(t, "running", strings.TrimSpace(string(state)), "%s is not running", container)

		// The agent waits for its PKI material rather than crashing, so give the deploy time to have
		// written it and the agent time to have noticed.
		eventually(t, 90*time.Second, 5*time.Second, func() error {
			logs, lerr := containerLogs(ctx, container)
			if lerr != nil {
				return lerr
			}
			for _, want := range []string{
				// API-less mode was actually selected (--edge-loopback with no --kubeconfig).
				"edge mode:",
				// The fleet intermediate was found and a leaf signed from it locally.
				"minted edge route-bus leaf",
			} {
				if !strings.Contains(logs, want) {
					return fmt.Errorf("%s log missing %q:\n%s", container, want, tail(logs, 30))
				}
			}
			// The failure mode itself. An edge has no apiserver, so any CompiledNIC read would fail —
			// and that error used to abort the whole reconcile tick, taking the EDGE_UNDERLAY record
			// and the egress defaults with it even though neither needs API data.
			//
			// Only this exact string is asserted on. A generic "reconcile: " check would be flaky:
			// the agent can legitimately log one while the flowplane sidecar is still starting and
			// ListInterfaces is refused.
			if strings.Contains(logs, "list compilednics") {
				return fmt.Errorf("%s is reading CompiledNICs — it has no apiserver:\n%s", container, tail(logs, 30))
			}
			return nil
		})
	}
}

// lbIntentFixture renders the whole intent: VPC, Subnet, LBPool, LoadBalancer and the backend NIC.
// The LoadBalancer pins spec.vip (bring-your-own) and selects its backend by label — the two halves
// the compiler joins into CompiledNIC.spec.lb.
func lbIntentFixture(node, cluster string) string {
	return fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: lbi-vpc}
spec: {vni: %d, defaultPolicy: Allow}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: Subnet
metadata: {name: lbi-subnet}
spec: {vpcRef: {name: lbi-vpc}, v4Prefix: 10.0.5.0/24}
---
# The edge-owned public v4 prefix (fabric.PublicV4): both edges advertise it as our ASN and the WAN
# routes it back via either, so any VIP inside it is anycast across the edge fleet.
apiVersion: net.ectobase.dev/v1alpha1
kind: LBPool
metadata: {name: lbi-pool}
spec: {v4Prefix: 192.0.2.0/24}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: LoadBalancer
metadata: {name: lbi-lb}
spec:
  vip: %q
  poolRef: {name: lbi-pool}
  ports: [{port: 80, proto: TCP}]
  targetSelector: {matchLabels: {app: lbi-backend}}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata:
  name: %s
  labels: {app: lbi-backend}
spec: {vpcRef: {name: lbi-vpc}, ips: [%q], mac: %q}
---
# The Container owns the NIC and is the PLACEMENT AUTHORITY: it stamps CompiledNIC.clusterName (the
# pool the twin is emitted into) and nodeName. Without an owning workload no CompiledNIC is ever
# produced, so the NIC carries no placement of its own. busybox httpd serves the fixed body the WAN
# curl asserts on, bound to all interfaces so it is listening before the overlay iface is attached.
apiVersion: compute.ectobase.dev/v1alpha1
kind: Container
metadata: {name: ctr-%[3]s, namespace: default}
spec:
  clusterName: %[7]q
  nodeName: %[6]q
  interfaceRefs: [{name: %[3]s}]
  image: busybox:1.36
  command: ["sh", "-c", "mkdir -p /www && echo %[8]s > /www/index.html && exec httpd -f -p 80 -h /www"]
`, lbIntentVNI, lbIntentVIP, lbIntentNIC, lbIntentIP, lbIntentMAC, node, cluster, lbIntentBody)
}

func patchLbIntentVPCReady(t *testing.T, ctx context.Context, cfg *config.Config) {
	t.Helper()
	_, err := kubectl(ctx, cfg, "dispatch", "patch", "vpcs.net.ectobase.dev", "lbi-vpc",
		"--subresource=status", "--type=merge",
		"-p", fmt.Sprintf(`{"status":{"vni":%d,"state":"Ready"}}`, lbIntentVNI))
	require.NoError(t, err, "patch lbi-vpc status Ready")
}

// lbIntentDiagnostics collects what actually distinguishes the failure modes when the WAN curl does
// not come back: whether the edge agents are on the bus at all, and what they did with the LB_VIP
// records. Best-effort — it only ever appears inside a failure message.
func lbIntentDiagnostics(ctx context.Context, cfg *config.Config) string {
	var b strings.Builder
	for _, edge := range []string{"edge1", "edge2"} {
		container := clab.ContainerName(cfg.Name, "mesh-agent-"+edge)
		logs, err := containerLogs(ctx, container)
		if err != nil {
			fmt.Fprintf(&b, "\n--- %s: %v\n", container, err)
			continue
		}
		fmt.Fprintf(&b, "\n--- %s (last 20 lines) ---\n%s\n", container, tail(logs, 20))
	}
	return b.String()
}

// containerLogs returns a clab container's combined stdout+stderr.
//
// The 2>&1 is load-bearing and goes through a shell deliberately: `docker logs` replays the
// container's stderr on ITS stderr, and Go's standard logger writes to stderr — so an agent's whole
// log lands there. SudoOutput captures stdout only, which would silently return an empty string.
func containerLogs(ctx context.Context, container string) (string, error) {
	out, err := exec.SudoOutput(ctx, "sh", "-c",
		fmt.Sprintf("docker logs --tail 200 %s 2>&1", container))
	if err != nil {
		return "", fmt.Errorf("docker logs %s: %w", container, err)
	}
	return string(out), nil
}

// lbKeyBytes renders the LB map key for a v4 VIP: vni(0, LE u32) ++ ipv4 ++ port(LE u16) ++ proto
// ++ pad. Little-endian because that is how the kernel lays the struct out on x86.
func lbKeyBytes(vip string, port, proto int) string {
	return hexBytes(le32(0)) + hexBytes(ipBytes(vip)[:4]) +
		hexBytes([]byte{byte(port & 0xff), byte(port >> 8)}) + fmt.Sprintf("%02x", proto)
}

// ipBytes returns an address as bytes: 16 for v6, and for v4 the 4-byte form left-justified into a
// 16-byte buffer (the layout flowplane's LbBackend.overlay_ip uses).
func ipBytes(s string) []byte {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	out := make([]byte, 16)
	if v4 := ip.To4(); v4 != nil {
		copy(out, v4)
		return out
	}
	copy(out, ip.To16())
	return out
}

func le32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func hexBytes(b []byte) string {
	var sb strings.Builder
	for _, x := range b {
		fmt.Fprintf(&sb, "%02x", x)
	}
	return sb.String()
}

// normalizeHex flattens bpftool's JSON byte arrays (`["0x00","0xc0",...]`) into one contiguous hex
// string so a byte pattern can be matched with a substring search.
//
// It keeps ONLY the quoted 0x-tokens. Two traps make the obvious "strip everything that is not a
// hex digit" wrong: 'x' is not a hex digit, so "0x00" would collapse to three digits for one byte
// and skew every offset after it; and the surrounding JSON field names are themselves partly hex
// ("value" contributes "ae"), which would splice junk into the middle of the stream.
func normalizeHex(dump string) string {
	var sb strings.Builder
	for _, tok := range strings.Split(dump, `"`) {
		if !strings.HasPrefix(tok, "0x") {
			continue
		}
		b, err := strconv.ParseUint(tok[2:], 16, 8)
		if err != nil {
			continue
		}
		fmt.Fprintf(&sb, "%02x", b)
	}
	return sb.String()
}

// A note on the edge return hop, because it cost a long debugging session and the failure mode is
// deeply unobvious.
//
// The decapped reply surfaces on the edge's geneve device carrying the GUEST's next-hop MAC, not the
// device's, so the kernel's eth_type_trans() stamps it PACKET_OTHERHOST before any tc program runs
// and ip_rcv drops it before routing. `edge_local_deliver` rewrites the destination MAC, which looks
// like it should fix exactly this — but pkt_type is already decided by then, so the rewrite alone
// changes nothing. `Action::PassToStack` is what makes it work: it also issues
// bpf_skb_change_type(PACKET_HOST).
//
// Symptom to recognize: `tcpdump -nni any` in the edge netns shows the reply as `fp-geneve0 P`
// (PACKET_OTHERHOST) and nothing leaves on the WAN uplink. A healthy flow ends in `eth3 Out`.
