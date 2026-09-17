package render

import (
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

var update = flag.Bool("update", false, "update golden files")

func TestClabGolden(t *testing.T) {
	c, err := config.LoadBytes([]byte(`
name: ectobase
images: {talos: img/talos, tayga: img/tayga, wan: img/wan, registry: registry:2, frr: img/frr, vyos: img/vyos, flowplane: img/flowplane, mesh: img/mesh}
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  nat64Prefix: 64:ff9b::/96
  clusters: [{name: dispatch, nodes: 1}, {name: k02, nodes: 2}]
`))
	if err != nil {
		t.Fatal(err)
	}
	// Fixed modules dir so the golden stays stable across hosts (the real path is
	// host-dependent; ClabView keeps it off the pure View for exactly this reason).
	view := fabric.ClabView{View: fabric.Build(c), ModulesDir: "/lib/modules"}

	b, err := os.ReadFile("../../templates/fabric.clab.yml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	out, err := String(string(b), view)
	if err != nil {
		t.Fatal(err)
	}

	const goldenPath = "testdata/golden/fabric.clab.yml"
	if *update {
		if err := os.MkdirAll("testdata/golden", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if out != string(want) {
		t.Errorf("rendered output differs from golden %s (run with -update to regenerate)", goldenPath)
	}

	// Structural invariants (independent of the byte-for-byte golden). One container-mode
	// Talos node per cluster node, named <cluster>-<index>, carrying the fabric links.
	for _, name := range []string{
		"dispatch-1:", "k02-1:", "k02-2:",
		"registry:", "wan:", "edge1:", "edge2:", "sw1:", "sw2:", "nat64-1:", "nat64-2:",
		"flowplane-edge1:", "mesh-agent-edge1:", "mesh-agent-edge2:",
	} {
		if !strings.Contains(out, name) {
			t.Errorf("expected node %q in rendered topology", name)
		}
	}
	// B10: the N/S-LB edge sidecar shares edge1's netns (the real docker container
	// name, not the bare node name) and attaches wan_rx on the dual-stack WAN uplink.
	for _, want := range []string{
		// Both edges get a flowplane sidecar (anycast public prefixes; WAN ECMPs to either).
		"network-mode: container:clab-ectobase-edge1",
		"network-mode: container:clab-ectobase-edge2",
		"--local-underlay fd00:ffff::e1",
		"--local-underlay fd00:ffff::e2",
		"image: img/flowplane",
		"--role edge --uplink eth1 --wan-uplink eth3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in rendered topology (flowplane edge sidecars)", want)
		}
	}
	// Each WAN edge runs a mesh agent in its netns, in API-less edge mode: --edge-loopback with NO
	// --kubeconfig, minting its route-bus leaf from the fleet intermediate rather than cert-manager,
	// and sharing the flowplane sidecar's socket over the host-backed bind. Without this the edge
	// announces nothing and every LB_IP record on the bus is dropped fleet-wide.
	for _, want := range []string{
		"image: img/mesh",
		"agent --node-id edge1 --underlay fd00:ffff::e1",
		"agent --node-id edge2 --underlay fd00:ffff::e2",
		"--edge-loopback fd00:ffff::e1",
		"--edge-loopback fd00:ffff::e2",
		// The reflector is the dispatch cluster's fabric identity, reached over BGP.
		"--reflector [fd00:cafe:2e6b::1]:1338",
		"--routebus-intermediate /etc/routebus",
		"--dataplane unix:///run/flowplane/dataplane.sock",
		// Both halves of the socket rendezvous: the sidecar exports it, the agent consumes it.
		"- edge/edge1/run:/run/flowplane",
		"- edge/edge2/run:/run/flowplane",
		"- edge/pki:/etc/routebus:ro",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in rendered topology (WAN edge mesh agents)", want)
		}
	}
	// An edge has no apiserver by design; a --kubeconfig here would silently re-enable the
	// CompiledNIC reads that abort the whole reconcile tick when they fail.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "agent --node-id edge") && strings.Contains(line, "--kubeconfig") {
			t.Errorf("edge agent must run without a kubeconfig: %q", line)
		}
	}

	// The retired kind substrate must be gone: no k8s-kind lifecycle nodes, no
	// ext-container node containers.
	for _, gone := range []string{"kind: k8s-kind", "kind: ext-container", "dispatch-control-plane:"} {
		if strings.Contains(out, gone) {
			t.Errorf("rendered topology still references the retired kind substrate: %q", gone)
		}
	}
	// Each Talos node reads its USERDATA env-file and binds its per-node mounts + the
	// host kernel modules.
	for _, want := range []string{
		"image: img/talos",
		"PLATFORM: container",
		"env-files: [talos/dispatch/dispatch-1.env]",
		"env-files: [talos/k02/k02-2.env]",
		"- mounts/dispatch-1/run:/run",
		"- /lib/modules:/usr/lib/modules:ro",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in rendered topology", want)
		}
	}
	// Link endpoints attach to the Talos nodes directly.
	for _, ep := range []string{`"dispatch-1:eth1"`, `"k02-2:eth2"`} {
		if !strings.Contains(out, ep) {
			t.Errorf("expected link endpoint %s in rendered topology", ep)
		}
	}
	// Switch host-ports: PortSeq 1,2,3 → sw1:eth3, sw1:eth4, sw1:eth5.
	for _, port := range []string{"sw1:eth3", "sw1:eth4", "sw1:eth5"} {
		if !strings.Contains(out, port) {
			t.Errorf("expected switch host-port %q in rendered topology", port)
		}
	}
}
