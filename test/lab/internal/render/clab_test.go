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
images: {talos: img/talos, tayga: img/tayga, wan: img/wan, registry: registry:2, frr: img/frr, vyos: img/vyos}
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
	} {
		if !strings.Contains(out, name) {
			t.Errorf("expected node %q in rendered topology", name)
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
