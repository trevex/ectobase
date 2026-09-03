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
images: {talos: img/talos, vyos: img/vyos, tayga: img/tayga, wan: img/wan, registry: registry:2, frr: img/frr}
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  nat64Prefix: 64:ff9b::/96
  clusters: [{name: dispatch, nodes: 1}, {name: k02, nodes: 2}]
`))
	if err != nil {
		t.Fatal(err)
	}
	view := fabric.Build(c)

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

	// Structural invariants (independent of the byte-for-byte golden). One k8s-kind
	// lifecycle node per cluster (dispatch:, k02:) plus the kind-created node
	// containers as ext-container link endpoints (<cluster>-control-plane / -worker).
	for _, name := range []string{
		"dispatch:", "k02:",
		"dispatch-control-plane:", "k02-control-plane:", "k02-worker:",
		"registry:", "wan:", "edge1:", "edge2:", "sw1:", "sw2:", "nat64-1:", "nat64-2:",
	} {
		if !strings.Contains(out, name) {
			t.Errorf("expected node %q in rendered topology", name)
		}
	}
	// The k8s-kind lifecycle nodes own no netns; links must attach to the
	// ext-container node containers, never the lifecycle node.
	for _, ep := range []string{`"dispatch-control-plane:eth1"`, `"k02-worker:eth2"`} {
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
