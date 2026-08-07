package render

import (
	"os"
	"strings"
	"testing"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

// kindFixture mirrors the base clab fixture (central:1, k02:2) but declares the
// kindNode image the kind-cluster template renders into each node.
const kindFixture = `
name: ectobase
images: {talos: img/talos, kindNode: ghcr.io/trevex/ectobase/kind-node-fabric:dev, vyos: img/vyos, tayga: img/tayga, wan: img/wan, registry: registry:2}
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  nat64Prefix: 64:ff9b::/96
  clusters: [{name: central, nodes: 1}, {name: k02, nodes: 2}]
`

// TestKindClabNodes asserts the cluster-node block renders as a k8s-kind node
// pointing at the per-cluster kind Cluster config under kind/.
func TestKindClabNodes(t *testing.T) {
	c, err := config.LoadBytes([]byte(kindFixture))
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

	for _, want := range []string{
		"kind: k8s-kind",
		"startup-config: kind/central-kind.yaml",
		"startup-config: kind/k02-kind.yaml",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in rendered clab topology", want)
		}
	}
	// The old Talos cluster-node wiring must be gone.
	if strings.Contains(out, "talos/central-1.env") {
		t.Errorf("clab topology still references the removed Talos env-file bind")
	}
}

// TestKindClusterGolden renders one cluster's kind Cluster config (control-plane
// only for the default single-node cluster) and asserts the load-bearing
// networking, image, extraMounts, and registry-mirror lines.
func TestKindClusterGolden(t *testing.T) {
	c, err := config.LoadBytes([]byte(kindFixture))
	if err != nil {
		t.Fatal(err)
	}
	view := fabric.Build(c)

	b, err := os.ReadFile("../../templates/k8s/kind-cluster.yaml.tmpl")
	if err != nil {
		t.Fatal(err)
	}

	// Emulate genKindCluster's data for the central (single control-plane) cluster
	// with deterministic absolute paths so the golden stays stable across hosts.
	const base = "/build/ectobase/kind"
	data := struct {
		RegistryHost string
		Nodes        []struct{ Role, Image, PrefixPath, UplinksPath string }
	}{
		RegistryHost: view.RegistryHost(),
		Nodes: []struct{ Role, Image, PrefixPath, UplinksPath string }{{
			Role:        "control-plane",
			Image:       view.Images()["kindNode"],
			PrefixPath:  base + "/central-1.prefix",
			UplinksPath: base + "/central-uplinks",
		}},
	}
	out, err := String(string(b), data)
	if err != nil {
		t.Fatal(err)
	}

	const goldenPath = "testdata/golden/central-kind.yaml"
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

	for _, w := range []string{
		"ipFamily: ipv6",
		"disableDefaultCNI: true",
		"kubeProxyMode: none",
		"image: ghcr.io/trevex/ectobase/kind-node-fabric:dev",
		"containerPath: /etc/fabric/prefix",
		"containerPath: /etc/fabric/uplinks",
		`registry.mirrors."ghcr.io"`,
		view.RegistryHost(),
	} {
		if !strings.Contains(out, w) {
			t.Errorf("expected %q in rendered kind Cluster config", w)
		}
	}
}
