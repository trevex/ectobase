package render

import (
	"os"
	"strings"
	"testing"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
	"github.com/trevex/ectobase/test/lab/internal/talos"
)

func TestCiliumGolden(t *testing.T) {
	c, err := config.LoadBytes([]byte(`
name: ectobase
images: {talos: img/talos, vyos: img/vyos, tayga: img/tayga, wan: img/wan, registry: registry:2}
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  nat64Prefix: 64:ff9b::/96
  clusters: [{name: central, nodes: 1}, {name: k02, nodes: 2}]
`))
	if err != nil {
		t.Fatal(err)
	}
	v := fabric.Build(c)

	tmpl, err := os.ReadFile("../../templates/k8s/cilium-values.yaml.tmpl")
	if err != nil {
		t.Fatal(err)
	}

	ctx := talos.NewClusterCtx(v, "central")
	s, err := String(string(tmpl), ctx)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	const goldenPath = "testdata/golden/cilium-central.yaml"
	if *update {
		if err := os.MkdirAll("testdata/golden", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if s != string(want) {
		t.Errorf("rendered output differs from golden %s (run with -update to regenerate)", goldenPath)
	}

	// Structural assertions (independent of the byte-for-byte golden).
	if !strings.Contains(s, "clusterPoolIPv6PodCIDRList") {
		t.Errorf("expected clusterPoolIPv6PodCIDRList in rendered values")
	}
	if !strings.Contains(s, "fd00:244:") {
		t.Errorf("expected central pod subnet prefix fd00:244: in rendered values")
	}
	if !strings.Contains(s, "kubeProxyReplacement: true") {
		t.Errorf("expected kubeProxyReplacement: true")
	}
	if !strings.Contains(s, "k8sServicePort: 7445") {
		t.Errorf("expected k8sServicePort: 7445")
	}
	if !strings.Contains(s, "tunnelProtocol: vxlan") {
		t.Errorf("expected tunnelProtocol: vxlan")
	}
	if !strings.Contains(s, "ipv4:\n  enabled: false") {
		t.Errorf("expected ipv4 disabled block")
	}
}
