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

	// Structural assertions (independent of the byte-for-byte golden). The kind
	// values use ipam.mode: kubernetes (kind allocates node podCIDRs), cni.exclusive
	// false (Multus/KubeVirt coexistence), and route-source masquerade (pod→fabric
	// /64 reachability). k8sServiceHost/Port are injected at install time (the kind
	// API IP), NOT in the values — so 7445/KubePrism must be ABSENT.
	if !strings.Contains(s, "mode: kubernetes") {
		t.Errorf("expected ipam.mode: kubernetes in rendered values")
	}
	// k8sServiceHost/Port are injected at install time, so they must NOT be set as
	// config lines here (a bare "k8sServiceHost:" / "k8sServicePort:" YAML key).
	if strings.Contains(s, "\nk8sServiceHost:") || strings.Contains(s, "\nk8sServicePort:") {
		t.Errorf("k8sServiceHost/Port must be injected at install, not set in the values")
	}
	if !strings.Contains(s, "cni:\n  exclusive: false") {
		t.Errorf("expected cni.exclusive: false (Multus coexistence)")
	}
	if !strings.Contains(s, "enableMasqueradeRouteSource: true") {
		t.Errorf("expected enableMasqueradeRouteSource: true")
	}
	if !strings.Contains(s, "kubeProxyReplacement: true") {
		t.Errorf("expected kubeProxyReplacement: true")
	}
	if !strings.Contains(s, "tunnelProtocol: vxlan") {
		t.Errorf("expected tunnelProtocol: vxlan")
	}
	if !strings.Contains(s, "ipv4:\n  enabled: false") {
		t.Errorf("expected ipv4 disabled block")
	}
}
