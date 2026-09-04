package render

import (
	"os"
	"strings"
	"testing"
)

// TestCiliumValuesGolden renders the container-mode Cilium values for one cluster's
// pod pool and asserts the load-bearing container-mode + KubePrism + IPv6 lines.
func TestCiliumValuesGolden(t *testing.T) {
	b, err := os.ReadFile("../../templates/k8s/cilium-values.yaml.tmpl")
	if err != nil {
		t.Fatal(err)
	}

	// Fixed pod pool so the golden stays stable (the real value is the per-cluster
	// fd00:244:<h>::/56 derived from the cluster-name hash).
	data := struct{ PodSubnet string }{PodSubnet: "fd00:244:dead::/56"}
	out, err := String(string(b), data)
	if err != nil {
		t.Fatal(err)
	}

	const goldenPath = "testdata/golden/cilium-values.yaml"
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
		"- fd00:244:dead::/56",           // per-cluster pod pool threaded through
		"clusterPoolIPv6MaskSize: 64",    // per-node /64 out of the /56 pool
		"kubeProxyReplacement: true",     // KubePrism kube-proxy replacement
		"k8sServiceHost: localhost",      // KubePrism host-local apiserver LB
		`k8sServicePort: "7445"`,         // KubePrism port (matches cluster-patch)
		"hostRoot: /sys/fs/cgroup",       // container-mode: mount the host cgroup
		"autoMount:\n    enabled: false", // container-mode: no agent auto-mount
		"SYS_ADMIN",                      // agent container-mode capability set
	} {
		if !strings.Contains(out, w) {
			t.Errorf("expected %q in rendered cilium values", w)
		}
	}
	// IPv6-only: the v4 stack must be disabled and v6 enabled.
	if !strings.Contains(out, "ipv4:\n  enabled: false") || !strings.Contains(out, "ipv6:\n  enabled: true") {
		t.Errorf("expected IPv6-only (ipv4 disabled, ipv6 enabled) in rendered cilium values")
	}
}
