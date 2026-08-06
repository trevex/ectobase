package docstrip

import (
	"strings"
	"testing"
)

func TestStripDropsKind(t *testing.T) {
	in := []byte(`apiVersion: v1alpha1
kind: KubeFlannelCNIConfig
foo: bar
---
apiVersion: v1alpha1
kind: KubeProxyConfig
enabled: false
`)
	out, err := Strip(in, "KubeFlannelCNIConfig")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "KubeFlannelCNIConfig") {
		t.Errorf("dropped kind still present:\n%s", s)
	}
	if !strings.Contains(s, "KubeProxyConfig") {
		t.Errorf("preserved kind missing:\n%s", s)
	}
	if !strings.Contains(s, "enabled: false") {
		t.Errorf("preserved doc body missing:\n%s", s)
	}
}
