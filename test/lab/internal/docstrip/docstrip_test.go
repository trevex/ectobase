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

func TestRemoveKeysDropsTaintsFromMatchingKind(t *testing.T) {
	in := []byte(`apiVersion: v1alpha1
kind: KubeNodeConfig
nodeIP:
  validSubnets:
    - fd00:cafe::/64
labels:
  node-role.kubernetes.io/control-plane: ""
taints:
  node-role.kubernetes.io/control-plane: NoSchedule
---
apiVersion: v1alpha1
kind: KubeletConfig
taints:
  keep-me: NoSchedule
`)
	out, err := RemoveKeys(in, "KubeNodeConfig", "taints")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "NoSchedule\n  node-role") || strings.Contains(s, "node-role.kubernetes.io/control-plane: NoSchedule") {
		t.Errorf("control-plane taint not removed:\n%s", s)
	}
	// Sibling keys in the same doc are preserved.
	if !strings.Contains(s, "validSubnets") || !strings.Contains(s, `node-role.kubernetes.io/control-plane: ""`) {
		t.Errorf("sibling keys (nodeIP/labels) were dropped:\n%s", s)
	}
	// Other kinds keep their taints untouched.
	if !strings.Contains(s, "keep-me: NoSchedule") {
		t.Errorf("taints on a different kind were removed:\n%s", s)
	}
}
