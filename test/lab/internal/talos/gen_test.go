package talos

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserdata(t *testing.T) {
	// base64("hello") = aGVsbG8=
	if got := Userdata([]byte("hello")); got != "USERDATA=aGVsbG8=\n" {
		t.Fatalf("Userdata = %q", got)
	}
}

// clusterPatch/nodePatch/bgpPeer are the minimal per-doc patches Gen threads through
// talosctl — inlined (not the render templates) so this test stays self-contained.
const clusterPatch = `apiVersion: v1alpha1
kind: KubeProxyConfig
enabled: false
---
cluster:
  etcd:
    advertisedSubnets:
      - fd00:cafe:abcd::/64
`

const nodePatch = `apiVersion: v1alpha1
kind: KubeNodeConfig
nodeIP:
  validSubnets:
    - fd00:cafe:abcd::/64
---
machine:
  network:
    hostname: dispatch-1
    interfaces:
      - interface: dummy0
        dummy: true
        addresses:
          - fd00:cafe:abcd::1/128
`

const bgpPeer = `---
apiVersion: v1alpha1
kind: BGPPeerConfig
localASN: 65100
routerID: 10.0.100.1
routeSource: fd00:cafe:abcd::1
advertise:
  - dummy0
  - vip0
multipath: true
neighbors:
  - link: eth1
    peerASN: 65010
  - link: eth2
    peerASN: 65010
`

// TestGen runs the full talosctl pipeline (gen secrets/config, docstrip flannel,
// machineconfig patch, append BGPPeerConfig, base64 USERDATA env-file, mounts dirs) and
// asserts the deterministic outputs. It skips when talosctl is not on PATH.
func TestGen(t *testing.T) {
	if _, err := exec.LookPath("talosctl"); err != nil {
		t.Skip("talosctl not on PATH (devshell pins it); skipping Gen integration test")
	}
	dir := t.TempDir()
	genDir := filepath.Join(dir, "talos", "dispatch")
	mountsDir := filepath.Join(dir, "mounts")
	if err := os.MkdirAll(genDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := Gen(context.Background(), GenSpec{
		Dir:          genDir,
		SecretsPath:  filepath.Join(dir, "secrets", "dispatch.yaml"),
		MountsDir:    mountsDir,
		ClusterName:  "dispatch",
		Endpoint:     "https://[fd00:cafe:abcd:1::1]:6443",
		SANs:         []string{"fd00:cafe:abcd:1::1", "fd00:cafe:abcd::1"},
		ClusterPatch: []byte(clusterPatch),
		StripDocs:    []string{"HostnameConfig", "DiscoveryServiceConfig", "DiscoveryIdentityConfig", "KubeFlannelCNIConfig"},
		Nodes:        []NodeSpec{{Name: "dispatch-1", Patch: []byte(nodePatch), Peer: []byte(bgpPeer)}},
	}); err != nil {
		t.Fatalf("Gen: %v", err)
	}

	// The env-file must be USERDATA=<base64>\n and decode to the node machine config.
	env, err := os.ReadFile(filepath.Join(genDir, "dispatch-1.env"))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSuffix(string(env), "\n")
	b64, ok := strings.CutPrefix(line, "USERDATA=")
	if !ok {
		t.Fatalf("env-file not USERDATA= form: %q", line[:min(40, len(line))])
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("USERDATA not valid base64: %v", err)
	}
	mc := string(raw)
	if !strings.Contains(mc, "fd00:cafe:abcd::1/128") {
		t.Error("machine config missing the /128 node identity on dummy0")
	}
	if !strings.Contains(mc, "kind: BGPPeerConfig") {
		t.Error("machine config missing the appended BGPPeerConfig doc")
	}
	if strings.Contains(mc, "KubeFlannelCNIConfig") {
		t.Error("machine config still has the flannel CNI doc (should be stripped -> CNI none)")
	}

	// Per-node mounts dirs must exist (real mount points for Talos' MS_SHARED).
	for _, sub := range []string{"run", "var", "cni"} {
		if st, err := os.Stat(filepath.Join(mountsDir, "dispatch-1", sub)); err != nil || !st.IsDir() {
			t.Errorf("mounts dir dispatch-1/%s missing: %v", sub, err)
		}
	}
}
