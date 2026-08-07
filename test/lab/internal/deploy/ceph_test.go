package deploy

import (
	"context"
	"strings"
	"testing"
)

// fakeRunner records every command it is asked to run so the argv composition can
// be asserted without a live cluster.
type fakeRunner struct {
	calls  [][]string // each entry is [name, args...]
	stdins []string   // stdin for RunStdin calls (parallel index-free capture)
}

func (f *fakeRunner) record(name string, args ...string) {
	f.calls = append(f.calls, append([]string{name}, args...))
}
func (f *fakeRunner) Run(_ context.Context, name string, args ...string) error {
	f.record(name, args...)
	return nil
}
func (f *fakeRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	f.record(name, args...)
	return nil, nil
}
func (f *fakeRunner) RunStdin(_ context.Context, stdin, name string, args ...string) error {
	f.record(name, args...)
	f.stdins = append(f.stdins, stdin)
	return nil
}
func (f *fakeRunner) Sudo(_ context.Context, args ...string) error {
	f.record("sudo", args...)
	return nil
}
func (f *fakeRunner) SudoOutput(_ context.Context, args ...string) ([]byte, error) {
	f.record("sudo", args...)
	return nil, nil
}

// findCall returns the first recorded call whose argv contains all of subseq (in
// order), or nil.
func (f *fakeRunner) findCall(subseq ...string) []string {
	for _, c := range f.calls {
		if containsSubseq(c, subseq) {
			return c
		}
	}
	return nil
}

func containsSubseq(hay, needle []string) bool {
	i := 0
	for _, h := range hay {
		if i < len(needle) && h == needle[i] {
			i++
		}
	}
	return i == len(needle)
}

var testParams = CephParams{
	FSID: "abcd-1234",
	Mon:  "[fd00:cafe:635::1]:3300",
	Pool: "replicapool",
	Key:  "AQBkey==",
}

func TestCephCSIValuesRender(t *testing.T) {
	got := cephCSIValues(testParams)
	for _, want := range []string{
		`clusterID: "abcd-1234"`,
		`- "[fd00:cafe:635::1]:3300"`,
		"replicaCount: 1",
		"name: csi-rbd-secret",
		`userID: "rbd"`,
		`userKey: "AQBkey=="`,
		"name: ceph-rbd",
		`pool: "replicapool"`,
		`imageFeatures: "layering"`,
		`mapOptions: "ms_mode=prefer-crc"`,
		"fstype: ext4",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("ceph-csi values missing %q:\n%s", want, got)
		}
	}
	// clusterID must appear in both csiConfig and storageClass.
	if n := strings.Count(got, `clusterID: "abcd-1234"`); n != 2 {
		t.Fatalf("expected clusterID twice (csiConfig + storageClass), got %d:\n%s", n, got)
	}
}

func TestCephCSIValuesDefaultPool(t *testing.T) {
	p := testParams
	p.Pool = ""
	if got := cephCSIValues(p); !strings.Contains(got, `pool: "replicapool"`) {
		t.Fatalf("empty pool should default to replicapool:\n%s", got)
	}
}

func TestCephCSIHelmArgs(t *testing.T) {
	args := cephCSIHelmArgs("/kc/central.kubeconfig", "/values.yaml")
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"upgrade --install ceph-csi-rbd ceph-csi/ceph-csi-rbd",
		"--kubeconfig /kc/central.kubeconfig",
		"--version 3.11.0",
		"--namespace ceph-csi --create-namespace",
		"-f /values.yaml",
		"--wait --timeout 5m",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("helm args missing %q:\n%s", want, joined)
		}
	}
}

// TestCephCSIArgvComposition drives CephCSI through the fake runner and asserts the
// helm install argv + PSA-privileged namespace pre-create.
func TestCephCSIArgvComposition(t *testing.T) {
	f := &fakeRunner{}
	dir := t.TempDir()
	if err := CephCSI(context.Background(), f, "/kc/k02.kubeconfig", "k02", dir, testParams); err != nil {
		t.Fatalf("CephCSI: %v", err)
	}
	// helm repo add/update (best-effort) then the install.
	if f.findCall("helm", "upgrade", "--install", "ceph-csi-rbd") == nil {
		t.Fatalf("no helm install call:\n%v", f.calls)
	}
	if c := f.findCall("helm", "upgrade", "--install", "ceph-csi-rbd"); !containsSubseq(c, []string{"--version", "3.11.0"}) {
		t.Fatalf("install missing version pin:\n%v", c)
	}
	// The ceph-csi namespace is pre-created PSA-privileged via kubectl apply -f -.
	foundNS := false
	for _, s := range f.stdins {
		if strings.Contains(s, "name: ceph-csi") && strings.Contains(s, "pod-security.kubernetes.io/enforce: privileged") {
			foundNS = true
		}
	}
	if !foundNS {
		t.Fatalf("ceph-csi namespace not pre-created PSA-privileged; stdins:\n%v", f.stdins)
	}
	// Values file was written into the values dir.
	if c := f.findCall("helm", "upgrade", "--install", "ceph-csi-rbd"); !containsSubseq(c, []string{"-f", dir + "/csi-values-k02.yaml"}) {
		t.Fatalf("install did not reference the rendered values file:\n%v", c)
	}
}

func TestCSIAddonsReleaseURL(t *testing.T) {
	got := csiAddonsReleaseURL("v0.12.0", "crds.yaml")
	want := "https://github.com/csi-addons/kubernetes-csi-addons/releases/download/v0.12.0/crds.yaml"
	if got != want {
		t.Fatalf("release URL = %q, want %q", got, want)
	}
}

func TestCSIAddonsSidecarPatch(t *testing.T) {
	patch := csiAddonsSidecarPatch("v0.12.0")
	for _, want := range []string{
		`"name":"csi-addons"`,
		`"image":"quay.io/csiaddons/k8s-sidecar:v0.12.0"`,
		`"containerPort":9070`,
		`--controller-port=9070`,
		`"value":"unix:///csi/csi-addons.sock"`,
		`"name":"socket-dir","mountPath":"/csi"`,
		`spec.nodeName`,
	} {
		if !strings.Contains(patch, want) {
			t.Fatalf("sidecar patch missing %q:\n%s", want, patch)
		}
	}
}

func TestCSIAddonsSidecarRBAC(t *testing.T) {
	rbac := csiAddonsSidecarRBAC("ceph-csi-rbd-provisioner", "ceph-csi")
	for _, want := range []string{
		"csiaddonsnodes",
		"system:auth-delegator",
		"name: ceph-csi-rbd-provisioner, namespace: ceph-csi",
		"replicasets",
		"deployments",
	} {
		if !strings.Contains(rbac, want) {
			t.Fatalf("sidecar rbac missing %q:\n%s", want, rbac)
		}
	}
}

// TestCSIAddonsArgvOrder drives CSIAddons through the fake runner and asserts the
// crds->ns->rbac->controller apply order + the sidecar patch/rollout when the
// provisioner is present.
func TestCSIAddonsArgvOrder(t *testing.T) {
	f := &fakeRunner{}
	if err := CSIAddons(context.Background(), f, "/kc/central.kubeconfig", ""); err != nil {
		t.Fatalf("CSIAddons: %v", err)
	}
	// The three release assets are applied in order.
	crds := "https://github.com/csi-addons/kubernetes-csi-addons/releases/download/v0.12.0/crds.yaml"
	rbac := "https://github.com/csi-addons/kubernetes-csi-addons/releases/download/v0.12.0/rbac.yaml"
	ctrl := "https://github.com/csi-addons/kubernetes-csi-addons/releases/download/v0.12.0/setup-controller.yaml"
	if f.findCall("kubectl", "apply", "-f", crds) == nil {
		t.Fatalf("crds not applied:\n%v", f.calls)
	}
	if f.findCall("kubectl", "apply", "-f", rbac) == nil {
		t.Fatalf("rbac not applied:\n%v", f.calls)
	}
	if f.findCall("kubectl", "apply", "-f", ctrl) == nil {
		t.Fatalf("controller not applied:\n%v", f.calls)
	}
	// csi-addons-system is pre-created privileged.
	foundNS := false
	for _, s := range f.stdins {
		if strings.Contains(s, "name: csi-addons-system") && strings.Contains(s, "privileged") {
			foundNS = true
		}
	}
	if !foundNS {
		t.Fatalf("csi-addons-system ns not created privileged:\n%v", f.stdins)
	}
	// The fake `get deploy` succeeds (returns nil), so the sidecar is wired.
	if f.findCall("kubectl", "patch", "deploy", CephCSIProv) == nil {
		t.Fatalf("provisioner not patched with sidecar:\n%v", f.calls)
	}
}

func TestCephEnvRender(t *testing.T) {
	got := cephEnv(testParams)
	want := "CEPH_FSID=abcd-1234\nCEPH_MON=[fd00:cafe:635::1]:3300\nCEPH_POOL=replicapool\nCEPH_RBD_KEY=AQBkey==\n"
	if got != want {
		t.Fatalf("ceph.env = %q, want %q", got, want)
	}
}

func TestCephOSDUp(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{"1 osds: 1 up (since 3m), 1 in (since 3m)", true},
		{"3 osds: 3 up (since 1h), 3 in", true},
		{"1 osds: 0 up (since 5s), 0 in", false},
		{"", false},
	}
	for _, c := range cases {
		if got := cephOSDUp([]byte(c.out)); got != c.want {
			t.Fatalf("cephOSDUp(%q) = %v, want %v", c.out, got, c.want)
		}
	}
}
