package deploy

import (
	"context"
	"strings"
	"testing"
)

func TestCSIClusterIDPatch(t *testing.T) {
	args := []string{"-reflector-admin=x", "-csi-cluster-id=", "-csi-secret-name=y"}
	i, patch, err := csiClusterIDPatch(args, "abc-123")
	if err != nil {
		t.Fatalf("csiClusterIDPatch: %v", err)
	}
	if i != 1 {
		t.Fatalf("index = %d, want 1", i)
	}
	for _, want := range []string{
		`"path":"/spec/template/spec/containers/0/args/1"`,
		`-csi-cluster-id=abc-123`,
		`"op":"replace"`,
	} {
		if !strings.Contains(patch, want) {
			t.Fatalf("patch missing %q:\n%s", want, patch)
		}
	}
}

func TestCSIClusterIDPatchMissing(t *testing.T) {
	args := []string{"-reflector-admin=x", "-csi-secret-name=y"}
	if _, _, err := csiClusterIDPatch(args, "abc-123"); err == nil {
		t.Fatalf("expected error when no -csi-cluster-id= arg present")
	}
}

func TestKubeVirtCRPatch(t *testing.T) {
	patch := kubevirtCRPatch()
	for _, want := range []string{
		`"useEmulation":true`,
		`"NetworkBindingPlugins"`,
		`"domainAttachmentType":"tap"`,
		`ectobase-system/flowplane`,
	} {
		if !strings.Contains(patch, want) {
			t.Fatalf("kubevirt CR patch missing %q:\n%s", want, patch)
		}
	}
}

func TestKubeVirtCDIURLs(t *testing.T) {
	for _, c := range []struct {
		got, want string
	}{
		{kubevirtOperatorURL(), "v1.5.0/kubevirt-operator.yaml"},
		{kubevirtCRURL(), "v1.5.0/kubevirt-cr.yaml"},
		{cdiOperatorURL(), "v1.61.0/cdi-operator.yaml"},
		{cdiCRURL(), "v1.61.0/cdi-cr.yaml"},
	} {
		if !strings.HasSuffix(c.got, c.want) {
			t.Fatalf("URL %q does not end with %q", c.got, c.want)
		}
	}
}

// TestKubeVirtCDIArgv drives KubeVirtCDI through the fake runner and asserts the
// apply/label/wait/patch argv for both KubeVirt and CDI.
func TestKubeVirtCDIArgv(t *testing.T) {
	f := &fakeRunner{}
	if err := KubeVirtCDI(context.Background(), f, "/kc/k02.kubeconfig"); err != nil {
		t.Fatalf("KubeVirtCDI: %v", err)
	}
	checks := [][]string{
		{"kubectl", "apply", "-f", kubevirtOperatorURL()},
		{"kubectl", "apply", "-f", kubevirtCRURL()},
		{"kubectl", "label", "namespace", "kubevirt", "pod-security.kubernetes.io/enforce=privileged", "--overwrite"},
		{"kubectl", "wait", "kv/kubevirt", "--for=condition=Available", "--timeout=10m"},
		{"kubectl", "patch", "kubevirt", "kubevirt", "--type=merge", "-p", kubevirtCRPatch()},
		{"kubectl", "apply", "-f", cdiOperatorURL()},
		{"kubectl", "apply", "-f", cdiCRURL()},
		{"kubectl", "label", "namespace", "cdi", "pod-security.kubernetes.io/enforce=privileged", "--overwrite"},
		{"kubectl", "wait", "cdi/cdi", "--for=condition=Available", "--timeout=10m"},
	}
	for _, want := range checks {
		if f.findCall(want...) == nil {
			t.Fatalf("missing call %v in:\n%v", want, f.calls)
		}
	}
}

// TestPatchHubCSIClusterID drives PatchHubCSIClusterID through a runner that
// returns a canned args array and asserts the JSON6902 patch it composes.
func TestPatchHubCSIClusterID(t *testing.T) {
	f := &csiArgsRunner{args: `["-reflector-admin=x","-csi-cluster-id=","-csi-secret-name=y"]`}
	if err := PatchHubCSIClusterID(context.Background(), f, "/kc/hub.kubeconfig", "fsid-9"); err != nil {
		t.Fatalf("PatchHubCSIClusterID: %v", err)
	}
	c := f.findCall("kubectl", "patch", "deploy", "hub-controller", "--type=json")
	if c == nil {
		t.Fatalf("no hub-controller patch call:\n%v", f.calls)
	}
	joined := strings.Join(c, " ")
	if !strings.Contains(joined, `-csi-cluster-id=fsid-9`) || !strings.Contains(joined, `/args/1`) {
		t.Fatalf("patch argv wrong:\n%s", joined)
	}
}

// csiArgsRunner is a fakeRunner whose Output returns a canned args JSON array (so the
// PatchHubCSIClusterID read path has something to parse).
type csiArgsRunner struct {
	fakeRunner
	args string
}

func (c *csiArgsRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	c.record(name, args...)
	return []byte(c.args), nil
}
