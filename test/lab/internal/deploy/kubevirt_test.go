package deploy

import (
	"context"
	"strings"
	"testing"
)

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

// TestSetDispatchCSIClusterID asserts the fsid reaches the dispatch controller through HELM rather
// than a kubectl patch of the live Deployment.
//
// The distinction is the bug this replaced: patching container args claims them for the
// "kubectl-patch" field manager, so the next `helm upgrade` of the release fails with a field
// conflict and `lab deploy` stops working after `lab tier2 up`. Asserting the argv keeps it that way.
func TestSetDispatchCSIClusterID(t *testing.T) {
	f := &fakeRunner{}
	if err := SetDispatchCSIClusterID(context.Background(), f, "/kc/dispatch.kubeconfig", "/charts/ectobase-dispatch", "fsid-9"); err != nil {
		t.Fatalf("SetDispatchCSIClusterID: %v", err)
	}
	c := f.findCall("helm", "upgrade", "ectobase-dispatch")
	if c == nil {
		t.Fatalf("no dispatch helm upgrade:\n%v", f.calls)
	}
	joined := strings.Join(c, " ")
	for _, want := range []string{"--reuse-values", "ceph.clusterID=fsid-9", "--namespace system"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("helm argv missing %q:\n%s", want, joined)
		}
	}
	// It must NOT go back to patching the Deployment.
	if f.findCall("kubectl", "patch", "deploy", "dispatch-controller") != nil {
		t.Fatalf("still patching the Deployment; that is what broke `lab deploy`:\n%v", f.calls)
	}
}
