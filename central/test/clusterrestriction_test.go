// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netinstall "github.com/trevex/ectobase/api/net/install"
	computeinstall "github.com/trevex/ectobase/api/compute/install"
	platforminstall "github.com/trevex/ectobase/api/platform/install"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// TestClusterRestriction_BrokerImpersonation proves the ClusterRestriction
// validating admission plugin end-to-end against the REAL kit aggregated
// apiserver, exercised by an IMPERSONATED broker identity
// (ectobase:cluster:c1). The four assertions:
//
//   - (allow) a broker may write its OWN ClusterPool's status;
//   - (deny)  a broker may NOT write ANOTHER pool's status;
//   - (deny)  a broker may NOT set spec.clusterName on any object — and the
//     forbidden message contains "spec.clusterName", proving it is OUR plugin
//     denying (not generic authz);
//   - (allow) an unimpersonated admin MAY set spec.clusterName.
//
// AUTHORIZATION: the main control plane (controller-runtime envtest) runs in
// RBAC mode and proxies aggregated-group requests to the central apiserver,
// which ALSO delegates authz back to the main control plane (SubjectAccessReview).
// The kit/extension apiserver exposes no --authorization-mode (only delegated
// authz options), so AlwaysAllow is unavailable. Instead we grant the broker
// identity ectobase:cluster:c1 a broad ClusterRole via RBAC so its requests pass
// BOTH authz layers and reach the ClusterRestriction admission plugin — the gate
// under test. (Impersonation itself is also RBAC-granted below.)
func TestClusterRestriction_BrokerImpersonation(t *testing.T) {
	t.Setenv("GOWORK", "off")

	const ns = "default"

	scheme := runtime.NewScheme()
	platforminstall.Install(scheme)
	netinstall.Install(scheme)
	computeinstall.Install(scheme)
	// rbac.authorization.k8s.io (via client-go scheme) is needed to create the
	// ClusterRole/ClusterRoleBinding that authorizes the impersonated broker.
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("register client-go scheme: %v", err)
	}
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiregistration scheme: %v", err)
	}

	env, err := kitenvtest.NewEnvironment(
		"github.com/trevex/ectobase/central/cmd/apiserver",
		nil,
		[]string{filepath.Join(".", "fixtures")},
	)
	if err != nil {
		t.Fatalf("NewEnvironment: %v", err)
	}

	if _, err := env.Start(scheme, os.Stderr); err != nil {
		t.Fatalf("env.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("env.Stop: %v", err)
		}
	})
	if err := env.WaitUntilReadyWithTimeout(apiServiceTimeout); err != nil {
		t.Fatalf("WaitUntilReadyWithTimeout: %v", err)
	}

	// Admin (unimpersonated) client.
	admin, err := client.New(env.GetRESTConfig(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("admin client.New: %v", err)
	}

	ctx := kitenvtest.Context()

	// Grant the broker identity broad access so its requests pass authz (both the
	// main control plane's RBAC and the aggregated apiserver's delegated authz) and
	// reach the ClusterRestriction admission plugin — the actual gate under test.
	if err := admin.Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "ectobase-broker-test"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"*"},
			Resources: []string{"*"},
			Verbs:     []string{"*"},
		}},
	}); err != nil {
		t.Fatalf("create broker ClusterRole: %v", err)
	}
	if err := admin.Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "ectobase-broker-test"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "ectobase-broker-test"},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: "ectobase:cluster:c1"}},
	}); err != nil {
		t.Fatalf("create broker ClusterRoleBinding: %v", err)
	}

	// Impersonating broker client for cluster c1.
	cfg := *env.GetRESTConfig()
	cfg.Impersonate = rest.ImpersonationConfig{UserName: "ectobase:cluster:c1"}
	brokerClient, err := client.New(&cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("broker client.New: %v", err)
	}

	// Admin seeds the two pools c1 (the broker's own) and c2 (foreign).
	if err := admin.Create(ctx, &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c1"}}); err != nil {
		t.Fatalf("admin create pool c1: %v", err)
	}
	if err := admin.Create(ctx, &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c2"}}); err != nil {
		t.Fatalf("admin create pool c2: %v", err)
	}

	// (allow) broker writes its OWN pool's status.
	own := &platformv1.ClusterPool{}
	if err := brokerClient.Get(ctx, client.ObjectKey{Name: "c1"}, own); err != nil {
		t.Fatalf("broker get c1: %v", err)
	}
	own.Status.Phase = clusterpoolPhaseReady
	if err := brokerClient.Status().Update(ctx, own); err != nil {
		t.Fatalf("(allow) broker status update of own pool c1 must succeed, got: %v", err)
	}
	t.Log("(allow own-pool status): PASS")

	// (deny) broker writes ANOTHER pool's status.
	foreign := &platformv1.ClusterPool{}
	if err := brokerClient.Get(ctx, client.ObjectKey{Name: "c2"}, foreign); err != nil {
		t.Fatalf("broker get c2: %v", err)
	}
	foreign.Status.Phase = clusterpoolPhaseReady
	err = brokerClient.Status().Update(ctx, foreign)
	if err == nil {
		t.Fatal("(deny cross-pool status): expected Forbidden updating c2, got nil")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("(deny cross-pool status): expected Forbidden, got %v", err)
	}
	t.Logf("(deny cross-pool status): PASS (%v)", err)

	// (deny) broker sets spec.clusterName — the message must name spec.clusterName,
	// proving it is OUR admission plugin (not generic authz) doing the denying. This
	// exercises the reflection-based Spec.ClusterName extraction, which works on the
	// INTERNAL (json-tagless) net type the apiserver hands to admission — the earlier
	// ToUnstructured+json-path approach failed open here (regression guard).
	vmBroker := &computev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm-broker"},
		Spec:       computev1.VirtualMachineSpec{ClusterName: "c1"},
	}
	err = brokerClient.Create(ctx, vmBroker)
	if err == nil {
		t.Fatal("(deny spec.clusterName): expected Forbidden creating VM with spec.clusterName, got nil")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("(deny spec.clusterName): expected Forbidden, got %v", err)
	}
	if got := err.Error(); !strings.Contains(got, "spec.clusterName") {
		t.Fatalf("(deny spec.clusterName): expected message to mention spec.clusterName (proving OUR plugin), got: %v", got)
	}
	t.Logf("(deny spec.clusterName): PASS (%v)", err)

	// (allow) admin sets spec.clusterName on a VM — unrestricted.
	vmAdmin := &computev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm-admin"},
		Spec:       computev1.VirtualMachineSpec{ClusterName: "c1"},
	}
	if err := admin.Create(ctx, vmAdmin); err != nil {
		t.Fatalf("(allow admin spec.clusterName): expected success, got: %v", err)
	}
	t.Log("(allow admin spec.clusterName): PASS")
}

// clusterpoolPhaseReady mirrors clusterpool.PhaseReady without importing the
// package (kept local to avoid an import solely for a string constant).
const clusterpoolPhaseReady = "Ready"
