// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	compiledinstall "github.com/trevex/ectobase/api/compiled/install"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computeinstall "github.com/trevex/ectobase/api/compute/install"
	netinstall "github.com/trevex/ectobase/api/net/install"
	platforminstall "github.com/trevex/ectobase/api/platform/install"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// TestPerPoolRBAC_ScopesABroker proves, against the REAL aggregated apiserver, that a pool broker
// is bounded by RBAC alone — the guarantees that used to come from the ClusterRestriction
// admission plugin, plus the one it could never make.
//
// This is the whole point of the per-pool authorization work. Admission never runs on
// GET/LIST/WATCH, so a plugin could only ever police writes; cross-pool READS were prevented by
// nothing but the broker's own client-side field selector, which is a filter the caller chooses,
// not a boundary. Two scopes replace it: a namespaced RoleBinding for the pool's compiled objects
// (expressible only because the broker's lists are namespace-scoped — a cluster-wide LIST
// authorizes against an empty namespace no RoleBinding can match), and resourceNames for the
// cluster-scoped objects it owns.
//
// The rules below mirror what enrollment provisions per pool (clusterPoolsManifest in
// test/lab/internal/deploy/ectobase.go); if those drift apart, this test stops being evidence.
func TestPerPoolRBAC_ScopesABroker(t *testing.T) {
	t.Setenv("GOWORK", "off")

	const (
		ownPool     = "c1"
		foreignPool = "c2"
		ownNS       = "pool-c1"
		foreignNS   = "pool-c2"
		brokerUser  = "ectobase:cluster:c1"
	)

	scheme := runtime.NewScheme()
	platforminstall.Install(scheme)
	netinstall.Install(scheme)
	computeinstall.Install(scheme)
	compiledinstall.Install(scheme)
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("register client-go scheme: %v", err)
	}
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiregistration scheme: %v", err)
	}

	env, err := kitenvtest.NewEnvironment(
		"github.com/trevex/ectobase/dispatch/cmd/apiserver",
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

	admin, err := client.New(env.GetRESTConfig(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("admin client.New: %v", err)
	}
	ctx := kitenvtest.Context()

	// --- what enrollment provisions for one pool ---
	for _, ns := range []string{ownNS, foreignNS} {
		if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
			t.Fatalf("create namespace %s: %v", ns, err)
		}
	}
	if err := admin.Create(ctx, &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: ownNS, Name: "dispatch-broker"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"compiled.ectobase.dev"},
				Resources: []string{"compilednics", "compiledvms", "compiledvolumeattachments", "compiledcontainers"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"compiled.ectobase.dev"},
				Resources: []string{"compiledvms/status"},
				Verbs:     []string{"get", "update", "patch"},
			},
		},
	}); err != nil {
		t.Fatalf("create per-pool Role: %v", err)
	}
	if err := admin.Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: ownNS, Name: "dispatch-broker"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "dispatch-broker"},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: brokerUser}},
	}); err != nil {
		t.Fatalf("create per-pool RoleBinding: %v", err)
	}
	if err := admin.Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "dispatch-broker-pool-c1"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{"platform.ectobase.dev"},
				Resources:     []string{"clusterpools"},
				ResourceNames: []string{ownPool},
				Verbs:         []string{"get"},
			},
			{
				APIGroups:     []string{"platform.ectobase.dev"},
				Resources:     []string{"clusterpools/status"},
				ResourceNames: []string{ownPool},
				Verbs:         []string{"get", "update", "patch"},
			},
		},
	}); err != nil {
		t.Fatalf("create per-pool ClusterRole: %v", err)
	}
	if err := admin.Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "dispatch-broker-pool-c1"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "dispatch-broker-pool-c1"},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: brokerUser}},
	}); err != nil {
		t.Fatalf("create per-pool ClusterRoleBinding: %v", err)
	}

	// --- state in both pools, seeded by an unrestricted identity ---
	for _, p := range []string{ownPool, foreignPool} {
		if err := admin.Create(ctx, &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: p}}); err != nil {
			t.Fatalf("create pool %s: %v", p, err)
		}
	}
	for ns, name := range map[string]string{ownNS: "default-nic-a", foreignNS: "default-nic-b"} {
		if err := admin.Create(ctx, &compiledv1.CompiledNIC{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		}); err != nil {
			t.Fatalf("create CompiledNIC %s/%s: %v", ns, name, err)
		}
	}

	cfg := *env.GetRESTConfig()
	cfg.Impersonate = rest.ImpersonationConfig{UserName: brokerUser}
	broker, err := client.New(&cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("broker client.New: %v", err)
	}

	t.Run("ReadsOwnPoolsCompiledObjects", func(t *testing.T) {
		var list compiledv1.CompiledNICList
		if err := broker.List(ctx, &list, client.InNamespace(ownNS)); err != nil {
			t.Fatalf("broker must be able to list its own pool's CompiledNICs: %v", err)
		}
		if len(list.Items) != 1 || list.Items[0].Name != "default-nic-a" {
			t.Fatalf("own-pool list = %d items, want the one seeded", len(list.Items))
		}
	})

	t.Run("CannotReadAnotherPoolsCompiledObjects", func(t *testing.T) {
		// The gap admission could never close: this is a read, so no plugin ever saw it.
		var list compiledv1.CompiledNICList
		err := broker.List(ctx, &list, client.InNamespace(foreignNS))
		if err == nil {
			t.Fatalf("broker listed ANOTHER pool's CompiledNICs (%d items); cross-pool reads are not scoped", len(list.Items))
		}
		if !apierrors.IsForbidden(err) {
			t.Fatalf("want Forbidden listing a foreign pool, got: %v", err)
		}
	})

	t.Run("CannotListCompiledObjectsClusterWide", func(t *testing.T) {
		// A cluster-wide LIST carries no namespace, so a RoleBinding cannot authorize it. This is
		// exactly why the broker's cache had to become namespace-scoped first.
		var list compiledv1.CompiledNICList
		if err := broker.List(ctx, &list); err == nil {
			t.Fatalf("broker listed CompiledNICs cluster-wide (%d items)", len(list.Items))
		} else if !apierrors.IsForbidden(err) {
			t.Fatalf("want Forbidden on a cluster-wide list, got: %v", err)
		}
	})

	t.Run("CannotDeleteOrEditSpecInItsOwnPool", func(t *testing.T) {
		// The two guarantees the old admission plugin made about writes. The grant is read-only on
		// the objects plus one status subresource, so both are structurally impossible now.
		own := &compiledv1.CompiledNIC{ObjectMeta: metav1.ObjectMeta{Namespace: ownNS, Name: "default-nic-a"}}
		if err := broker.Delete(ctx, own); err == nil {
			t.Fatal("broker deleted a compiled object in its own pool")
		} else if !apierrors.IsForbidden(err) {
			t.Fatalf("want Forbidden on delete, got: %v", err)
		}

		var nic compiledv1.CompiledNIC
		if err := broker.Get(ctx, client.ObjectKey{Namespace: ownNS, Name: "default-nic-a"}, &nic); err != nil {
			t.Fatalf("broker get own CompiledNIC: %v", err)
		}
		nic.Spec.ClusterName = foreignPool // the old "may not set spec.clusterName" guard
		if err := broker.Update(ctx, &nic); err == nil {
			t.Fatal("broker rewrote a compiled object's spec (could re-home a workload)")
		} else if !apierrors.IsForbidden(err) {
			t.Fatalf("want Forbidden on spec update, got: %v", err)
		}
	})

	t.Run("OwnClusterPoolStatusOnly", func(t *testing.T) {
		var own platformv1.ClusterPool
		if err := broker.Get(ctx, client.ObjectKey{Name: ownPool}, &own); err != nil {
			t.Fatalf("broker get own pool: %v", err)
		}
		own.Status.Phase = clusterpoolPhaseReady
		if err := broker.Status().Update(ctx, &own); err != nil {
			t.Fatalf("broker must write its OWN pool's status: %v", err)
		}

		// resourceNames names exactly one object, so a foreign pool is not even readable.
		var foreign platformv1.ClusterPool
		if err := broker.Get(ctx, client.ObjectKey{Name: foreignPool}, &foreign); err == nil {
			t.Fatal("broker read ANOTHER pool's ClusterPool")
		} else if !apierrors.IsForbidden(err) {
			t.Fatalf("want Forbidden reading a foreign pool, got: %v", err)
		}
	})
}

// clusterpoolPhaseReady mirrors clusterpool.PhaseReady without importing the package (kept local
// to avoid an import solely for a string constant).
const clusterpoolPhaseReady = "Ready"
