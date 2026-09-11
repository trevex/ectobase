// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	computeinstall "github.com/trevex/ectobase/api/compute/install"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netinstall "github.com/trevex/ectobase/api/net/install"
	platforminstall "github.com/trevex/ectobase/api/platform/install"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// TestClusterNameValidation_AggregatedAPIServer proves the pool-identifier constraint is enforced
// by the REAL aggregated apiserver, not just by the Validate methods in isolation.
//
// This distinction is the whole point: these types are served from Go structs with no structural
// schema, so +kubebuilder:validation markers never execute — a marker-based constraint would look
// correct in the source, pass every unit test, and silently admit garbage in production. Only the
// object's Validate method runs, and only if the strategy actually finds it. This test is what
// pins that wiring.
//
// It matters because a cluster name becomes the `pool-<name>` namespace holding that pool's
// compiled objects; an invalid one fails much later, at namespace creation, far from the edit
// that caused it.
func TestClusterNameValidation_AggregatedAPIServer(t *testing.T) {
	t.Setenv("GOWORK", "off")

	scheme := runtime.NewScheme()
	platforminstall.Install(scheme)
	netinstall.Install(scheme)
	computeinstall.Install(scheme)
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

	t.Run("ClusterPoolNameRejected", func(t *testing.T) {
		// Uppercase is a legal path segment, so generic object-name validation accepts it; only
		// our Validate makes it a DNS-1123 label.
		pool := &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "poolA"}}
		err := admin.Create(ctx, pool)
		if err == nil {
			_ = admin.Delete(ctx, pool)
			t.Fatal("aggregated apiserver accepted ClusterPool \"poolA\"; Validate is not wired")
		}
		if !strings.Contains(err.Error(), "metadata.name") {
			t.Fatalf("rejection did not name the offending field: %v", err)
		}
	})

	t.Run("ClusterPoolNameAccepted", func(t *testing.T) {
		pool := &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "pool-ok"}}
		if err := admin.Create(ctx, pool); err != nil {
			t.Fatalf("valid ClusterPool name rejected: %v", err)
		}
		t.Cleanup(func() { _ = admin.Delete(ctx, pool) })
	})

	t.Run("VirtualMachineClusterNameRejected", func(t *testing.T) {
		// A dot would split the derived namespace into something Kubernetes will not accept.
		vm := &computev1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: "vm-bad", Namespace: "default"}}
		vm.Spec.ClusterName = "pool.a"
		err := admin.Create(ctx, vm)
		if err == nil {
			_ = admin.Delete(ctx, vm)
			t.Fatal("aggregated apiserver accepted spec.clusterName \"pool.a\"")
		}
		if !strings.Contains(err.Error(), "clusterName") {
			t.Fatalf("rejection did not name the offending field: %v", err)
		}
	})

	t.Run("VirtualMachineClusterNameAccepted", func(t *testing.T) {
		vm := &computev1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: "vm-ok", Namespace: "default"}}
		vm.Spec.ClusterName = "pool-a"
		if err := admin.Create(ctx, vm); err != nil {
			t.Fatalf("valid spec.clusterName rejected: %v", err)
		}
		t.Cleanup(func() { _ = admin.Delete(ctx, vm) })
	})
}
