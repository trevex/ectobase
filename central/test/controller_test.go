// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	"github.com/trevex/ectobase/central/apis/platform/install"
	"github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	"github.com/trevex/ectobase/central/pkg/clusterpool"
)

// TestClusterPoolController_SetsPending runs the ClusterPool reconciler against
// the REAL aggregated apiserver (started via the same envtest harness as the
// CRUD test): a controller-runtime manager watches ClusterPool over the
// aggregated server, and a freshly created ClusterPool (empty status) must be
// driven to status.phase == "Pending" via a status-subresource update. This is
// the authoritative gate that the aggregated apiserver supports the
// controller-runtime informer/watch/status-patch path that Phase 2's
// scheduler/failover controllers depend on.
func TestClusterPoolController_SetsPending(t *testing.T) {
	// See envtest_test.go: the harness builds the apiserver with `-mod mod`,
	// which conflicts with the repo's go.work workspace mode.
	t.Setenv("GOWORK", "off")

	scheme := runtime.NewScheme()
	install.Install(scheme)
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
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

	// --- Manager + reconciler against the aggregated server. ---
	mgr, err := ctrl.NewManager(env.GetRESTConfig(), ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"}, // disable the metrics listener (port clash)
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := (&clusterpool.Reconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup reconciler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgrDone := make(chan error, 1)
	go func() { mgrDone <- mgr.Start(ctx) }()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("manager cache did not sync")
	}

	// A separate direct client for the test's own writes/reads.
	direct, err := client.New(env.GetRESTConfig(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("direct client: %v", err)
	}

	// --- Create a ClusterPool with empty status. ---
	pool := &v1alpha1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "ctrl-pool-"},
		Spec:       v1alpha1.ClusterPoolSpec{Region: "eu"},
	}
	if err := direct.Create(ctx, pool); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = direct.Delete(context.Background(), pool) })

	// --- Assert Eventually status.phase == "Pending". ---
	deadline := time.Now().Add(30 * time.Second)
	var lastPhase string
	for time.Now().Before(deadline) {
		got := &v1alpha1.ClusterPool{}
		if err := direct.Get(ctx, client.ObjectKeyFromObject(pool), got); err == nil {
			lastPhase = got.Status.Phase
			if lastPhase == "Pending" {
				cancel()
				select {
				case <-mgrDone:
				case <-time.After(10 * time.Second):
					t.Fatal("manager did not shut down")
				}
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("ClusterPool %q status.phase never became Pending (last=%q)", pool.Name, lastPhase)
}
