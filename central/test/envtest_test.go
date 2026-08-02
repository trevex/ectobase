// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	"github.com/trevex/ectobase/central/apis/platform/install"
	"github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

const apiServiceTimeout = 5 * time.Minute

func TestClusterPool_CRUDAndWatch(t *testing.T) {
	// The envtest harness builds the apiserver binary with `-mod mod`, which
	// conflicts with the repo's go.work workspace mode. Disable workspace mode
	// for the in-test build so the aggregated server compiles.
	t.Setenv("GOWORK", "off")

	scheme := runtime.NewScheme()
	install.Install(scheme)
	// APIService (apiregistration.k8s.io) must be registered so the envtest
	// harness can poll the aggregated APIService for readiness.
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

	// Build a watch-capable client against the aggregated server.
	c, err := client.NewWithWatch(env.GetRESTConfig(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("NewWithWatch: %v", err)
	}

	ctx := kitenvtest.Context()

	// --- Watch: start before create so we observe the ADDED event. ---
	watchList := &v1alpha1.ClusterPoolList{}
	w, err := c.Watch(ctx, watchList)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer w.Stop()

	// --- Create ---
	pool := &v1alpha1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-pool-",
		},
		Spec: v1alpha1.ClusterPoolSpec{
			Region: "eu",
		},
	}
	if err := c.Create(ctx, pool); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if pool.Name == "" {
		t.Fatalf("Create: expected generated name, got empty")
	}

	// --- Get ---
	got := &v1alpha1.ClusterPool{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pool), got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Spec.Region != "eu" {
		t.Fatalf("Get: expected Region=eu, got %q", got.Spec.Region)
	}

	// --- List ---
	list := &v1alpha1.ClusterPoolList{}
	if err := c.List(ctx, list); err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for i := range list.Items {
		if list.Items[i].Name == pool.Name {
			found = true
			if list.Items[i].Spec.Region != "eu" {
				t.Fatalf("List: expected Region=eu for %s, got %q", pool.Name, list.Items[i].Spec.Region)
			}
		}
	}
	if !found {
		t.Fatalf("List: created ClusterPool %q not found (%d items)", pool.Name, len(list.Items))
	}

	// --- Watch assertion: expect an event for our object. ---
	select {
	case ev, ok := <-w.ResultChan():
		if !ok {
			t.Fatalf("Watch: result channel closed unexpectedly")
		}
		obj, ok := ev.Object.(*v1alpha1.ClusterPool)
		if !ok {
			t.Fatalf("Watch: unexpected object type %T", ev.Object)
		}
		if obj.Name != pool.Name {
			t.Fatalf("Watch: expected event for %q, got %q", pool.Name, obj.Name)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("Watch: timed out waiting for event")
	}

	// --- Delete (cleanup / exercise delete path) ---
	if err := c.Delete(ctx, pool); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}
