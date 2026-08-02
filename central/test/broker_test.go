// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	"github.com/trevex/ectobase/central/apis/platform/install"
	"github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	"github.com/trevex/ectobase/central/internal/broker"
)

// TestBroker_Loopback is the Phase-2 integration gate: it runs the broker
// engine between TWO real in-process apiservers and asserts the full sync
// contract (bounded pull, update propagation, GC, partition-survive).
//
//   - CENTRAL   = the kit aggregated apiserver (serves CompiledWorkload with a
//     selectable spec.clusterName field), started via kitenvtest.
//   - DOWNSTREAM = a plain controller-runtime envtest apiserver with the
//     CompiledWorkload CRD installed from central/config/crd.
//
// The broker is driven directly via SyncOnce (no informer/WatchListClient) so
// the assertions are deterministic.
func TestBroker_Loopback(t *testing.T) {
	// The kit envtest harness builds the aggregated apiserver with `-mod mod`,
	// which conflicts with the repo's go.work workspace mode. Disable workspace
	// mode for the in-test build so the aggregated server compiles.
	t.Setenv("GOWORK", "off")

	scheme := runtime.NewScheme()
	install.Install(scheme)
	// APIService (apiregistration.k8s.io) must be registered so the kit envtest
	// harness can poll the aggregated APIService for readiness.
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiregistration scheme: %v", err)
	}

	// --- CENTRAL: kit aggregated apiserver. ---
	centralEnv, err := kitenvtest.NewEnvironment(
		"github.com/trevex/ectobase/central/cmd/apiserver",
		nil,
		[]string{filepath.Join(".", "fixtures")},
	)
	if err != nil {
		t.Fatalf("central NewEnvironment: %v", err)
	}
	if _, err := centralEnv.Start(scheme, os.Stderr); err != nil {
		t.Fatalf("central env.Start: %v", err)
	}
	// centralEnv is explicitly Stopped in assertion (d) to simulate a central
	// outage; guard the cleanup so a double-Stop is harmless.
	centralStopped := false
	t.Cleanup(func() {
		if centralStopped {
			return
		}
		if err := centralEnv.Stop(); err != nil {
			t.Errorf("central env.Stop: %v", err)
		}
	})
	if err := centralEnv.WaitUntilReadyWithTimeout(apiServiceTimeout); err != nil {
		t.Fatalf("central WaitUntilReadyWithTimeout: %v", err)
	}

	centralClient, err := client.New(centralEnv.GetRESTConfig(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("central client.New: %v", err)
	}

	// --- DOWNSTREAM: plain controller-runtime apiserver with the CRD. ---
	downEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{"../config/crd"},
		ErrorIfCRDPathMissing: true,
	}
	downCfg, err := downEnv.Start()
	if err != nil {
		t.Fatalf("downstream envtest.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := downEnv.Stop(); err != nil {
			t.Errorf("downstream env.Stop: %v", err)
		}
	})

	downstreamClient, err := client.New(downCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("downstream client.New: %v", err)
	}

	b := &broker.Broker{
		Central:     centralClient,
		Downstream:  downstreamClient,
		ClusterName: "c1",
	}

	ctx := kitenvtest.Context()

	// downList returns the current downstream CompiledWorkload names (sorted-agnostic).
	downNames := func() []string {
		t.Helper()
		list := &v1alpha1.CompiledWorkloadList{}
		if err := downstreamClient.List(ctx, list); err != nil {
			t.Fatalf("downstream List: %v", err)
		}
		names := make([]string, len(list.Items))
		for i := range list.Items {
			names[i] = list.Items[i].Name
		}
		return names
	}

	// ================================================================
	// (a) BOUNDED PULL: c2 must never cross into a c1-bound downstream.
	// ================================================================
	wlA := &v1alpha1.CompiledWorkload{
		ObjectMeta: metav1.ObjectMeta{Name: "wl-a"},
		Spec:       v1alpha1.CompiledWorkloadSpec{ClusterName: "c1", Payload: "x"},
	}
	if err := centralClient.Create(ctx, wlA); err != nil {
		t.Fatalf("central Create wl-a: %v", err)
	}
	wlB := &v1alpha1.CompiledWorkload{
		ObjectMeta: metav1.ObjectMeta{Name: "wl-b"},
		Spec:       v1alpha1.CompiledWorkloadSpec{ClusterName: "c2"},
	}
	if err := centralClient.Create(ctx, wlB); err != nil {
		t.Fatalf("central Create wl-b: %v", err)
	}

	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("(a) SyncOnce: %v", err)
	}
	names := downNames()
	if len(names) != 1 || names[0] != "wl-a" {
		t.Fatalf("(a) bounded pull: expected downstream=[wl-a], got %v", names)
	}
	got := &v1alpha1.CompiledWorkload{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Name: "wl-a"}, got); err != nil {
		t.Fatalf("(a) downstream Get wl-a: %v", err)
	}
	if got.Spec.Payload != "x" {
		t.Fatalf("(a) expected wl-a payload=x, got %q", got.Spec.Payload)
	}
	t.Log("(a) bounded pull: PASS (downstream=[wl-a], c2 excluded)")

	// ================================================================
	// (b) UPDATE: central wl-a payload x->x2 propagates downstream.
	// ================================================================
	cur := &v1alpha1.CompiledWorkload{}
	if err := centralClient.Get(ctx, client.ObjectKey{Name: "wl-a"}, cur); err != nil {
		t.Fatalf("(b) central Get wl-a: %v", err)
	}
	cur.Spec.Payload = "x2"
	if err := centralClient.Update(ctx, cur); err != nil {
		t.Fatalf("(b) central Update wl-a: %v", err)
	}

	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("(b) SyncOnce: %v", err)
	}
	got = &v1alpha1.CompiledWorkload{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Name: "wl-a"}, got); err != nil {
		t.Fatalf("(b) downstream Get wl-a: %v", err)
	}
	if got.Spec.Payload != "x2" {
		t.Fatalf("(b) update: expected downstream wl-a payload=x2, got %q", got.Spec.Payload)
	}
	t.Log("(b) update: PASS (downstream wl-a payload=x2)")

	// ================================================================
	// (c) GC: deleting central wl-a empties downstream.
	// ================================================================
	del := &v1alpha1.CompiledWorkload{ObjectMeta: metav1.ObjectMeta{Name: "wl-a"}}
	if err := centralClient.Delete(ctx, del); err != nil {
		t.Fatalf("(c) central Delete wl-a: %v", err)
	}

	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("(c) SyncOnce: %v", err)
	}
	if names := downNames(); len(names) != 0 {
		t.Fatalf("(c) gc: expected empty downstream, got %v", names)
	}
	t.Log("(c) gc: PASS (downstream empty)")

	// ================================================================
	// (d) PARTITION-SURVIVE: sync wl-c, stop central, downstream persists.
	// ================================================================
	wlC := &v1alpha1.CompiledWorkload{
		ObjectMeta: metav1.ObjectMeta{Name: "wl-c"},
		Spec:       v1alpha1.CompiledWorkloadSpec{ClusterName: "c1"},
	}
	if err := centralClient.Create(ctx, wlC); err != nil {
		t.Fatalf("(d) central Create wl-c: %v", err)
	}
	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("(d) SyncOnce: %v", err)
	}
	if names := downNames(); len(names) != 1 || names[0] != "wl-c" {
		t.Fatalf("(d) pre-partition: expected downstream=[wl-c], got %v", names)
	}

	// Simulate a central outage: stop the central apiserver entirely.
	if err := centralEnv.Stop(); err != nil {
		t.Fatalf("(d) central env.Stop: %v", err)
	}
	centralStopped = true

	// No SyncOnce here: prove the already-synced state persists without central.
	if names := downNames(); len(names) != 1 || names[0] != "wl-c" {
		t.Fatalf("(d) partition-survive: expected downstream=[wl-c] after central outage, got %v", names)
	}
	t.Log("(d) partition-survive: PASS (downstream=[wl-c] survives central outage)")
}
