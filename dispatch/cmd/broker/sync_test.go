// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
)

// startCompiledAPIServer starts an apiserver serving the compiled.ectobase.dev types. The broker
// reads them from the dispatch's aggregated apiserver and writes them to a pool's CRDs; to the
// broker both are just the same namespaced API, so the pool CRDs stand in for either side.
func startCompiledAPIServer(t *testing.T) *rest.Config {
	t.Helper()
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "charts", "ectobase-pool", "crd-bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	return cfg
}

// A broker that was down when its pool's last twin was deleted upstream must still prune it when it
// comes back. Nothing in the dispatch pool namespace means no watch event ever fires, so only a sync
// the broker runs of its own accord can see the stranded twin — which is exactly the state a
// Tier-2 failover leaves the source pool in.
func TestSync_StartupPrunesTwinsStrandedWhileDown(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}
	scheme := runtime.NewScheme()
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	dispatchCfg := startCompiledAPIServer(t)
	downstreamCfg := startCompiledAPIServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dispatch, err := client.New(dispatchCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	downstream, err := client.New(downstreamCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}

	// The pool namespace exists on the dispatch but is empty: its only VM has moved elsewhere.
	const clusterName = "c1"
	poolNS := validate.PoolNamespace(clusterName)
	if err := dispatch.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: poolNS}}); err != nil {
		t.Fatal(err)
	}
	// Downstream still holds the twin it mirrored before it went down.
	if err := downstream.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}}); err != nil {
		t.Fatal(err)
	}
	stranded := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "moved"}}
	if err := downstream.Create(ctx, stranded); err != nil {
		t.Fatal(err)
	}

	mgr, err := ctrl.NewManager(dispatchCfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Cache:   cache.Options{DefaultNamespaces: map[string]cache.Config{poolNS: {}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := setupSync(mgr, &brokerReconciler{
		dispatch: mgr.GetClient(), downstream: downstream, clusterName: clusterName,
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	deadline := time.Now().Add(30 * time.Second)
	for {
		err := downstream.Get(ctx, client.ObjectKeyFromObject(stranded), &compiledv1.CompiledVM{})
		if apierrors.IsNotFound(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the stranded CompiledVM survived the broker coming up (last get err=%v)", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
