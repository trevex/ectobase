// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// TestIPAllocationEnvtest runs the real IPPool + LoadBalancer allocators against a real
// in-process apiserver. The fake client cannot stand in for this: it does not apply the
// generated CRD schemas, so it would happily accept an IPAllocation missing a required field
// that a live apiserver rejects with a 422. What this proves that the unit tests cannot:
//
//   - the generated IPPool and IPAllocation CRDs install and serve;
//   - what claimAddress writes satisfies IPAllocation's required fields (address, poolRef,
//     consumerRef.kind, consumerRef.name) and its DNS-1123 object name;
//   - the used-set query — a label-selector list — works against a real API;
//   - the ownerReference carries the apiserver-assigned consumer UID, not a test fixture's.
//
// What it deliberately does NOT assert: that deleting the LoadBalancer reclaims the
// allocation. envtest runs no garbage collector, so an assertion either way would be
// meaningless. Reclamation is a live-lab check.
//
// Skips cleanly when KUBEBUILDER_ASSETS is unset (outside the nix devShell).
func TestIPAllocationEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "charts", "ectobase-pool", "crd-bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	defer func() { _ = env.Stop() }()

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&IPPoolReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader()}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	if err := (&LoadBalancerIPReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader()}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = mgr.Start(ctx) }()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("cache sync")
	}
	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}

	// Spec only: the real IPPoolReconciler drives Status Ready (envtest ignores any in-memory
	// Status set on create).
	mustCreate(ctx, t, direct, &netv1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "pub", Namespace: "default"},
		Spec:       netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V4Prefix: sp("198.51.100.0/24")},
	})
	mustCreate(ctx, t, direct, &netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "lb", Namespace: "default"},
		Spec: netv1.LoadBalancerSpec{
			PoolRef: netv1.LocalObjectReference{Name: "pub"},
			Ports:   []netv1.LoadBalancerPort{{Port: 80, Proto: "TCP"}},
		},
	})

	var lb netv1.LoadBalancer
	eventually(t, 40*time.Second, func() error {
		if err := direct.Get(ctx, client.ObjectKey{Namespace: "default", Name: "lb"}, &lb); err != nil {
			return err
		}
		if lb.Status.State != "Allocated" || lb.Status.AllocatedIP == "" {
			return fmt.Errorf("lb status = %+v", lb.Status)
		}
		return nil
	})
	// The downstream contract the compiler reads (compilednic.go). It must not notice that
	// the address now comes from an IPAllocation.
	if lb.Status.AllocatedIP != "198.51.100.1" {
		t.Fatalf("status.allocatedIP = %q want 198.51.100.1", lb.Status.AllocatedIP)
	}

	var alloc netv1.IPAllocation
	if err := direct.Get(ctx, client.ObjectKey{Namespace: "default", Name: "pub-198-51-100-1"}, &alloc); err != nil {
		t.Fatalf("no allocation at the deterministic name: %v", err)
	}
	if alloc.Labels[netv1.PoolLabel] != "pub" {
		t.Fatalf("pool label = %q want pub", alloc.Labels[netv1.PoolLabel])
	}
	if alloc.Spec.Address != "198.51.100.1" || alloc.Spec.PoolRef.Name != "pub" {
		t.Fatalf("spec = %+v", alloc.Spec)
	}
	if alloc.Spec.ConsumerRef.Kind != "LoadBalancer" || alloc.Spec.ConsumerRef.Name != "lb" {
		t.Fatalf("consumerRef = %+v", alloc.Spec.ConsumerRef)
	}
	ref := metav1.GetControllerOf(&alloc)
	if ref == nil {
		t.Fatal("no controller ownerReference; garbage collection would never reclaim this")
	}
	if ref.Kind != "LoadBalancer" || ref.Name != "lb" || ref.UID != lb.UID {
		t.Fatalf("ownerRef = %+v want LoadBalancer/lb/%s", ref, lb.UID)
	}
	if ref.Controller == nil || !*ref.Controller {
		t.Fatalf("ownerRef is not a controller ref: %+v", ref)
	}

	// A second, unpinned LoadBalancer on the same pool gets the NEXT address, which is only
	// true if the used-set label-list actually saw the first claim through the real API.
	mustCreate(ctx, t, direct, &netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "lb2", Namespace: "default"},
		Spec: netv1.LoadBalancerSpec{
			PoolRef: netv1.LocalObjectReference{Name: "pub"},
			Ports:   []netv1.LoadBalancerPort{{Port: 80, Proto: "TCP"}},
		},
	})
	eventually(t, 40*time.Second, func() error {
		var second netv1.LoadBalancer
		if err := direct.Get(ctx, client.ObjectKey{Namespace: "default", Name: "lb2"}, &second); err != nil {
			return err
		}
		if second.Status.AllocatedIP != "198.51.100.2" {
			return fmt.Errorf("lb2 allocatedIP = %q want 198.51.100.2", second.Status.AllocatedIP)
		}
		return nil
	})

	// The pool's derived counter follows the claims.
	eventually(t, 40*time.Second, func() error {
		var pool netv1.IPPool
		if err := direct.Get(ctx, client.ObjectKey{Namespace: "default", Name: "pub"}, &pool); err != nil {
			return err
		}
		if pool.Status.State != "Ready" || pool.Status.Total != 256 || pool.Status.Allocated != 2 {
			return fmt.Errorf("pool status = %+v", pool.Status)
		}
		return nil
	})
}
