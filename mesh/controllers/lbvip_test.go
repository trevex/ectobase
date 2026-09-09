// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func readyPool(name, v4 string) *netv1.LBPool {
	p := &netv1.LBPool{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}, Spec: netv1.LBPoolSpec{V4Prefix: sp(v4)}}
	p.Status.State = "Ready"
	return p
}

func lb(name, pool, vip string) *netv1.LoadBalancer {
	return &netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Generation: 1},
		Spec:       netv1.LoadBalancerSpec{PoolRef: netv1.LocalObjectReference{Name: pool}, VIP: vip},
	}
}

func TestLBPeersNeedingRetry(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = netv1.AddToScheme(scheme)
	// stuck peer on same pool, a Ready peer, and a different-pool stuck peer
	stuck := lb("stuck", "p", "")
	stuck.Status.State = "Exhausted"
	ready := lb("ready", "p", "")
	ready.Status.State = "Allocated"
	other := lb("other", "q", "")
	other.Status.State = "Exhausted"
	gone := lb("gone", "p", "")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(stuck, ready, other).Build()

	reqs := lbPeersNeedingRetry(context.Background(), cl, gone)
	if len(reqs) != 1 {
		t.Fatalf("got %d requests, want exactly 1 (stuck): %v", len(reqs), reqs)
	}
	if reqs[0].Name != "stuck" {
		t.Fatalf("got %q, want stuck (not ready/Allocated, not other/different-pool)", reqs[0].Name)
	}
}

func TestLBVIPAllocateAndAdopt(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = netv1.AddToScheme(scheme)
	pool := readyPool("p", "198.51.100.0/24")
	byo := lb("byo", "p", "198.51.100.10")
	auto := lb("auto", "p", "")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, byo, auto).WithStatusSubresource(&netv1.LoadBalancer{}).Build()
	r := &LBVIPReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	_ = r.Sync(ctx, byo)
	_ = r.Sync(ctx, auto)

	get := func(n string) netv1.LoadBalancer {
		var x netv1.LoadBalancer
		_ = cl.Get(ctx, keyOf(&netv1.LoadBalancer{ObjectMeta: metav1.ObjectMeta{Name: n, Namespace: "default"}}), &x)
		return x
	}
	if g := get("byo"); g.Status.State != "Allocated" || g.Status.AllocatedVIP != "198.51.100.10" {
		t.Fatalf("byo = %+v", g.Status)
	}
	if g := get("auto"); g.Status.State != "Allocated" || g.Status.AllocatedVIP != "198.51.100.1" {
		t.Fatalf("auto = %+v want .1", g.Status)
	}
}

func TestLBVIPStickyAcrossGenerationBump(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = netv1.AddToScheme(scheme)
	pool := readyPool("p", "198.51.100.0/24")
	a := lb("a", "p", "") // auto
	b := lb("b", "p", "") // auto
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, a, b).WithStatusSubresource(&netv1.LoadBalancer{}).Build()
	r := &LBVIPReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	_ = r.Sync(ctx, a) // a -> .1
	_ = r.Sync(ctx, b) // b -> .2

	// free the lower address by deleting a
	var ga netv1.LoadBalancer
	_ = cl.Get(ctx, keyOf(a), &ga)
	if err := cl.Delete(ctx, &ga); err != nil {
		t.Fatal(err)
	}

	var gb netv1.LoadBalancer
	_ = cl.Get(ctx, keyOf(b), &gb)
	if gb.Status.AllocatedVIP != "198.51.100.2" {
		t.Fatalf("precondition: b should have .2, got %v", gb.Status.AllocatedVIP)
	}
	gb.Generation = 2
	if err := cl.Update(ctx, &gb); err != nil {
		t.Fatal(err)
	}
	_ = cl.Get(ctx, keyOf(b), &gb)
	gb.Generation = 2
	if err := r.Sync(ctx, &gb); err != nil {
		t.Fatal(err)
	}
	var got netv1.LoadBalancer
	_ = cl.Get(ctx, keyOf(b), &got)
	if got.Status.AllocatedVIP != "198.51.100.2" {
		t.Fatalf("b VIP renumbered on unrelated edit: got %v want 198.51.100.2 (sticky)", got.Status.AllocatedVIP)
	}
	if got.Status.ObservedGeneration != 2 {
		t.Fatalf("observedGeneration = %d want 2", got.Status.ObservedGeneration)
	}
}
