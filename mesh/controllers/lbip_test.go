// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func readyPool(name, v4 string) *netv1.IPPool {
	p := &netv1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V4Prefix: sp(v4)},
	}
	p.Status.State = "Ready"
	return p
}

func lb(name, pool, lbIP string) *netv1.LoadBalancer {
	return &netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Generation: 1, UID: types.UID("uid-" + name)},
		Spec:       netv1.LoadBalancerSpec{PoolRef: netv1.LocalObjectReference{Name: pool}, IP: lbIP},
	}
}

// A freed address is a deleted IPAllocation, whoever freed it — including a NAT gateway, which
// is why the retry watch hangs off the allocation and not off the LoadBalancer.
func TestLBsWaitingOnPool(t *testing.T) {
	scheme := lbScheme(t)
	stuck := lb("stuck", "p", "")
	stuck.Status.State = "Exhausted"
	ready := lb("ready", "p", "")
	ready.Status.State = "Allocated"
	other := lb("other", "q", "")
	other.Status.State = "Exhausted"
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(stuck, ready, other).Build()

	reqs := lbsWaitingOnPool(context.Background(), cl, "default", "p")
	if len(reqs) != 1 {
		t.Fatalf("got %d requests, want exactly 1 (stuck): %v", len(reqs), reqs)
	}
	if reqs[0].Name != "stuck" {
		t.Fatalf("got %q, want stuck (not ready/Allocated, not other/different-pool)", reqs[0].Name)
	}
	if reqs := lbsWaitingOnPool(context.Background(), cl, "default", ""); reqs != nil {
		t.Fatalf("an allocation with no poolRef should enqueue nothing, got %v", reqs)
	}
}

func TestLBAddressAllocateAndAdopt(t *testing.T) {
	scheme := lbScheme(t)
	pool := readyPool("p", "198.51.100.0/24")
	byo := lb("byo", "p", "198.51.100.10")
	auto := lb("auto", "p", "")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, byo, auto).
		WithStatusSubresource(&netv1.LoadBalancer{}).Build()
	r := &LoadBalancerIPReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	if err := r.Sync(ctx, byo); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(ctx, auto); err != nil {
		t.Fatal(err)
	}

	get := func(n string) netv1.LoadBalancer {
		var x netv1.LoadBalancer
		_ = cl.Get(ctx, keyOf(&netv1.LoadBalancer{ObjectMeta: metav1.ObjectMeta{Name: n, Namespace: "default"}}), &x)
		return x
	}
	if g := get("byo"); g.Status.State != "Allocated" || g.Status.AllocatedIP != "198.51.100.10" {
		t.Fatalf("byo = %+v", g.Status)
	}
	if g := get("auto"); g.Status.State != "Allocated" || g.Status.AllocatedIP != "198.51.100.1" {
		t.Fatalf("auto = %+v want .1", g.Status)
	}

	// The claim itself: one IPAllocation per address, at its deterministic name.
	var list netv1.IPAllocationList
	if err := cl.List(ctx, &list, client.InNamespace("default")); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 2 {
		t.Fatalf("ipallocations = %d want 2: %v", len(list.Items), list.Items)
	}
	for _, name := range []string{"p-198-51-100-10", "p-198-51-100-1"} {
		var a netv1.IPAllocation
		if err := cl.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, &a); err != nil {
			t.Fatalf("allocation %s missing: %v", name, err)
		}
		if a.Labels[netv1.PoolLabel] != "p" {
			t.Fatalf("%s pool label = %q want p", name, a.Labels[netv1.PoolLabel])
		}
	}

	// A re-reconcile adopts its own allocation rather than creating a second.
	b := get("byo")
	b.Generation = 2
	if err := r.Sync(ctx, &b); err != nil {
		t.Fatal(err)
	}
	if err := cl.List(ctx, &list, client.InNamespace("default")); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 2 {
		t.Fatalf("after re-reconcile ipallocations = %d want still 2", len(list.Items))
	}
	if g := get("byo"); g.Status.AllocatedIP != "198.51.100.10" {
		t.Fatalf("byo renumbered on re-reconcile: %v", g.Status.AllocatedIP)
	}
}

// The ownerRef is the whole reclamation story, and envtest runs no garbage collector, so these
// fields are the only part of it provable off a live cluster. Assert them explicitly.
func TestLBAllocationIsOwnedByItsLoadBalancer(t *testing.T) {
	scheme := lbScheme(t)
	pool := readyPool("p", "198.51.100.0/24")
	l := lb("lb", "p", "")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, l).
		WithStatusSubresource(&netv1.LoadBalancer{}).Build()
	r := &LoadBalancerIPReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	if err := r.Sync(ctx, l); err != nil {
		t.Fatal(err)
	}

	var a netv1.IPAllocation
	if err := cl.Get(ctx, types.NamespacedName{Namespace: "default", Name: "p-198-51-100-1"}, &a); err != nil {
		t.Fatal(err)
	}
	ref := metav1.GetControllerOf(&a)
	if ref == nil {
		t.Fatal("no controller ownerReference; nothing would ever reclaim this allocation")
	}
	if ref.Kind != "LoadBalancer" || ref.Name != "lb" || ref.UID != "uid-lb" {
		t.Fatalf("ownerRef = %+v want LoadBalancer/lb/uid-lb", ref)
	}
	if ref.Controller == nil || !*ref.Controller {
		t.Fatalf("ownerRef is not a controller ref: %+v", ref)
	}
	if a.Spec.ConsumerRef.Kind != "LoadBalancer" || a.Spec.ConsumerRef.Name != "lb" {
		t.Fatalf("consumerRef = %+v", a.Spec.ConsumerRef)
	}
}

// An internal pool is not a load-balancer pool, whatever its prefix says.
func TestLBRefusesAnInternalPool(t *testing.T) {
	scheme := lbScheme(t)
	pool := readyPool("p", "198.51.100.0/24")
	pool.Spec.Type = netv1.IPPoolTypeInternal
	l := lb("lb", "p", "")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, l).
		WithStatusSubresource(&netv1.LoadBalancer{}).Build()
	r := &LoadBalancerIPReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	if err := r.Sync(ctx, l); err != nil {
		t.Fatal(err)
	}
	var got netv1.LoadBalancer
	if err := cl.Get(ctx, keyOf(l), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != "Invalid" {
		t.Fatalf("state = %q want Invalid (pool is internal)", got.Status.State)
	}
	var list netv1.IPAllocationList
	if err := cl.List(ctx, &list, client.InNamespace("default")); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 0 {
		t.Fatalf("a refused LB still claimed %d address(es)", len(list.Items))
	}
}

// A pinned address that another consumer already holds is refused, not stolen.
func TestLBPinnedAddressHeldByAnotherConsumerIsRefused(t *testing.T) {
	scheme := lbScheme(t)
	pool := readyPool("p", "198.51.100.0/24")
	holder := lb("holder", "p", "198.51.100.10")
	thief := lb("thief", "p", "198.51.100.10")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, holder, thief).
		WithStatusSubresource(&netv1.LoadBalancer{}).Build()
	r := &LoadBalancerIPReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	if err := r.Sync(ctx, holder); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(ctx, thief); err != nil {
		t.Fatal(err)
	}

	var got netv1.LoadBalancer
	if err := cl.Get(ctx, keyOf(thief), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != "Invalid" || got.Status.AllocatedIP != "" {
		t.Fatalf("thief = %+v want Invalid with no address", got.Status)
	}
	var list netv1.IPAllocationList
	if err := cl.List(ctx, &list, client.InNamespace("default")); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("ipallocations = %d want 1 (the holder's)", len(list.Items))
	}
	ref := metav1.GetControllerOf(&list.Items[0])
	if ref == nil || ref.Name != "holder" {
		t.Fatalf("the surviving allocation is not the holder's: %+v", ref)
	}
}

// Repointing spec.ip must hand the old address back, or a pool leaks one address per edit.
func TestLBRepinReleasesTheOldAddress(t *testing.T) {
	scheme := lbScheme(t)
	pool := readyPool("p", "198.51.100.0/24")
	l := lb("lb", "p", "198.51.100.10")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, l).
		WithStatusSubresource(&netv1.LoadBalancer{}).Build()
	r := &LoadBalancerIPReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	if err := r.Sync(ctx, l); err != nil {
		t.Fatal(err)
	}

	var got netv1.LoadBalancer
	if err := cl.Get(ctx, keyOf(l), &got); err != nil {
		t.Fatal(err)
	}
	got.Spec.IP = "198.51.100.11"
	got.Generation = 2
	if err := cl.Update(ctx, &got); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(ctx, &got); err != nil {
		t.Fatal(err)
	}

	var list netv1.IPAllocationList
	if err := cl.List(ctx, &list, client.InNamespace("default")); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].Spec.Address != "198.51.100.11" {
		t.Fatalf("after re-pin: %d allocation(s) %v, want only 198.51.100.11", len(list.Items), list.Items)
	}
	var after netv1.LoadBalancer
	if err := cl.Get(ctx, keyOf(l), &after); err != nil {
		t.Fatal(err)
	}
	if after.Status.AllocatedIP != "198.51.100.11" {
		t.Fatalf("status.allocatedIP = %q want 198.51.100.11", after.Status.AllocatedIP)
	}
}

func TestLBAddressStickyAcrossGenerationBump(t *testing.T) {
	scheme := lbScheme(t)
	pool := readyPool("p", "198.51.100.0/24")
	a := lb("a", "p", "") // auto
	b := lb("b", "p", "") // auto
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, a, b).
		WithStatusSubresource(&netv1.LoadBalancer{}).Build()
	r := &LoadBalancerIPReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	if err := r.Sync(ctx, a); err != nil { // a -> .1
		t.Fatal(err)
	}
	if err := r.Sync(ctx, b); err != nil { // b -> .2
		t.Fatal(err)
	}

	// Free the lower address by deleting a AND its claim. envtest and the fake client run no
	// garbage collector, so the allocation has to go explicitly here — in production the
	// ownerRef does this, which is the one thing only the live lab can prove.
	var ga netv1.LoadBalancer
	if err := cl.Get(ctx, keyOf(a), &ga); err != nil {
		t.Fatal(err)
	}
	if err := cl.Delete(ctx, &ga); err != nil {
		t.Fatal(err)
	}
	var aAlloc netv1.IPAllocation
	if err := cl.Get(ctx, types.NamespacedName{Namespace: "default", Name: "p-198-51-100-1"}, &aAlloc); err != nil {
		t.Fatal(err)
	}
	if err := cl.Delete(ctx, &aAlloc); err != nil {
		t.Fatal(err)
	}

	var gb netv1.LoadBalancer
	if err := cl.Get(ctx, keyOf(b), &gb); err != nil {
		t.Fatal(err)
	}
	if gb.Status.AllocatedIP != "198.51.100.2" {
		t.Fatalf("precondition: b should have .2, got %v", gb.Status.AllocatedIP)
	}
	gb.Generation = 2
	if err := cl.Update(ctx, &gb); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(ctx, keyOf(b), &gb); err != nil {
		t.Fatal(err)
	}
	gb.Generation = 2
	if err := r.Sync(ctx, &gb); err != nil {
		t.Fatal(err)
	}
	var got netv1.LoadBalancer
	if err := cl.Get(ctx, keyOf(b), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.AllocatedIP != "198.51.100.2" {
		t.Fatalf("b LB address renumbered on unrelated edit: got %v want 198.51.100.2 (sticky)", got.Status.AllocatedIP)
	}
	if got.Status.ObservedGeneration != 2 {
		t.Fatalf("observedGeneration = %d want 2", got.Status.ObservedGeneration)
	}
}

// An exhausted pool parks the LB rather than erroring, and claims nothing.
func TestLBExhaustedPool(t *testing.T) {
	scheme := lbScheme(t)
	pool := racePool() // exactly one allocatable address
	first := lb("first", "p", "")
	second := lb("second", "p", "")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, first, second).
		WithStatusSubresource(&netv1.LoadBalancer{}).Build()
	r := &LoadBalancerIPReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	if err := r.Sync(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(ctx, second); err != nil {
		t.Fatal(err)
	}
	var got netv1.LoadBalancer
	if err := cl.Get(ctx, keyOf(second), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != "Exhausted" {
		t.Fatalf("state = %q want Exhausted", got.Status.State)
	}
}

// A missing pool is Invalid; a pool that is not yet Ready is Pending, not a failed allocation.
func TestLBStatesFollowTheirPool(t *testing.T) {
	scheme := lbScheme(t)
	pending := readyPool("pending", "198.51.100.0/24")
	pending.Status.State = "Pending"
	onPending := lb("on-pending", "pending", "")
	onMissing := lb("on-missing", "nope", "")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pending, onPending, onMissing).
		WithStatusSubresource(&netv1.LoadBalancer{}).Build()
	r := &LoadBalancerIPReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	if err := r.Sync(ctx, onPending); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(ctx, onMissing); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, want string }{
		{"on-pending", "Pending"},
		{"on-missing", "Invalid"},
	} {
		var got netv1.LoadBalancer
		if err := cl.Get(ctx, types.NamespacedName{Namespace: "default", Name: tc.name}, &got); err != nil {
			t.Fatal(err)
		}
		if got.Status.State != tc.want {
			t.Fatalf("%s state = %q want %q", tc.name, got.Status.State, tc.want)
		}
	}
}

// Repointing spec.poolRef must hand the old pool's address back too. The claim lives in a pool
// this reconcile never looks at, which is why release selects on the consumer and not the pool.
func TestLBPoolSwapReleasesTheOldPoolsAddress(t *testing.T) {
	scheme := lbScheme(t)
	a := readyPool("a", "198.51.100.0/24")
	b := readyPool("b", "203.0.113.0/24")
	l := lb("lb", "a", "")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(a, b, l).
		WithStatusSubresource(&netv1.LoadBalancer{}).Build()
	r := &LoadBalancerIPReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	if err := r.Sync(ctx, l); err != nil {
		t.Fatal(err)
	}

	var got netv1.LoadBalancer
	if err := cl.Get(ctx, keyOf(l), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.AllocatedIP != "198.51.100.1" {
		t.Fatalf("precondition: want 198.51.100.1, got %q", got.Status.AllocatedIP)
	}
	got.Spec.PoolRef.Name = "b"
	got.Generation = 2
	if err := cl.Update(ctx, &got); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(ctx, &got); err != nil {
		t.Fatal(err)
	}

	var list netv1.IPAllocationList
	if err := cl.List(ctx, &list, client.InNamespace("default")); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		var names []string
		for i := range list.Items {
			names = append(names, list.Items[i].Name)
		}
		t.Fatalf("after pool swap: %d allocations %v, want only the one in pool b", len(list.Items), names)
	}
	if list.Items[0].Spec.PoolRef.Name != "b" || list.Items[0].Spec.Address != "203.0.113.1" {
		t.Fatalf("surviving allocation = %+v want pool b / 203.0.113.1", list.Items[0].Spec)
	}
	if list.Items[0].Labels[netv1.ConsumerLabel] != "uid-lb" {
		t.Fatalf("consumer index label = %q want uid-lb", list.Items[0].Labels[netv1.ConsumerLabel])
	}
}
