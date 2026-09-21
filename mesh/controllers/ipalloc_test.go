// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The name is the allocation's uniqueness guarantee: object names are unique in a namespace, so
// Create is a compare-and-swap. That only holds if the encoding is INJECTIVE (two addresses can
// never collide) and always produces a legal DNS-1123 subdomain.
func TestAllocationNameIsInjectiveAndLegal(t *testing.T) {
	for _, tc := range []struct{ pool, addr, want string }{
		{"pub", "192.0.2.40", "pub-192-0-2-40"},
		{"pub", "10.0.0.1", "pub-10-0-0-1"},
		// Expanded, so there is never a "::" — the compressed form of ::1 would encode to
		// "--1", which is not a legal name.
		{"pub", "2001:db8:2b::a", "pub-2001-0db8-002b-0000-0000-0000-0000-000a"},
		{"pub", "::1", "pub-0000-0000-0000-0000-0000-0000-0000-0001"},
	} {
		got, err := allocationName(tc.pool, netip.MustParseAddr(tc.addr))
		if err != nil || got != tc.want {
			t.Fatalf("allocationName(%q,%q) = %q,%v want %q", tc.pool, tc.addr, got, err, tc.want)
		}
		if errs := validation.IsDNS1123Subdomain(got); len(errs) > 0 {
			t.Fatalf("name %q is not a legal object name: %v", got, errs)
		}
	}
}

// Distinct addresses must never share a name, including across families.
func TestAllocationNamesDoNotCollide(t *testing.T) {
	seen := map[string]string{}
	for _, a := range []string{"192.0.2.40", "192.0.2.41", "::1", "::2",
		"2001:db8::1", "2001:db8:0:0:0:0:0:1"} { // the last two are the SAME address
		n, err := allocationName("p", netip.MustParseAddr(a))
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[n]; dup && netip.MustParseAddr(prev) != netip.MustParseAddr(a) {
			t.Fatalf("addresses %s and %s both encode to %q", prev, a, n)
		}
		seen[n] = a
	}
}

// The pool name and the address share one dash-separated string, so the encoding must be
// injective over the PAIR. Expansion is what makes it so: the address is always a fixed number
// of groups (8 for v6, 4 for v4), so the split is unique. Compressed, ("p-2001", db8::1) and
// ("p", 2001:db8::1) both spell "p-2001-db8--1" and a claim on one address refuses the other.
//
// This is the assertion that fails if anyone swaps StringExpanded for String — the legality
// check above does not, because "pub---1" is a legal DNS-1123 subdomain.
func TestAllocationNameIsInjectiveOverPoolAndAddress(t *testing.T) {
	for _, tc := range []struct {
		aPool, aAddr, bPool, bAddr string
	}{
		{"p-2001", "db8::1", "p", "2001:db8::1"},
		{"p-10", "0.0.1.5", "p", "10.0.0.1"},
		{"p-0000", "2001:db8::1", "p", "0:2001:db8::1"},
	} {
		a, err := allocationName(tc.aPool, netip.MustParseAddr(tc.aAddr))
		if err != nil {
			t.Fatal(err)
		}
		b, err := allocationName(tc.bPool, netip.MustParseAddr(tc.bAddr))
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Fatalf("(%s,%s) and (%s,%s) both encode to %q: a claim on one address would refuse the other",
				tc.aPool, tc.aAddr, tc.bPool, tc.bAddr, a)
		}
	}
}

// An address that cannot be spelled as a legal object name must be refused, not allocated: a
// name the apiserver rejects is a claim that collides with nothing.
func TestAllocationNameRefusesUnnameableAddresses(t *testing.T) {
	if _, err := allocationName("", netip.MustParseAddr("192.0.2.40")); err == nil {
		t.Fatal("empty pool name yields a leading dash; want an error")
	}
	if _, err := allocationName("p", netip.MustParseAddr("fe80::1%eth0")); err == nil {
		t.Fatal("a zoned address yields a '%' in the name; want an error")
	}
	if _, err := allocationName("p", netip.Addr{}); err == nil {
		t.Fatal("the zero Addr is not an address; want an error")
	}
}

// ::ffff:192.0.2.1 and 192.0.2.1 are one address. Two names for it would let two allocators
// both "win" it, which is exactly what the Create-is-a-CAS argument forbids.
func TestAllocationNameUnmapsV4InV6(t *testing.T) {
	mapped, err := allocationName("p", netip.MustParseAddr("::ffff:192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := allocationName("p", netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if mapped != plain {
		t.Fatalf("one address, two names: %q vs %q", mapped, plain)
	}
}

// countingClient records Create outcomes so the concurrency test can report whether the
// AlreadyExists path — the compare-and-swap itself — was actually exercised, rather than
// assuming the fake client scheduled the goroutines the way the argument needs.
type countingClient struct {
	client.Client
	creates, conflicts atomic.Int64
}

func (c *countingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.creates.Add(1)
	err := c.Client.Create(ctx, obj, opts...)
	if apierrors.IsAlreadyExists(err) {
		c.conflicts.Add(1)
	}
	return err
}

// racePool is a pool with EXACTLY one allocatable address: a /30 gives .0 (network), .1, .2 and
// .3 (broadcast); reserving .2 leaves .1 alone.
func racePool() *netv1.IPPool {
	p := &netv1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"},
		Spec: netv1.IPPoolSpec{
			Type:        netv1.IPPoolTypePublic,
			V4Prefix:    sp("198.51.100.0/30"),
			ReservedIPs: []string{"198.51.100.2"},
		},
	}
	p.Status.State = "Ready"
	return p
}

// Two (here: eight) consumers racing for the last free address: exactly one wins. This is what
// the design buys over scanning consumer statuses, where every racer reads the same used-set and
// every racer writes. The claim is the object NAME, so the apiserver — or here the fake client's
// tracker — resolves the race for free.
func TestTwoConsumersRacingForTheLastAddressOnlyOneWins(t *testing.T) {
	scheme := lbScheme(t)
	pool := racePool()
	const racers = 8

	consumers := make([]*netv1.LoadBalancer, racers)
	objs := []client.Object{pool}
	for i := range consumers {
		consumers[i] = &netv1.LoadBalancer{ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("lb%d", i),
			Namespace: "default",
			UID:       types.UID(fmt.Sprintf("uid-%d", i)),
		}}
		objs = append(objs, consumers[i])
	}
	cl := &countingClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()}

	ctx := context.Background()
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	won := make([]bool, racers)
	errs := make([]error, racers)
	for i := range consumers {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait() // let them all reach the used-set read together
			_, ok, err := claimAddress(ctx, cl, cl, pool, consumers[i], "LoadBalancer", nil, nil)
			won[i], errs[i] = ok, err
		}(i)
	}
	start.Done()
	done.Wait()

	winners := 0
	for i := range won {
		if errs[i] != nil {
			t.Fatalf("racer %d errored: %v", i, errs[i])
		}
		if won[i] {
			winners++
		}
	}

	var list netv1.IPAllocationList
	if err := cl.List(ctx, &list, client.InNamespace("default")); err != nil {
		t.Fatal(err)
	}
	t.Logf("winners=%d allocations=%d creates=%d already-exists=%d",
		winners, len(list.Items), cl.creates.Load(), cl.conflicts.Load())

	if winners != 1 {
		t.Fatalf("winners = %d, want exactly 1 (the pool holds one address)", winners)
	}
	if len(list.Items) != 1 {
		t.Fatalf("ipallocations = %d, want exactly 1", len(list.Items))
	}
	if got := list.Items[0].Spec.Address; got != "198.51.100.1" {
		t.Fatalf("allocated address = %q want 198.51.100.1", got)
	}
}

// The deterministic half of the same argument, with no scheduling involved: an address already
// claimed by another consumer is simply not available, whether it is asked for by name or
// reached by the lowest-free walk.
func TestClaimRefusesAnAddressAnotherConsumerHolds(t *testing.T) {
	scheme := lbScheme(t)
	pool := racePool()
	holder := &netv1.LoadBalancer{ObjectMeta: metav1.ObjectMeta{Name: "holder", Namespace: "default", UID: "uid-holder"}}
	rival := &netv1.LoadBalancer{ObjectMeta: metav1.ObjectMeta{Name: "rival", Namespace: "default", UID: "uid-rival"}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, holder, rival).Build()
	ctx := context.Background()

	got, ok, err := claimAddress(ctx, cl, cl, pool, holder, "LoadBalancer", nil, nil)
	if err != nil || !ok || got.String() != "198.51.100.1" {
		t.Fatalf("holder claim = %v,%v,%v want 198.51.100.1", got, ok, err)
	}
	// Re-claiming is idempotent: the holder adopts its own allocation, it does not take a second.
	again, ok, err := claimAddress(ctx, cl, cl, pool, holder, "LoadBalancer", nil, nil)
	if err != nil || !ok || again != got {
		t.Fatalf("holder re-claim = %v,%v,%v want %v", again, ok, err, got)
	}

	// Auto-allocation for the rival finds nothing left.
	if _, ok, err := claimAddress(ctx, cl, cl, pool, rival, "LoadBalancer", nil, nil); err != nil || ok {
		t.Fatalf("rival auto-claim = ok:%v err:%v, want exhausted", ok, err)
	}
	// Pinning the held address is refused as unallocatable, not silently granted.
	pin := netip.MustParseAddr("198.51.100.1")
	if _, _, err := claimAddress(ctx, cl, cl, pool, rival, "LoadBalancer", &pin, nil); !errors.Is(err, errNotAllocatable) {
		t.Fatalf("rival pin on a held address = %v, want errNotAllocatable", err)
	}

	var list netv1.IPAllocationList
	if err := cl.List(ctx, &list, client.InNamespace("default")); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("ipallocations = %d, want exactly 1", len(list.Items))
	}
}

// A consumer repointed at a different address must not keep its old claim: one address per
// single-address consumer, or the pool leaks one address per edit.
func TestReleaseClaimsExceptFreesTheSupersededAddress(t *testing.T) {
	scheme := lbScheme(t)
	pool := &netv1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"},
		Spec:       netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V4Prefix: sp("198.51.100.0/24")},
	}
	pool.Status.State = "Ready"
	lb := &netv1.LoadBalancer{ObjectMeta: metav1.ObjectMeta{Name: "lb", Namespace: "default", UID: "uid-lb"}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, lb).Build()
	ctx := context.Background()

	first := netip.MustParseAddr("198.51.100.10")
	if _, ok, err := claimAddress(ctx, cl, cl, pool, lb, "LoadBalancer", &first, nil); err != nil || !ok {
		t.Fatalf("first claim = %v,%v", ok, err)
	}
	second := netip.MustParseAddr("198.51.100.11")
	if _, ok, err := claimAddress(ctx, cl, cl, pool, lb, "LoadBalancer", &second, nil); err != nil || !ok {
		t.Fatalf("second claim = %v,%v", ok, err)
	}
	if err := releaseClaimsExcept(ctx, cl, cl, pool, lb, "LoadBalancer", second); err != nil {
		t.Fatal(err)
	}

	var list netv1.IPAllocationList
	if err := cl.List(ctx, &list, client.InNamespace("default")); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].Spec.Address != "198.51.100.11" {
		t.Fatalf("after release: %d allocations %v, want exactly 198.51.100.11", len(list.Items), list.Items)
	}
}

// The allocation carries a controller ownerReference to its consumer, which is what Kubernetes
// garbage collection reclaims it by. envtest runs no garbage collector, so the ownerRef FIELDS
// are the only part of reclamation provable here; the collection itself is a live-lab check.
func TestClaimSetsControllerOwnerRefAndPoolLabel(t *testing.T) {
	scheme := lbScheme(t)
	pool := &netv1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "pub", Namespace: "default"},
		Spec:       netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V4Prefix: sp("198.51.100.0/24")},
	}
	pool.Status.State = "Ready"
	lb := &netv1.LoadBalancer{ObjectMeta: metav1.ObjectMeta{Name: "lb", Namespace: "default", UID: "uid-lb"}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, lb).Build()
	ctx := context.Background()

	addr, ok, err := claimAddress(ctx, cl, cl, pool, lb, "LoadBalancer", nil, nil)
	if err != nil || !ok {
		t.Fatalf("claim = %v,%v,%v", addr, ok, err)
	}
	var alloc netv1.IPAllocation
	if err := cl.Get(ctx, types.NamespacedName{Namespace: "default", Name: "pub-198-51-100-1"}, &alloc); err != nil {
		t.Fatalf("allocation not at its deterministic name: %v", err)
	}
	if alloc.Labels[netv1.PoolLabel] != "pub" {
		t.Fatalf("pool label = %q want pub", alloc.Labels[netv1.PoolLabel])
	}
	if alloc.Spec.PoolRef.Name != "pub" || alloc.Spec.Address != "198.51.100.1" {
		t.Fatalf("spec = %+v", alloc.Spec)
	}
	if alloc.Spec.ConsumerRef.Kind != "LoadBalancer" || alloc.Spec.ConsumerRef.Name != "lb" {
		t.Fatalf("consumerRef = %+v", alloc.Spec.ConsumerRef)
	}
	ref := metav1.GetControllerOf(&alloc)
	if ref == nil {
		t.Fatal("no controller ownerReference; garbage collection would never reclaim this")
	}
	if ref.Kind != "LoadBalancer" || ref.Name != "lb" || ref.UID != "uid-lb" {
		t.Fatalf("ownerRef = %+v want LoadBalancer/lb/uid-lb", ref)
	}
	if ref.Controller == nil || !*ref.Controller {
		t.Fatalf("ownerRef is not a CONTROLLER ref: %+v", ref)
	}
	if ref.BlockOwnerDeletion == nil || !*ref.BlockOwnerDeletion {
		t.Fatalf("ownerRef does not block owner deletion: %+v", ref)
	}
}
