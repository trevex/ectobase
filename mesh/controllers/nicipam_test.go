package controllers

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func readySubnet(name, vpc, v4, v6 string) *netv1.Subnet {
	s := &netv1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       netv1.SubnetSpec{VPCRef: netv1.LocalObjectReference{Name: vpc}},
	}
	if v4 != "" {
		s.Spec.V4Prefix = sp(v4)
	}
	if v6 != "" {
		s.Spec.V6Prefix = sp(v6)
	}
	s.Status.State = "Ready"
	return s
}

func nic(name, vpc, subnet string, ips ...string) *netv1.NetworkInterface {
	return &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Generation: 1},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:    netv1.LocalObjectReference{Name: vpc},
			SubnetRef: netv1.LocalObjectReference{Name: subnet},
			IPs:       ips,
		},
	}
}

func TestNICPeersNeedingRetry(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = netv1.AddToScheme(scheme)
	// stuck peer in same VPC, a Ready peer, and a different-VPC stuck peer
	stuck := nic("stuck", "blue", "s")
	stuck.Status.State = "Exhausted"
	ready := nic("ready", "blue", "s")
	ready.Status.State = "Allocated"
	other := nic("other", "green", "s2")
	other.Status.State = "Exhausted"
	gone := nic("gone", "blue", "s")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(stuck, ready, other).Build()

	reqs := nicPeersNeedingRetry(context.Background(), cl, gone)
	if len(reqs) != 1 {
		t.Fatalf("got %d requests, want exactly 1 (stuck): %v", len(reqs), reqs)
	}
	if reqs[0].Name != "stuck" {
		t.Fatalf("got %q, want stuck (not ready/Allocated, not other/different-VPC)", reqs[0].Name)
	}
}

func TestNICAllocateAndAdopt(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	sub := readySubnet("s", "blue", "10.0.1.0/24", "fd00:1::/64")
	auto := nic("auto", "blue", "s")
	byo := nic("byo", "blue", "s", "10.0.1.50")

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(sub, auto, byo).
		WithStatusSubresource(&netv1.NetworkInterface{}).Build()
	r := &NICIPAMReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()

	if err := r.Sync(ctx, byo); err != nil {
		t.Fatalf("sync byo: %v", err)
	}
	if err := r.Sync(ctx, auto); err != nil {
		t.Fatalf("sync auto: %v", err)
	}

	get := func(n string) netv1.NetworkInterface {
		var x netv1.NetworkInterface
		if err := cl.Get(ctx, keyOf(&netv1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: n, Namespace: "default"}}), &x); err != nil {
			t.Fatal(err)
		}
		return x
	}
	gb := get("byo")
	if gb.Status.State != "Allocated" || gb.Status.ObservedGeneration != 1 {
		t.Fatalf("byo status = %+v", gb.Status)
	}
	if len(gb.Status.AllocatedIPs) != 1 || gb.Status.AllocatedIPs[0] != "10.0.1.50" {
		t.Fatalf("byo allocated = %v want [10.0.1.50]", gb.Status.AllocatedIPs)
	}
	ga := get("auto")
	if ga.Status.State != "Allocated" || len(ga.Status.AllocatedIPs) != 2 {
		t.Fatalf("auto allocated = %+v want v4+v6", ga.Status)
	}
	if ga.Status.AllocatedIPs[0] != "10.0.1.1" {
		t.Fatalf("auto v4 = %v want 10.0.1.1", ga.Status.AllocatedIPs[0])
	}
}

func TestNICStickyAcrossGenerationBump(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = netv1.AddToScheme(scheme)
	sub := readySubnet("s", "blue", "10.0.1.0/24", "")
	a := nic("a", "blue", "s") // auto
	b := nic("b", "blue", "s") // auto
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sub, a, b).WithStatusSubresource(&netv1.NetworkInterface{}).Build()
	r := &NICIPAMReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	_ = r.Sync(ctx, a) // a -> 10.0.1.1
	_ = r.Sync(ctx, b) // b -> 10.0.1.2

	// free the lower address by deleting a
	var ga netv1.NetworkInterface
	_ = cl.Get(ctx, keyOf(a), &ga)
	if err := cl.Delete(ctx, &ga); err != nil {
		t.Fatal(err)
	}

	// bump b's generation (simulate an unrelated spec edit) and re-sync
	var gb netv1.NetworkInterface
	_ = cl.Get(ctx, keyOf(b), &gb)
	if gb.Status.AllocatedIPs[0] != "10.0.1.2" {
		t.Fatalf("precondition: b should have .2, got %v", gb.Status.AllocatedIPs)
	}
	gb.Generation = 2
	if err := cl.Update(ctx, &gb); err != nil {
		t.Fatal(err)
	}
	// re-fetch (Update may reset status expectations) then Sync
	_ = cl.Get(ctx, keyOf(b), &gb)
	gb.Generation = 2
	if err := r.Sync(ctx, &gb); err != nil {
		t.Fatal(err)
	}
	var got netv1.NetworkInterface
	_ = cl.Get(ctx, keyOf(b), &got)
	if len(got.Status.AllocatedIPs) != 1 || got.Status.AllocatedIPs[0] != "10.0.1.2" {
		t.Fatalf("b renumbered on unrelated edit: got %v want [10.0.1.2] (sticky)", got.Status.AllocatedIPs)
	}
	if got.Status.ObservedGeneration != 2 {
		t.Fatalf("observedGeneration = %d want 2", got.Status.ObservedGeneration)
	}
}

func TestNICOutOfSubnetIsInvalid(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = netv1.AddToScheme(scheme)
	sub := readySubnet("s", "blue", "10.0.1.0/24", "")
	bad := nic("bad", "blue", "s", "10.0.9.9")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sub, bad).WithStatusSubresource(&netv1.NetworkInterface{}).Build()
	r := &NICIPAMReconciler{Client: cl, APIReader: cl}
	if err := r.Sync(context.Background(), bad); err != nil {
		t.Fatal(err)
	}
	var g netv1.NetworkInterface
	_ = cl.Get(context.Background(), keyOf(bad), &g)
	if g.Status.State != "Invalid" {
		t.Fatalf("state = %q want Invalid", g.Status.State)
	}
}

func TestNICExhaustion(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = netv1.AddToScheme(scheme)
	sub := readySubnet("s", "blue", "192.168.0.0/30", "")
	occ1 := nic("o1", "blue", "s", "192.168.0.1")
	occ2 := nic("o2", "blue", "s", "192.168.0.2")
	want := nic("want", "blue", "s")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sub, occ1, occ2, want).WithStatusSubresource(&netv1.NetworkInterface{}).Build()
	r := &NICIPAMReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	_ = r.Sync(ctx, occ1)
	_ = r.Sync(ctx, occ2)
	_ = r.Sync(ctx, want)
	var g netv1.NetworkInterface
	_ = cl.Get(ctx, keyOf(want), &g)
	if g.Status.State != "Exhausted" {
		t.Fatalf("state = %q want Exhausted", g.Status.State)
	}
}

func TestNICAdoptsLegacyIPs(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = netv1.AddToScheme(scheme)
	sub := readySubnet("s", "blue", "10.0.1.0/24", "")
	legacy := nic("legacy", "blue", "s", "10.0.1.77")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sub, legacy).WithStatusSubresource(&netv1.NetworkInterface{}).Build()
	r := &NICIPAMReconciler{Client: cl, APIReader: cl}
	if err := r.Sync(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	var g netv1.NetworkInterface
	_ = cl.Get(context.Background(), keyOf(legacy), &g)
	if g.Status.State != "Allocated" || len(g.Status.AllocatedIPs) != 1 || g.Status.AllocatedIPs[0] != "10.0.1.77" {
		t.Fatalf("legacy adoption = %+v want [10.0.1.77]", g.Status)
	}
}
