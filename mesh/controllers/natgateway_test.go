package controllers

import (
	"context"
	"reflect"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ptr[T any](v T) *T { return &v }

func newNIC(name, vpc string, ips ...string) *netv1.NetworkInterface {
	n := &netv1.NetworkInterface{}
	n.Name = name
	n.Namespace = "default"
	n.Spec.VPCRef = netv1.LocalObjectReference{Name: vpc}
	n.Spec.IPs = ips
	// Spec.IPs are pins, which central IPAM validates and then commits to status —
	// so a BYO NIC carries them in BOTH places once Allocated. Mirror that here.
	n.Status.State = "Allocated"
	n.Status.AllocatedIPs = ips
	return n
}

// newAutoNIC is the NORMAL path: the NIC pins nothing and central IPAM picks its
// addresses, so the overlay IPs exist only in status.
func newAutoNIC(name, vpc string, ips ...string) *netv1.NetworkInterface {
	n := &netv1.NetworkInterface{}
	n.Name = name
	n.Namespace = "default"
	n.Spec.VPCRef = netv1.LocalObjectReference{Name: vpc}
	n.Status.State = "Allocated"
	n.Status.AllocatedIPs = ips
	return n
}

// The overlay IP of a NIC lives in status — Spec.IPs is only ever an optional pin.
// A NIC that auto-allocates (the normal path) therefore has an empty Spec.IPs, and
// sourcing the allocation table from spec left it with no SNAT block at all.
func TestSyncAllocatesForAutoAllocatedNICs(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	natgw := &netv1.NATGateway{}
	natgw.Name = "gw"
	natgw.Namespace = "default"
	natgw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	natgw.Spec.PublicIPs = []string{"203.0.113.10"}

	auto := newAutoNIC("nic-auto", "blue", "10.0.0.5")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(natgw, auto).
		WithStatusSubresource(&netv1.NATGateway{}).
		Build()

	r := &NATGatewayReconciler{Client: c, APIReader: c}
	ctx := context.Background()
	if err := r.Sync(ctx, natgw); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	var got netv1.NATGateway
	if err := c.Get(ctx, keyOf(natgw), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Allocations) != 1 {
		t.Fatalf("want 1 allocation for the auto-allocated NIC, got %d: %+v",
			len(got.Status.Allocations), got.Status.Allocations)
	}
	if got.Status.Allocations[0].Source != "10.0.0.5" {
		t.Fatalf("allocation source = %q, want the status-allocated overlay IP 10.0.0.5",
			got.Status.Allocations[0].Source)
	}
}

// A NIC with no allocated address yet is not a NAT source: allocating it a block
// would burn ports on an identity that does not exist on the datapath.
func TestSyncSkipsUnallocatedNICs(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	natgw := &netv1.NATGateway{}
	natgw.Name = "gw"
	natgw.Namespace = "default"
	natgw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	natgw.Spec.PublicIPs = []string{"203.0.113.10"}

	pending := &netv1.NetworkInterface{}
	pending.Name = "nic-pending"
	pending.Namespace = "default"
	pending.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	pending.Status.State = "Pending"

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(natgw, pending).
		WithStatusSubresource(&netv1.NATGateway{}).
		Build()

	r := &NATGatewayReconciler{Client: c, APIReader: c}
	if err := r.Sync(context.Background(), natgw); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	var got netv1.NATGateway
	if err := c.Get(context.Background(), keyOf(natgw), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Allocations) != 0 {
		t.Fatalf("want no allocations, got %+v", got.Status.Allocations)
	}
}

func TestSyncAllocatesDeterministicDisjointBlocks(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	natgw := &netv1.NATGateway{}
	natgw.Name = "gw"
	natgw.Namespace = "default"
	natgw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	natgw.Spec.PublicIPs = []string{"203.0.113.10"}
	natgw.Spec.PortsPerSource = ptr(int32(1024))

	blueA := newNIC("nic-a", "blue", "10.0.0.1")
	blueB := newNIC("nic-b", "blue", "10.0.0.2")
	green := newNIC("nic-c", "green", "10.0.0.9")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(natgw, blueA, blueB, green).
		WithStatusSubresource(&netv1.NATGateway{}).
		Build()

	r := &NATGatewayReconciler{Client: c, APIReader: c}
	ctx := context.Background()

	if err := r.Sync(ctx, natgw); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	var got netv1.NATGateway
	if err := c.Get(ctx, keyOf(natgw), &got); err != nil {
		t.Fatal(err)
	}

	if got.Status.State != "Ready" {
		t.Fatalf("State = %q, want Ready", got.Status.State)
	}
	if len(got.Status.Allocations) != 2 {
		t.Fatalf("want 2 allocations, got %d: %+v", len(got.Status.Allocations), got.Status.Allocations)
	}

	sources := map[string]netv1.NATAllocation{}
	for _, a := range got.Status.Allocations {
		if a.PublicIP != "203.0.113.10" {
			t.Fatalf("allocation %+v not on the public IP", a)
		}
		sources[a.Source] = a
	}
	if _, ok := sources["10.0.0.1"]; !ok {
		t.Fatalf("missing allocation for 10.0.0.1: %+v", got.Status.Allocations)
	}
	if _, ok := sources["10.0.0.2"]; !ok {
		t.Fatalf("missing allocation for 10.0.0.2: %+v", got.Status.Allocations)
	}
	if _, ok := sources["10.0.0.9"]; ok {
		t.Fatalf("green VPC source 10.0.0.9 must not be allocated: %+v", got.Status.Allocations)
	}

	// Disjoint port-blocks within the shared public IP.
	a1, a2 := sources["10.0.0.1"], sources["10.0.0.2"]
	disjoint := a1.PortMax < a2.PortMin || a2.PortMax < a1.PortMin
	if !disjoint {
		t.Fatalf("port-blocks overlap: %+v %+v", a1, a2)
	}

	// A second reconcile must be byte-identical (deterministic/stable).
	before := got.Status.Allocations
	if err := r.Sync(ctx, &got); err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	var again netv1.NATGateway
	if err := c.Get(ctx, keyOf(natgw), &again); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, again.Status.Allocations) {
		t.Fatalf("allocations not stable:\n before %+v\n after  %+v", before, again.Status.Allocations)
	}
}
