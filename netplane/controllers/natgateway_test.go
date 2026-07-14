package controllers

import (
	"context"
	"reflect"
	"testing"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
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
	return n
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

	r := &Reconciler{Client: c}
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
	if a1.PortMax < a2.PortMin && a2.PortMax < a1.PortMin {
		// impossible, but keep the intent explicit
	}
	if !(a1.PortMax < a2.PortMin || a2.PortMax < a1.PortMin) {
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
