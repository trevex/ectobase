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
