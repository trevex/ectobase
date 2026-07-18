package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func meterScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func nodePtr(s string) *string { return &s }

// A NIC scheduled to this node with a bandwidth cap set → the agent calls ConfigureMeter with the
// spec's totalMbps/publicMbps and the NIC name as the interface_id.
func TestReconcileMeter_PushesCap(t *testing.T) {
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:    netv1.LocalObjectReference{Name: "vpc-a"},
			NodeName:  nodePtr("nodeA"),
			Bandwidth: &netv1.InterfaceBandwidth{TotalMbps: 100, PublicMbps: 40},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(meterScheme(t)).WithObjects(nic).Build()
	dp := newRecordingDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileMeter(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := dp.getMeter("web-0-nic0")
	if !ok {
		t.Fatalf("ConfigureMeter not called for web-0-nic0; meters=%+v", dp.meters)
	}
	if got.totalMbps != 100 || got.publicMbps != 40 {
		t.Fatalf("ConfigureMeter caps = (%d,%d), want (100,40)", got.totalMbps, got.publicMbps)
	}
}

// A NIC without a bandwidth spec, or scheduled to another node, is not metered.
func TestReconcileMeter_SkipsUnsetAndOffNode(t *testing.T) {
	noCap := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec:       netv1.NetworkInterfaceSpec{VPCRef: netv1.LocalObjectReference{Name: "vpc-a"}, NodeName: nodePtr("nodeA")},
	}
	offNode := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:    netv1.LocalObjectReference{Name: "vpc-a"},
			NodeName:  nodePtr("nodeB"),
			Bandwidth: &netv1.InterfaceBandwidth{TotalMbps: 50},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(meterScheme(t)).WithObjects(noCap, offNode).Build()
	dp := newRecordingDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileMeter(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.meters) != 0 {
		t.Fatalf("no meters expected, got %+v", dp.meters)
	}
}

// Reconcile is level-triggered: an unchanged cap is pushed once, and clearing the spec sets it back
// to unlimited (0/0).
func TestReconcileMeter_ConvergesAndClears(t *testing.T) {
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:    netv1.LocalObjectReference{Name: "vpc-a"},
			NodeName:  nodePtr("nodeA"),
			Bandwidth: &netv1.InterfaceBandwidth{TotalMbps: 100, PublicMbps: 40},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(meterScheme(t)).WithObjects(nic).Build()
	dp := newRecordingDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	// Two reconciles with an unchanged cap → ConfigureMeter called exactly once (idempotent skip).
	for i := 0; i < 2; i++ {
		if err := r.ReconcileMeter(context.Background()); err != nil {
			t.Fatalf("reconcile #%d: %v", i+1, err)
		}
	}
	if n := dp.meterN["web-0-nic0"]; n != 1 {
		t.Fatalf("ConfigureMeter called %d times for unchanged cap, want 1", n)
	}

	// Clear the bandwidth spec → the next reconcile sets the cap back to unlimited (0/0).
	nic.Spec.Bandwidth = nil
	if err := cl.Update(context.Background(), nic); err != nil {
		t.Fatal(err)
	}
	if err := r.ReconcileMeter(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := dp.getMeter("web-0-nic0")
	if !ok {
		t.Fatal("ConfigureMeter clear not called")
	}
	if got.totalMbps != 0 || got.publicMbps != 0 {
		t.Fatalf("clear caps = (%d,%d), want (0,0)", got.totalMbps, got.publicMbps)
	}
	if n := dp.meterN["web-0-nic0"]; n != 2 {
		t.Fatalf("ConfigureMeter called %d times total, want 2 (set + clear)", n)
	}
}
