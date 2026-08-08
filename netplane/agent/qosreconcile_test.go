package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func qosScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func qosNodePtr(s string) *string { return &s }

func TestReconcileQoS_PushesCaps(t *testing.T) {
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:   netv1.LocalObjectReference{Name: "vpc-a"},
			NodeName: qosNodePtr("nodeA"),
			QoS: &netv1.InterfaceQoS{
				Egress:  &netv1.EgressQoS{RateMbps: 100, PublicMbps: 40},
				Ingress: &netv1.RateLimit{RateMbps: 200},
			},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(nic).Build()
	dp := newRecordingDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileQoS(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := dp.getQoS("web-0-nic0")
	if !ok {
		t.Fatalf("ConfigureQoS not called for web-0-nic0; qos=%+v", dp.qos)
	}
	if got.egressMbps != 100 || got.publicMbps != 40 || got.ingressMbps != 200 {
		t.Fatalf("ConfigureQoS caps = (%d,%d,%d), want (100,40,200)", got.egressMbps, got.publicMbps, got.ingressMbps)
	}
}

func TestReconcileQoS_SkipsUnsetAndOffNode(t *testing.T) {
	noCap := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec:       netv1.NetworkInterfaceSpec{VPCRef: netv1.LocalObjectReference{Name: "vpc-a"}, NodeName: qosNodePtr("nodeA")},
	}
	offNode := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:   netv1.LocalObjectReference{Name: "vpc-a"},
			NodeName: qosNodePtr("nodeB"),
			QoS:      &netv1.InterfaceQoS{Egress: &netv1.EgressQoS{RateMbps: 50}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(noCap, offNode).Build()
	dp := newRecordingDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileQoS(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.qos) != 0 {
		t.Fatalf("no qos expected, got %+v", dp.qos)
	}
}

func TestReconcileQoS_ConvergesAndClears(t *testing.T) {
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:   netv1.LocalObjectReference{Name: "vpc-a"},
			NodeName: qosNodePtr("nodeA"),
			QoS:      &netv1.InterfaceQoS{Egress: &netv1.EgressQoS{RateMbps: 100, PublicMbps: 40}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(nic).Build()
	dp := newRecordingDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	for i := 0; i < 2; i++ {
		if err := r.ReconcileQoS(context.Background()); err != nil {
			t.Fatalf("reconcile #%d: %v", i+1, err)
		}
	}
	if n := dp.qosN["web-0-nic0"]; n != 1 {
		t.Fatalf("ConfigureQoS called %d times for unchanged caps, want 1", n)
	}

	nic.Spec.QoS = nil
	if err := cl.Update(context.Background(), nic); err != nil {
		t.Fatal(err)
	}
	if err := r.ReconcileQoS(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := dp.getQoS("web-0-nic0")
	if !ok {
		t.Fatal("ConfigureQoS clear not called")
	}
	if got.egressMbps != 0 || got.publicMbps != 0 || got.ingressMbps != 0 {
		t.Fatalf("clear caps = (%d,%d,%d), want (0,0,0)", got.egressMbps, got.publicMbps, got.ingressMbps)
	}
	if n := dp.qosN["web-0-nic0"]; n != 2 {
		t.Fatalf("ConfigureQoS called %d times total, want 2", n)
	}
}
