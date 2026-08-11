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

func TestReconcileQoS_PushesCaps(t *testing.T) {
	// QoS locality is determined by (VNI, overlayIP) matching dp.ifaces, not by nodeName.
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef: netv1.LocalObjectReference{Name: "vpc-a"},
			IPs:    []string{"10.0.0.1"},
			QoS: &netv1.InterfaceQoS{
				Egress:  &netv1.EgressQoS{RateMbps: 100, PublicMbps: 40},
				Ingress: &netv1.RateLimit{RateMbps: 200},
			},
		},
		Status: netv1.NetworkInterfaceStatus{VNI: 100},
	}
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(nic).Build()
	dp := newRecordingDP()
	// Make the NIC locally attached by having the dataplane report its (VNI, IP).
	dp.ifaces = []LocalInterface{{InterfaceID: "web-0-nic0", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
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

func TestReconcileQoS_ResolvesVNIFromVPC(t *testing.T) {
	// nic.Status.VNI is unset (as in production — no controller writes it). The effective VNI must
	// resolve through the referenced VPC's status.vni (=100), matching the locally-attached interface.
	vpc := &netv1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "vpc-a", Namespace: "default"},
		Status:     netv1.VPCStatus{VNI: 100},
	}
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef: netv1.LocalObjectReference{Name: "vpc-a"},
			IPs:    []string{"10.0.0.1"},
			QoS: &netv1.InterfaceQoS{
				Egress:  &netv1.EgressQoS{RateMbps: 100, PublicMbps: 40},
				Ingress: &netv1.RateLimit{RateMbps: 200},
			},
		},
		// Status.VNI intentionally zero — resolution must come from the VPC.
	}
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(vpc, nic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "web-0-nic0", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileQoS(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := dp.getQoS("web-0-nic0")
	if !ok {
		t.Fatalf("ConfigureQoS not called for web-0-nic0 (VNI should resolve from VPC); qos=%+v", dp.qos)
	}
	if got.egressMbps != 100 || got.publicMbps != 40 || got.ingressMbps != 200 {
		t.Fatalf("ConfigureQoS caps = (%d,%d,%d), want (100,40,200)", got.egressMbps, got.publicMbps, got.ingressMbps)
	}
}

func TestReconcileQoS_SkipsWhenVNIUnresolvable(t *testing.T) {
	// No VPC object and status.vni==0 → effective VNI stays 0 → NIC is skipped even though a
	// same-named interface is locally attached (its real VNI can't be matched).
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef: netv1.LocalObjectReference{Name: "vpc-missing"},
			IPs:    []string{"10.0.0.1"},
			QoS:    &netv1.InterfaceQoS{Egress: &netv1.EgressQoS{RateMbps: 100}},
		},
		// Status.VNI zero, VPC absent.
	}
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(nic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "web-0-nic0", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileQoS(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.qos) != 0 {
		t.Fatalf("no qos expected when VNI is unresolvable, got %+v", dp.qos)
	}
}

func TestReconcileQoS_SkipsUnsetAndOffNode(t *testing.T) {
	// noCap: locally attached (VNI 100 / 10.0.0.1 in dp.ifaces) but no QoS set → skip.
	noCap := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec:       netv1.NetworkInterfaceSpec{VPCRef: netv1.LocalObjectReference{Name: "vpc-a"}, IPs: []string{"10.0.0.1"}},
		Status:     netv1.NetworkInterfaceStatus{VNI: 100},
	}
	// offNode: QoS set but (VNI, IP) NOT in dp.ifaces → treated as not local, skip.
	offNode := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1-nic0", Namespace: "default"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef: netv1.LocalObjectReference{Name: "vpc-a"},
			IPs:    []string{"10.0.0.2"},
			QoS:    &netv1.InterfaceQoS{Egress: &netv1.EgressQoS{RateMbps: 50}},
		},
		Status: netv1.NetworkInterfaceStatus{VNI: 200},
	}
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(noCap, offNode).Build()
	dp := newRecordingDP()
	// Only noCap (VNI 100 / 10.0.0.1) is locally attached; offNode is not.
	dp.ifaces = []LocalInterface{{InterfaceID: "web-0-nic0", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
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
			VPCRef: netv1.LocalObjectReference{Name: "vpc-a"},
			IPs:    []string{"10.0.0.1"},
			QoS:    &netv1.InterfaceQoS{Egress: &netv1.EgressQoS{RateMbps: 100, PublicMbps: 40}},
		},
		Status: netv1.NetworkInterfaceStatus{VNI: 100},
	}
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(nic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "web-0-nic0", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
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
