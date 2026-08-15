package agent

import (
	"context"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func qosScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

// makeCompiledNIC builds a minimal CompiledNIC for QoS tests.
func makeCompiledNIC(name string, vni int32, ips []string, qos *compiledv1.CompiledQoS) *compiledv1.CompiledNIC {
	return &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: compiledv1.CompiledNICSpec{
			VNI:        vni,
			OverlayIPs: ips,
			QoS:        qos,
		},
	}
}

func TestReconcileQoS_PushesCaps(t *testing.T) {
	// QoS locality is determined by (VNI, overlayIP) matching dp.ifaces, not by nodeName.
	cnic := makeCompiledNIC("default-web-0-nic0", 100, []string{"10.0.0.1"}, &compiledv1.CompiledQoS{
		EgressMbps:  100,
		PublicMbps:  40,
		IngressMbps: 200,
	})
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(cnic).Build()
	dp := newRecordingDP()
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

func TestReconcileQoS_SkipsUnsetAndOffNode(t *testing.T) {
	// noCap: locally attached (VNI 100 / 10.0.0.1 in dp.ifaces) but no QoS set → skip.
	noCap := makeCompiledNIC("default-web-0-nic0", 100, []string{"10.0.0.1"}, nil)
	// offNode: QoS set but (VNI, IP) NOT in dp.ifaces → treated as not local, skip.
	offNode := makeCompiledNIC("default-web-1-nic0", 200, []string{"10.0.0.2"}, &compiledv1.CompiledQoS{
		EgressMbps: 50,
	})
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
	cnic := makeCompiledNIC("default-web-0-nic0", 100, []string{"10.0.0.1"}, &compiledv1.CompiledQoS{
		EgressMbps: 100,
		PublicMbps: 40,
	})
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(cnic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "web-0-nic0", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	// Two reconcile passes with unchanged QoS: ConfigureQoS must be called only once.
	for i := 0; i < 2; i++ {
		if err := r.ReconcileQoS(context.Background()); err != nil {
			t.Fatalf("reconcile #%d: %v", i+1, err)
		}
	}
	if n := dp.qosN["web-0-nic0"]; n != 1 {
		t.Fatalf("ConfigureQoS called %d times for unchanged caps, want 1", n)
	}

	// Clear QoS on the CompiledNIC → agent must push 0/0/0.
	cnic.Spec.QoS = nil
	if err := cl.Update(context.Background(), cnic); err != nil {
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

func TestReconcileQoS_VNIOverlapSafe(t *testing.T) {
	// Two NICs with the same overlay IP but different VNIs: only the locally-attached one (VNI 100)
	// gets QoS programmed; the other (VNI 200) is on a different node.
	local := makeCompiledNIC("ns-a-nic0", 100, []string{"10.0.0.1"}, &compiledv1.CompiledQoS{EgressMbps: 100})
	remote := makeCompiledNIC("ns-b-nic0", 200, []string{"10.0.0.1"}, &compiledv1.CompiledQoS{EgressMbps: 50})
	cl := fake.NewClientBuilder().WithScheme(qosScheme(t)).WithObjects(local, remote).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "a-nic0", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileQoS(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Only the VNI-100 interface gets programmed.
	if _, ok := dp.getQoS("a-nic0"); !ok {
		t.Fatal("expected QoS on a-nic0 (VNI 100)")
	}
	if len(dp.qos) != 1 {
		t.Fatalf("expected exactly 1 QoS call, got %d: %+v", len(dp.qos), dp.qos)
	}
	got, _ := dp.getQoS("a-nic0")
	if got.egressMbps != 100 {
		t.Fatalf("egressMbps = %d, want 100", got.egressMbps)
	}
}
