package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func egScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func hasVNI(vs []uint32, v uint32) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}

func TestDesiredEgressVNIs_NAT(t *testing.T) {
	s := egScheme(t)
	// A local NIC with a NAT allocation (CompiledNIC.NAT non-empty) needs egress: the NATGateway
	// reconciler allocates a block to every source in a gateway's VPC, so this stands in for
	// "the NIC's VPC has a NATGateway and this node hosts a NIC in it".
	cnic := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec: compiledv1.CompiledNICSpec{
			VNI:        100,
			OverlayIPs: []string{"10.0.0.1"},
			NAT:        []compiledv1.CompiledNATSource{{SourceIP: "10.0.0.1", NATIP: "203.0.113.1", PortMin: 1024, PortMax: 2048}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cnic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "nic-0", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	vnis, err := r.desiredEgressVNIs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasVNI(vnis, 100) {
		t.Fatalf("VNI 100 (NIC has a NAT allocation) must need egress, got %v", vnis)
	}
}

func TestDesiredEgressVNIs_LBBackend(t *testing.T) {
	s := egScheme(t)
	cnic := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec: compiledv1.CompiledNICSpec{
			VNI:        200,
			OverlayIPs: []string{"10.0.0.5"},
			LB:         []compiledv1.CompiledLB{{VIP: "203.0.113.5"}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cnic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "nic-0", Vni: 200, OverlayIPs: []string{"10.0.0.5"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}
	vnis, err := r.desiredEgressVNIs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasVNI(vnis, 200) {
		t.Fatalf("VNI 200 (LB backend on this node) must need egress, got %v", vnis)
	}
}

func TestDesiredEgressVNIs_NeitherIsEmpty(t *testing.T) {
	s := egScheme(t)
	// A local NIC with neither a NAT allocation nor LB membership needs no egress.
	cnic := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec:       compiledv1.CompiledNICSpec{VNI: 100, OverlayIPs: []string{"10.0.0.1"}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cnic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "nic-0", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}
	vnis, err := r.desiredEgressVNIs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(vnis) != 0 {
		t.Fatalf("no NAT + no LB backend => no egress VNIs, got %v", vnis)
	}
}
