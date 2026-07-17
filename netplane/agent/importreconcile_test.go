package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func egScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
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

func TestDesiredEgressVNIs_NATGateway(t *testing.T) {
	s := egScheme(t)
	node := "nodeA"
	vpc := &netv1.VPC{ObjectMeta: metav1.ObjectMeta{Name: "blue", Namespace: "default"}, Status: netv1.VPCStatus{VNI: 100}}
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default"},
		Spec:       netv1.NetworkInterfaceSpec{VPCRef: netv1.LocalObjectReference{Name: "blue"}, NodeName: &node},
		Status:     netv1.NetworkInterfaceStatus{VNI: 100},
	}
	gw := &netv1.NATGateway{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"}, Spec: netv1.NATGatewaySpec{VPCRef: netv1.LocalObjectReference{Name: "blue"}}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(vpc, nic, gw).Build()
	r := &Reconciler{client: cl, nodeID: node}

	vnis, err := r.desiredEgressVNIs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasVNI(vnis, 100) {
		t.Fatalf("VNI 100 (NATGateway-VPC, hosted here) must need egress, got %v", vnis)
	}
}

func TestDesiredEgressVNIs_LBBackend(t *testing.T) {
	s := egScheme(t)
	node := "nodeA"
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName: node, NICRef: netv1.LocalObjectReference{Name: "web-0"}, VNI: 200,
			LB: []netv1.CompiledLB{{VIP: "203.0.113.5"}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cnic).Build()
	r := &Reconciler{client: cl, nodeID: node}
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
	node := "nodeA"
	vpc := &netv1.VPC{ObjectMeta: metav1.ObjectMeta{Name: "blue", Namespace: "default"}, Status: netv1.VPCStatus{VNI: 100}}
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default"},
		Spec:       netv1.NetworkInterfaceSpec{VPCRef: netv1.LocalObjectReference{Name: "blue"}, NodeName: &node},
		Status:     netv1.NetworkInterfaceStatus{VNI: 100},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(vpc, nic).Build()
	r := &Reconciler{client: cl, nodeID: node}
	vnis, err := r.desiredEgressVNIs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(vnis) != 0 {
		t.Fatalf("no NATGateway + no LB backend => no egress VNIs, got %v", vnis)
	}
}
