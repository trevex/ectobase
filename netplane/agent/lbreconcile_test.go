package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func lbTestScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDesiredLB_JoinsUnderlayFromNIC(t *testing.T) {
	s := lbTestScheme(t)
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName: "nodeA",
			NICRef:   netv1.LocalObjectReference{Name: "web-0"},
			VNI:      100,
			LB:       []netv1.CompiledLB{{VIP: "203.0.113.50", Ports: []netv1.CompiledLBPort{{Port: 443, Proto: "TCP"}}}},
		},
	}
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default"},
		Status:     netv1.NetworkInterfaceStatus{UnderlayRoute: "2001:db8::dd"},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cnic, nic).Build()
	r := &Reconciler{client: cl, nodeID: "nodeA"}

	got, err := r.desiredLB(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 lbBacking, got %d", len(got))
	}
	if got[0].VIP != "203.0.113.50" || got[0].Vni != 100 || got[0].NicUnderlay != "2001:db8::dd" {
		t.Fatalf("lbBacking = %+v", got[0])
	}
	if len(got[0].Ports) != 1 || got[0].Ports[0].Port != 443 || got[0].Ports[0].Proto != 6 {
		t.Fatalf("ports = %+v, want [{443 6}]", got[0].Ports)
	}
}

func TestDesiredLB_SkipsWhenNoUnderlay(t *testing.T) {
	s := lbTestScheme(t)
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName: "nodeA", NICRef: netv1.LocalObjectReference{Name: "web-0"}, VNI: 100,
			LB: []netv1.CompiledLB{{VIP: "203.0.113.50"}},
		},
	}
	nic := &netv1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cnic, nic).Build()
	r := &Reconciler{client: cl, nodeID: "nodeA"}
	got, err := r.desiredLB(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 (no underlay allocated yet), got %d", len(got))
	}
}
