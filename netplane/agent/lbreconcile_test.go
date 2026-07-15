package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	rbv1 "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
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

func TestDesired_EmitsVIPAnycastRoute(t *testing.T) {
	s := lbTestScheme(t)
	node := "nodeA"
	// VPC provides VNI resolution via vniFor: use a NIC whose Status.VNI is set so vniFor returns it.
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default"},
		Spec:       netv1.NetworkInterfaceSpec{NodeName: &node, IPs: []string{"10.0.0.20"}},
		Status:     netv1.NetworkInterfaceStatus{VNI: 100, UnderlayRoute: "2001:db8::dd"},
	}
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName: node, NICRef: netv1.LocalObjectReference{Name: "web-0"}, VNI: 100,
			LB: []netv1.CompiledLB{{VIP: "203.0.113.50", Ports: []netv1.CompiledLBPort{{Port: 443, Proto: "TCP"}}}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(nic, cnic).Build()
	r := &Reconciler{client: cl, nodeID: node, underlay: "2001:db8::dd"}

	_, announce, _, err := r.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, rt := range announce {
		if rt.Prefix == "203.0.113.50/32" && rt.Nexthop == "2001:db8::dd" && rt.Vni == 100 && !rt.External {
			found = true
		}
	}
	if !found {
		t.Fatalf("VIP anycast route not emitted; got %+v", announce)
	}
}

func TestReconcileLB_EdgeAddsAndDiffs(t *testing.T) {
	s := lbTestScheme(t)
	lb := &netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "web-lb", Namespace: "default"},
		Spec:       netv1.LoadBalancerSpec{VIP: "203.0.113.50", Ports: []netv1.LoadBalancerPort{{Port: 443, Proto: "TCP"}}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(lb).Build()
	dp := newFakeDP()
	r := &Reconciler{client: cl, nodeID: "edge1", underlay: "2001:db8::e", edgeLoopback: "fd00::1", dp: dp}

	if err := r.ReconcileLB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.lbVips) != 1 || dp.lbVips[0] != "203.0.113.50" {
		t.Fatalf("want AddLbVip 203.0.113.50, got %+v", dp.lbVips)
	}
	// Second reconcile: unchanged → no re-add (create_lb rejects dup ids).
	dp.lbVips = nil
	if err := r.ReconcileLB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.lbVips) != 0 {
		t.Fatalf("steady-state re-added AddLbVip: %+v", dp.lbVips)
	}
}

func TestReconcileLB_V6VIP(t *testing.T) {
	// A v6 VIP flows through the edge AddLbVip path unchanged (id==VIP, family-agnostic).
	s := lbTestScheme(t)
	lb := &netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "web-lb6", Namespace: "default"},
		Spec:       netv1.LoadBalancerSpec{VIP: "2001:db8::a", Ports: []netv1.LoadBalancerPort{{Port: 443, Proto: "TCP"}}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(lb).Build()
	dp := newFakeDP()
	r := &Reconciler{client: cl, nodeID: "edge1", underlay: "2001:db8::e", edgeLoopback: "fd00::1", dp: dp}

	if err := r.ReconcileLB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.lbVips) != 1 || dp.lbVips[0] != "2001:db8::a" {
		t.Fatalf("want AddLbVip 2001:db8::a, got %+v", dp.lbVips)
	}
}

func TestReconcileLB_NonEdgeNoop(t *testing.T) {
	s := lbTestScheme(t)
	lb := &netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "web-lb", Namespace: "default"},
		Spec:       netv1.LoadBalancerSpec{VIP: "203.0.113.50"},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(lb).Build()
	dp := newFakeDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp} // no edgeLoopback
	if err := r.ReconcileLB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.lbVips) != 0 {
		t.Fatalf("non-edge must not AddLbVip: %+v", dp.lbVips)
	}
}

func TestDesiredPublic_EmitsLBVIP(t *testing.T) {
	s := lbTestScheme(t)
	node := "nodeA"
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default"},
		Status:     netv1.NetworkInterfaceStatus{VNI: 100, UnderlayRoute: "2001:db8::dd"},
	}
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName: node, NICRef: netv1.LocalObjectReference{Name: "web-0"}, VNI: 100,
			LB: []netv1.CompiledLB{{VIP: "203.0.113.50"}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(nic, cnic).Build()
	r := &Reconciler{client: cl, nodeID: node, underlay: "2001:db8::dd"}

	recs, err := r.DesiredPublic(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, pp := range recs {
		if pp.Kind == rbv1.PublicKind_PUBLIC_KIND_LB_VIP && pp.Prefix == "203.0.113.50/32" && pp.OwnerUnderlay == "2001:db8::dd" {
			found = true
		}
	}
	if !found {
		t.Fatalf("LB_VIP record not emitted; got %+v", recs)
	}
}
