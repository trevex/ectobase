package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// findExternalRoute returns the route with the given prefix, or nil.
func findExternalRoute(routes []ExternalRoute, prefix string) *ExternalRoute {
	for i := range routes {
		if routes[i].Prefix == prefix {
			return &routes[i]
		}
	}
	return nil
}

func TestDesiredExternalRoutesEdgeAnnouncesDefault(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	vpc := &netv1.VPC{}
	vpc.Name = "blue"
	vpc.Namespace = "default"
	vpc.Status.VNI = 100

	// EdgeUnderlay is deliberately left empty/bogus: it is deprecated and MUST be
	// ignored; edge role is decided by the edge-loopback identity, not this field.
	gw := &netv1.NATGateway{}
	gw.Name = "gw"
	gw.Namespace = "default"
	gw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, gw).Build()

	// This node IS the edge (edge-loopback set): it originates the external default
	// with nexthop = its own underlay (anycast).
	routes, err := DesiredExternalRoutes(context.Background(), c, "fd00::e", "fd00:lo::1")
	if err != nil {
		t.Fatal(err)
	}

	v4 := findExternalRoute(routes, "0.0.0.0/0")
	if v4 == nil {
		t.Fatalf("want an external default 0.0.0.0/0 route, got %+v", routes)
	}
	if v4.Vni != 100 || v4.Nexthop != "fd00::e" || !v4.External {
		t.Fatalf("bad v4 external default route: %+v", *v4)
	}

	v6 := findExternalRoute(routes, "64:ff9b::/96")
	if v6 == nil {
		t.Fatalf("want a NAT64 external 64:ff9b::/96 route, got %+v", routes)
	}
	if v6.Vni != 100 || v6.Nexthop != "fd00::e" || !v6.External {
		t.Fatalf("bad v6 NAT64 external route: %+v", *v6)
	}
}

// A LoadBalancer with NO NATGateway must still make the edge originate the external default for its
// VPC's VNI, so DSR replies (source = the public VIP, un-SNAT'd) can egress. No NAT64 for LB.
func TestDesiredExternalRoutesLoadBalancerDSR(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpc := &netv1.VPC{}
	vpc.Name = "blue"
	vpc.Namespace = "default"
	vpc.Status.VNI = 100

	lb := &netv1.LoadBalancer{}
	lb.Name = "web-lb"
	lb.Namespace = "default"
	lb.Spec.VIP = "203.0.113.5"
	lb.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	lb.Spec.Ports = []netv1.LoadBalancerPort{{Port: 80, Proto: "TCP"}}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, lb).Build()

	routes, err := DesiredExternalRoutes(context.Background(), c, "fd00::e", "fd00:lo::1")
	if err != nil {
		t.Fatal(err)
	}
	v4 := findExternalRoute(routes, "0.0.0.0/0")
	if v4 == nil {
		t.Fatalf("LoadBalancer must make the edge originate 0.0.0.0/0 for DSR return, got %+v", routes)
	}
	if v4.Vni != 100 || v4.Nexthop != "fd00::e" || !v4.External {
		t.Fatalf("bad LB external default: %+v", *v4)
	}
	// No NAT64 prefix for an LB-only VNI (DSR is same-family).
	if findExternalRoute(routes, "64:ff9b::/96") != nil {
		t.Fatalf("LB-only VNI must not originate the NAT64 prefix, got %+v", routes)
	}
}

func TestDesiredExternalRoutesNonEdgeStagesNothing(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	vpc := &netv1.VPC{}
	vpc.Name = "blue"
	vpc.Namespace = "default"
	vpc.Status.VNI = 100

	gw := &netv1.NATGateway{}
	gw.Name = "gw"
	gw.Namespace = "default"
	gw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, gw).Build()

	// This node is NOT the edge (empty edge-loopback): it announces nothing.
	routes, err := DesiredExternalRoutes(context.Background(), c, "fd00::b", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatalf("non-edge node must stage no external routes, got %+v", routes)
	}
}

// TestReconcileEdgeStagesExternalDefault checks the reconciler wiring: an edge
// node's Desired() includes the external default in its announce set (and
// subscribes to the VNI), while a non-edge node does not.
func TestReconcileEdgeStagesExternalDefault(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	vpc := &netv1.VPC{}
	vpc.Name = "blue"
	vpc.Namespace = "default"
	vpc.Status.VNI = 100

	gw := &netv1.NATGateway{}
	gw.Name = "gw"
	gw.Namespace = "default"
	gw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, gw).Build()

	// Edge node (identified by its edge-loopback, not NATGateway.EdgeUnderlay).
	edge := &Reconciler{client: c, nodeID: "edge", underlay: "fd00::e", edgeLoopback: "fd00:lo::1"}
	subs, announce, _, err := edge.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if findRoute(announce, "0.0.0.0/0") == nil || findRoute(announce, "64:ff9b::/96") == nil {
		t.Fatalf("edge Desired() must stage the external default routes, got %+v", announce)
	}
	if r := findRoute(announce, "0.0.0.0/0"); !r.External || r.Nexthop != "fd00::e" || r.Vni != 100 {
		t.Fatalf("bad staged external default: %+v", *r)
	}
	if !containsVNI(subs, 100) {
		t.Fatalf("edge must subscribe to the originated VNI 100, subs=%v", subs)
	}

	// Non-edge node.
	other := &Reconciler{client: c, nodeID: "other", underlay: "fd00::b"}
	_, announce2, _, err := other.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if findRoute(announce2, "0.0.0.0/0") != nil || findRoute(announce2, "64:ff9b::/96") != nil {
		t.Fatalf("non-edge Desired() must NOT stage external routes, got %+v", announce2)
	}
}

func findRoute(routes []Route, prefix string) *Route {
	for i := range routes {
		if routes[i].Prefix == prefix {
			return &routes[i]
		}
	}
	return nil
}

func containsVNI(vnis []uint32, v uint32) bool {
	for _, x := range vnis {
		if x == v {
			return true
		}
	}
	return false
}
