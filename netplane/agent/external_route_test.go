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

func TestDesiredExternalRoutesEdgeIntoPublicVNI(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	// No VPC/NATGateway/LoadBalancer objects at all: the edge is tenant-agnostic.
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	routes, err := DesiredExternalRoutes(context.Background(), c, "fd00::e", "fd00:lo::1")
	if err != nil {
		t.Fatal(err)
	}
	// Every route is originated into the public VNI (0), nexthop = the edge's own underlay.
	for _, want := range []string{"0.0.0.0/0", "64:ff9b::/96", "::/0"} {
		r := findExternalRoute(routes, want)
		if r == nil {
			t.Fatalf("want %s originated, got %+v", want, routes)
		}
		if r.Vni != PublicVNI || r.Nexthop != "fd00::e" || !r.External {
			t.Fatalf("bad public-VNI route %s: %+v", want, *r)
		}
	}
}

func TestDesiredExternalRoutesNonEdgeStagesNothing(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
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

	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Edge node (identified by its edge-loopback, not NATGateway.EdgeUnderlay).
	edge := &Reconciler{client: c, nodeID: "edge", underlay: "fd00::e", edgeLoopback: "fd00:lo::1"}
	subs, announce, _, _, err := edge.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if findRoute(announce, "0.0.0.0/0") == nil || findRoute(announce, "64:ff9b::/96") == nil {
		t.Fatalf("edge Desired() must stage the external default routes, got %+v", announce)
	}
	if r := findRoute(announce, "0.0.0.0/0"); !r.External || r.Nexthop != "fd00::e" || r.Vni != PublicVNI {
		t.Fatalf("bad staged external default: %+v", *r)
	}
	if !containsVNI(subs, PublicVNI) {
		t.Fatalf("edge must subscribe to the public VNI, subs=%v", subs)
	}

	// Non-edge node.
	other := &Reconciler{client: c, nodeID: "other", underlay: "fd00::b"}
	_, announce2, _, _, err := other.Desired(context.Background())
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
