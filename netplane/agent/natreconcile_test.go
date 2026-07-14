package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestDesiredExternalRoutesGatedOnEdgeLoopback checks that the external default
// is originated based on the agent's edge-loopback IDENTITY (--edge-loopback),
// NOT on NATGateway.Spec.EdgeUnderlay (deprecated/ignored).
func TestDesiredExternalRoutesGatedOnEdgeLoopback(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	vpc := &netv1.VPC{}
	vpc.Name = "blue"
	vpc.Namespace = "default"
	vpc.Status.VNI = 100

	// Bogus EdgeUnderlay: proves the routing decision does NOT read this field.
	gw := &netv1.NATGateway{}
	gw.Name = "gw"
	gw.Namespace = "default"
	gw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	gw.Spec.EdgeUnderlay = "fd00:bogus::1"

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, gw).Build()

	// Not an edge (empty edge-loopback): originate nothing, regardless of NATGateways.
	nonEdge, err := DesiredExternalRoutes(context.Background(), c, "fd00::a", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(nonEdge) != 0 {
		t.Fatalf("non-edge (empty edgeLoopback) must originate nothing, got %+v", nonEdge)
	}

	// Edge (edge-loopback set): originate 0.0.0.0/0 + NAT64 for VNI 100 with
	// nexthop == the edge's own underlay (anycast), despite the bogus EdgeUnderlay.
	routes, err := DesiredExternalRoutes(context.Background(), c, "fd00::a", "fd00:lo::1")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("edge must originate exactly the v4 + NAT64 defaults, got %+v", routes)
	}
	v4 := findExternalRoute(routes, "0.0.0.0/0")
	if v4 == nil || v4.Vni != 100 || v4.Nexthop != "fd00::a" || !v4.External {
		t.Fatalf("bad v4 external default: %+v", routes)
	}
	v6 := findExternalRoute(routes, nat64WellKnownPrefix)
	if v6 == nil || v6.Vni != 100 || v6.Nexthop != "fd00::a" || !v6.External {
		t.Fatalf("bad NAT64 external default: %+v", routes)
	}
}

func TestDesiredNatPicksLocalSourcesAndAnnouncesThem(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	vpc := &netv1.VPC{}
	vpc.Name = "blue"
	vpc.Namespace = "default"
	vpc.Status.VNI = 100

	// Local NIC (source 10.0.0.1 scheduled to nodeA).
	local := &netv1.NetworkInterface{}
	local.Name = "nic-a"
	local.Namespace = "default"
	local.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	local.Spec.NodeName = ptr("nodeA")
	local.Spec.IPs = []string{"10.0.0.1"}
	local.Status.VNI = 100

	// Remote NIC (source 10.0.0.2 scheduled to nodeB).
	remote := &netv1.NetworkInterface{}
	remote.Name = "nic-b"
	remote.Namespace = "default"
	remote.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	remote.Spec.NodeName = ptr("nodeB")
	remote.Spec.IPs = []string{"10.0.0.2"}
	remote.Status.VNI = 100

	gw := &netv1.NATGateway{}
	gw.Name = "gw"
	gw.Namespace = "default"
	gw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	gw.Status.Allocations = []netv1.NATAllocation{
		{Source: "10.0.0.1", PublicIP: "1.2.3.4", PortMin: 1024, PortMax: 2048},
		{Source: "10.0.0.2", PublicIP: "1.2.3.4", PortMin: 2048, PortMax: 3072},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, local, remote, gw).Build()

	sources, blocks, err := DesiredNat(context.Background(), c, "nodeA", "fd00::a")
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 {
		t.Fatalf("want 1 LOCAL NatSource, got %d: %+v", len(sources), sources)
	}
	s := sources[0]
	if s.Vni != 100 || s.SourceIP != "10.0.0.1" || s.NatIP != "1.2.3.4" || s.PortMin != 1024 || s.PortMax != 2048 {
		t.Fatalf("bad local NatSource: %+v", s)
	}
	if len(blocks) != 1 {
		t.Fatalf("want 1 announced NatBlock (local only), got %d: %+v", len(blocks), blocks)
	}
	b := blocks[0]
	if b.SourceIP != "10.0.0.1" || b.NatIP != "1.2.3.4" || b.PortMin != 1024 || b.PortMax != 2048 ||
		b.OwnerUnderlay != "fd00::a" || b.Vni != 100 {
		t.Fatalf("bad announced NatBlock: %+v", b)
	}
}
