package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

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
