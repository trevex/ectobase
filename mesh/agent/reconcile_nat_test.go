package agent

import (
	"context"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReconcileProgramsLocalNatSourceAndStagesAnnounce(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	// A local CompiledNIC carries the central NAT allocation; "local" is determined by the
	// dataplane's ListInterfaces matching (VNI, overlayIP) — not by a nodeName field.
	// The source's node-local underlay comes from the dataplane and is used as the block owner.
	cnic := &compiledv1.CompiledNIC{}
	cnic.Name = "default-nic-a"
	cnic.Namespace = "default"
	cnic.Spec = compiledv1.CompiledNICSpec{
		VNI:        100,
		OverlayIPs: []string{"10.0.0.1"},
		// PortMax is INCLUSIVE here, as the central allocator writes it (portMin + size - 1, so a
		// 1024-port block starting at 1024 ends at 2047). The dataplane's port_max is EXCLUSIVE,
		// so the agent is where the two conventions meet.
		NAT: []compiledv1.CompiledNATSource{
			{SourceIP: "10.0.0.1", NATIP: "203.0.113.1", PortMin: 1024, PortMax: 2047},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cnic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "nic-a", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: c, nodeID: "nodeA", underlay: "fd00::b", dp: dp}

	_, _, blocks, _, _, err := r.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// AddNatSource programmed exactly once with the expected args.
	dp.mu.Lock()
	n := dp.natSrcN["10.0.0.1"]
	call, ok := dp.natSrc["10.0.0.1"]
	dp.mu.Unlock()
	if !ok || n != 1 {
		t.Fatalf("AddNatSource for 10.0.0.1 called %d times (want 1), ok=%v", n, ok)
	}
	// 2047 inclusive becomes 2048 exclusive: the whole allocated block is usable. Passing it
	// through unconverted would hand the datapath [1024, 2047) and silently lose port 2047.
	if call.vni != 100 || call.src != "10.0.0.1" || call.nat != "203.0.113.1" || call.portMin != 1024 || call.portMax != 2048 {
		t.Fatalf("AddNatSource args = %+v", call)
	}

	// One NatBlock staged for announcement, owned by this node's underlay.
	if len(blocks) != 1 {
		t.Fatalf("want 1 staged NatBlock, got %d: %+v", len(blocks), blocks)
	}
	// The announced block carries the same exclusive range the local dataplane got: a peer's
	// NAT_OWNERS entry has to cover exactly the ports this node will SNAT onto, or returns for
	// the ports they disagree about are relayed to nobody.
	if blocks[0].OwnerUnderlay != "fd00::a" || blocks[0].NatIP != "203.0.113.1" ||
		blocks[0].SourceIP != "10.0.0.1" || blocks[0].Vni != 100 ||
		blocks[0].PortMin != 1024 || blocks[0].PortMax != 2048 {
		t.Fatalf("bad staged NatBlock: %+v", blocks[0])
	}
}

// A one-port block is the degenerate case of the inclusive/exclusive conversion: the allocator
// writes portMin == portMax, and passing that through unconverted gives the dataplane an EMPTY
// range, which it refuses as InvalidArgument — so portsPerSource: 1 would program nothing at all.
func TestReconcileMakesAOnePortBlockUsable(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	cnic := &compiledv1.CompiledNIC{}
	cnic.Name = "default-nic-a"
	cnic.Namespace = "default"
	cnic.Spec = compiledv1.CompiledNICSpec{
		VNI:        100,
		OverlayIPs: []string{"10.0.0.1"},
		NAT: []compiledv1.CompiledNATSource{
			{SourceIP: "10.0.0.1", NATIP: "203.0.113.1", PortMin: 5000, PortMax: 5000},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cnic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "nic-a", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: c, nodeID: "nodeA", underlay: "fd00::b", dp: dp}

	_, _, blocks, _, _, err := r.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	dp.mu.Lock()
	call, ok := dp.natSrc["10.0.0.1"]
	dp.mu.Unlock()
	if !ok {
		t.Fatal("AddNatSource was not called for a one-port block")
	}
	if call.portMin != 5000 || call.portMax != 5001 {
		t.Fatalf("AddNatSource got [%d,%d), want [5000,5001)", call.portMin, call.portMax)
	}
	if len(blocks) != 1 || blocks[0].PortMin != 5000 || blocks[0].PortMax != 5001 {
		t.Fatalf("bad staged NatBlock: %+v", blocks)
	}
}
