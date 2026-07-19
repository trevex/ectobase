package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReconcileProgramsLocalNatSourceAndStagesAnnounce(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	// A local CompiledNIC on nodeA carries the central NAT allocation; the source's node-local
	// underlay comes from the dataplane's attached-interface list and is used as the block owner.
	cnic := &netv1.CompiledNIC{}
	cnic.Name = "default-nic-a"
	cnic.Namespace = "default"
	cnic.Spec = netv1.CompiledNICSpec{
		NodeName:   "nodeA",
		VNI:        100,
		OverlayIPs: []string{"10.0.0.1"},
		NAT: []netv1.CompiledNATSource{
			{SourceIP: "10.0.0.1", NATIP: "203.0.113.1", PortMin: 1024, PortMax: 2048},
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
	if call.vni != 100 || call.src != "10.0.0.1" || call.nat != "203.0.113.1" || call.portMin != 1024 || call.portMax != 2048 {
		t.Fatalf("AddNatSource args = %+v", call)
	}

	// One NatBlock staged for announcement, owned by this node's underlay.
	if len(blocks) != 1 {
		t.Fatalf("want 1 staged NatBlock, got %d: %+v", len(blocks), blocks)
	}
	if blocks[0].OwnerUnderlay != "fd00::a" || blocks[0].NatIP != "203.0.113.1" ||
		blocks[0].SourceIP != "10.0.0.1" || blocks[0].Vni != 100 ||
		blocks[0].PortMin != 1024 || blocks[0].PortMax != 2048 {
		t.Fatalf("bad staged NatBlock: %+v", blocks[0])
	}
}
