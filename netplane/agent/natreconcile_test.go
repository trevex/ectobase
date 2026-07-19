package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The agent announces (and programs) NAT only for CompiledNICs scheduled to THIS node. A remote
// CompiledNIC's NAT is ignored here — its owning node announces it and this node learns it off the bus.
func TestDesiredAnnouncesOnlyLocalCompiledNicNat(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	localC := &netv1.CompiledNIC{}
	localC.Name = "default-nic-a"
	localC.Namespace = "default"
	localC.Spec = netv1.CompiledNICSpec{
		NodeName:   "nodeA",
		VNI:        100,
		OverlayIPs: []string{"10.0.0.1"},
		NAT:        []netv1.CompiledNATSource{{SourceIP: "10.0.0.1", NATIP: "1.2.3.4", PortMin: 1024, PortMax: 2048}},
	}

	remoteC := &netv1.CompiledNIC{}
	remoteC.Name = "default-nic-b"
	remoteC.Namespace = "default"
	remoteC.Spec = netv1.CompiledNICSpec{
		NodeName:   "nodeB",
		VNI:        100,
		OverlayIPs: []string{"10.0.0.2"},
		NAT:        []netv1.CompiledNATSource{{SourceIP: "10.0.0.2", NATIP: "1.2.3.4", PortMin: 2048, PortMax: 3072}},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(localC, remoteC).Build()
	dp := newRecordingDP()
	// Only the local source (10.0.0.1) is attached on this node; the remote (10.0.0.2) is not.
	dp.ifaces = []LocalInterface{{InterfaceID: "nic-a", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: c, nodeID: "nodeA", underlay: "fd00::b", dp: dp}

	_, _, blocks, _, _, err := r.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(blocks) != 1 {
		t.Fatalf("want 1 announced NatBlock (local only), got %d: %+v", len(blocks), blocks)
	}
	b := blocks[0]
	if b.SourceIP != "10.0.0.1" || b.NatIP != "1.2.3.4" || b.PortMin != 1024 || b.PortMax != 2048 ||
		b.OwnerUnderlay != "fd00::a" || b.Vni != 100 {
		t.Fatalf("bad announced NatBlock: %+v", b)
	}

	// AddNatSource programmed for the local source only, never the remote one.
	dp.mu.Lock()
	_, remoteProgrammed := dp.natSrc["10.0.0.2"]
	localN := dp.natSrcN["10.0.0.1"]
	dp.mu.Unlock()
	if localN != 1 {
		t.Fatalf("local AddNatSource called %d times, want 1", localN)
	}
	if remoteProgrammed {
		t.Fatalf("remote NAT source 10.0.0.2 must NOT be programmed on nodeA")
	}
}
