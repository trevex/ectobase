package agent

import (
	"context"
	"sort"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ptr[T any](v T) *T { return &v }

func TestDesiredAnnouncesLocalInterfaces(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	// Overlay host routes are announced from the LOCAL dataplane's attached interfaces (node-local
	// state), with the dataplane-reported underlay as the nexthop. A remote node's interfaces are not
	// reported here, so only the local one is announced.
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "nic-a", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: c, nodeID: "nodeA", underlay: "fd00::b", dp: dp}

	subs, ann, _, _, _, err := r.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Every node always subscribes to the public VNI (0) to learn the external defaults,
	// in addition to the VNIs it hosts.
	if len(subs) != 2 || subs[0] != PublicVNI || subs[1] != 100 {
		t.Fatalf("subs = %v, want [0 100]", subs)
	}
	if len(ann) != 1 {
		t.Fatalf("want 1 local announcement, got %d: %+v", len(ann), ann)
	}
	got := ann[0]
	// Nexthop is the dataplane-reported underlay (fd00::a), NOT the node underlay (fd00::b).
	if got.Vni != 100 || got.Prefix != "10.0.0.1/32" || got.Nexthop != "fd00::a" {
		t.Fatalf("announcement = %+v", got)
	}
	_ = sort.Ints // keep import if needed
}
