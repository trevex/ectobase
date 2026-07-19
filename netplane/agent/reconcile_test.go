package agent

import (
	"context"
	"sort"
	"testing"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ptr[T any](v T) *T { return &v }

func TestDesiredAnnouncesLocalInterfaces(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	// The agent reads CompiledNICs only. A local CompiledNIC (nodeA) is announced; a remote one
	// (nodeB) is not, and — since this node hosts nothing in the remote's VNI here — it happens to
	// share VNI 100, so the subscription set is still {public, 100}.
	local := &netv1.CompiledNIC{}
	local.Name = "default-nic-a"
	local.Namespace = "default"
	local.Spec = netv1.CompiledNICSpec{
		NodeName: "nodeA", NICRef: netv1.LocalObjectReference{Name: "nic-a"}, VNI: 100,
		OverlayIPs: []string{"10.0.0.1"},
	}

	remote := &netv1.CompiledNIC{}
	remote.Name = "default-nic-b"
	remote.Namespace = "default"
	remote.Spec = netv1.CompiledNICSpec{
		NodeName: "nodeB", NICRef: netv1.LocalObjectReference{Name: "nic-b"}, VNI: 100,
		OverlayIPs: []string{"10.0.0.2"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(local, remote).Build()
	r := &Reconciler{client: c, nodeID: "nodeA", underlay: "fd00::a"}

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
	if got.Vni != 100 || got.Prefix != "10.0.0.1/32" || got.Nexthop != "fd00::a" {
		t.Fatalf("announcement = %+v", got)
	}
	_ = sort.Ints // keep import if needed
}
