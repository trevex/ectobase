package agent

import (
	"context"
	"sort"
	"testing"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ptr[T any](v T) *T { return &v }

func TestDesiredAnnouncesLocalInterfaces(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpc := &netv1.VPC{}
	vpc.Name = "blue"
	vpc.Namespace = "default"
	vpc.Status.VNI = 100

	local := &netv1.NetworkInterface{}
	local.Name = "nic-a"
	local.Namespace = "default"
	local.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	local.Spec.NodeName = ptr("nodeA")
	local.Spec.IPs = []string{"10.0.0.1"}
	local.Status.VNI = 100

	remote := &netv1.NetworkInterface{}
	remote.Name = "nic-b"
	remote.Namespace = "default"
	remote.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	remote.Spec.NodeName = ptr("nodeB") // NOT ours
	remote.Spec.IPs = []string{"10.0.0.2"}
	remote.Status.VNI = 100

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, local, remote).Build()
	r := &Reconciler{client: c, nodeID: "nodeA", underlay: "fd00::a"}

	subs, ann, _, _, err := r.Desired(context.Background())
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
