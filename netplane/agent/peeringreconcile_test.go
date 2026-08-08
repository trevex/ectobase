package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestReconcilePass_IncludesPeeringImportsAndSubs verifies that the reconcile pass wires
// desiredPeeringImports into the assembled DesiredState: the returned PeeringImports map is
// populated and every peer VNI is included in the Subs slice so the Bus subscribes to it.
func TestReconcilePass_IncludesPeeringImportsAndSubs(t *testing.T) {
	s := egScheme(t)
	// CompiledNIC on this node: VNI 100, peers with VNI 200 for prefix "10.1.0.0/24".
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-0"},
		Spec: netv1.CompiledNICSpec{
			NodeName: "nodeA", VNI: 100,
			PeerImports: []netv1.CompiledPeerImport{{PeerVNI: 200, ImportPrefixes: []string{"10.1.0.0/24"}}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cnic).Build()
	r := &Reconciler{client: cl, nodeID: "nodeA", underlay: "fd00::a"}

	subs, _, _, _, peeringImports, err := r.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	// PeeringImports must carry VNI 100 -> [{PeerVNI:200, ImportPrefixes:["10.1.0.0/24"]}].
	imps, ok := peeringImports[100]
	if !ok || len(imps) != 1 {
		t.Fatalf("expected PeeringImports[100] with 1 entry, got %+v", peeringImports)
	}
	if imps[0].PeerVNI != 200 {
		t.Fatalf("expected PeerVNI 200, got %d", imps[0].PeerVNI)
	}
	if len(imps[0].ImportPrefixes) != 1 || imps[0].ImportPrefixes[0] != "10.1.0.0/24" {
		t.Fatalf("unexpected ImportPrefixes: %v", imps[0].ImportPrefixes)
	}
	// Peer VNI 200 must appear in subs so the Bus subscribes to it on routebus.
	if !hasVNI(subs, 200) {
		t.Fatalf("peer VNI 200 must be in subs, got %v", subs)
	}
}

func TestDesiredPeeringImports(t *testing.T) {
	s := egScheme(t) // reuse scheme helper from importreconcile_test.go
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-0"},
		Spec: netv1.CompiledNICSpec{
			NodeName: "nodeA", VNI: 100,
			PeerImports: []netv1.CompiledPeerImport{{PeerVNI: 200, ImportPrefixes: []string{"10.1.0.0/24"}}},
		},
	}
	offNode := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-1"},
		Spec: netv1.CompiledNICSpec{NodeName: "nodeB", VNI: 300,
			PeerImports: []netv1.CompiledPeerImport{{PeerVNI: 400}}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cnic, offNode).Build()
	r := &Reconciler{client: cl, nodeID: "nodeA"}
	got, err := r.desiredPeeringImports(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[100]) != 1 || got[100][0].PeerVNI != 200 {
		t.Fatalf("unexpected imports: %+v", got)
	}
	if len(got[100][0].ImportPrefixes) != 1 || got[100][0].ImportPrefixes[0] != "10.1.0.0/24" {
		t.Fatalf("prefixes not carried: %+v", got[100][0])
	}
}
