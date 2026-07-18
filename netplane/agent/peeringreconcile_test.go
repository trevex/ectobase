package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

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
