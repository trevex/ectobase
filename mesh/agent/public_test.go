package agent

import (
	"context"
	"testing"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDesiredPublicEdgeRecord(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(lbTestScheme(t)).Build()
	r := &Reconciler{client: cl, nodeID: "edge1", underlay: "fd00:db8:0:9::e", edgeLoopback: "fd00:db8:0:9::1"}
	pubs, err := r.DesiredPublic(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pubs) != 1 {
		t.Fatalf("want 1 public record, got %d: %+v", len(pubs), pubs)
	}
	p := pubs[0]
	if p.Kind != rbv1.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY {
		t.Errorf("kind = %v, want EDGE_UNDERLAY", p.Kind)
	}
	if p.Prefix != "fd00:db8:0:9::e/128" {
		t.Errorf("prefix = %q, want fd00:db8:0:9::e/128", p.Prefix)
	}
	if p.OwnerUnderlay != "fd00:db8:0:9::1" {
		t.Errorf("owner = %q, want fd00:db8:0:9::1", p.OwnerUnderlay)
	}
	if p.Vni != 0 {
		t.Errorf("vni = %d, want 0", p.Vni)
	}
}

func TestDesiredPublicNonEdgeEmpty(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(lbTestScheme(t)).Build()
	r := &Reconciler{client: cl, nodeID: "nodeA", underlay: "fd00::a"}
	pubs, err := r.DesiredPublic(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pubs) != 0 {
		t.Fatalf("non-edge node must announce no public records, got %+v", pubs)
	}
}

func TestApplyPublicEdgeUnderlayAddThenWithdraw(t *testing.T) {
	b := NewBus("nodeA", "fd00::a", newRecordingDP(), false)

	add := &rbv1.PublicPrefix{
		Kind:          rbv1.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY,
		Prefix:        "fd00:db8:0:9::e/128",
		OwnerUnderlay: "fd00:db8:0:9::1",
	}
	b.applyPublic(context.Background(), add, rbv1.RouteOp_ROUTE_OP_ADD)

	if got := b.LearnedEdge()["fd00:db8:0:9::e"]; got != "fd00:db8:0:9::1" {
		t.Fatalf("learnedEdge[anycast] = %q, want fd00:db8:0:9::1", got)
	}

	b.applyPublic(context.Background(), add, rbv1.RouteOp_ROUTE_OP_WITHDRAW)
	if _, ok := b.LearnedEdge()["fd00:db8:0:9::e"]; ok {
		t.Fatalf("learnedEdge still has anycast entry after withdraw")
	}
}

// TestApplyPublic_LBVIP_SameNodeDistinctOverlayBackendsWithdrawIndependently proves the agent-side
// half of the same-node-multi-backend fix end to end: two LB_VIP ADD updates for the SAME VIP/owner
// but DIFFERENT backend overlay IPs (two pods of one Service on the same node) must both reach
// AddLbBackend, and a WITHDRAW naming one overlay IP must remove only that backend on the dataplane
// — the other must remain.
func TestApplyPublic_LBVIP_SameNodeDistinctOverlayBackendsWithdrawIndependently(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("edge1", "2001:db8::e", dp, true) // isEdge = true
	ctx := context.Background()

	addA := &rbv1.PublicPrefix{
		Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "2001:db8::dd",
		OverlayIp: "10.0.0.5", Vni: 100,
	}
	addB := &rbv1.PublicPrefix{
		Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "2001:db8::dd",
		OverlayIp: "10.0.0.7", Vni: 100,
	}
	b.applyPublic(ctx, addA, rbv1.RouteOp_ROUTE_OP_ADD)
	b.applyPublic(ctx, addB, rbv1.RouteOp_ROUTE_OP_ADD)

	if got := dp.lbBackends["203.0.113.50"]; len(got) != 2 {
		t.Fatalf("both same-node backends must reach AddLbBackend, got %+v", got)
	}

	// Withdraw only the FIRST backend (overlay 10.0.0.5); the second (10.0.0.7) must remain.
	b.applyPublic(ctx, addA, rbv1.RouteOp_ROUTE_OP_WITHDRAW)

	if got := dp.lbBackends["203.0.113.50"]; len(got) != 1 || got[0] != "2001:db8::dd" {
		t.Fatalf("after withdrawing one backend, exactly the other must remain: %+v", got)
	}
	if remaining := dp.lbBackendOverlaysFor("203.0.113.50"); len(remaining) != 1 || remaining[0] != "10.0.0.7" {
		t.Fatalf("the SURVIVING backend must be the 10.0.0.7 one, not 10.0.0.5: %+v", remaining)
	}
}

func TestApplyPublicNatIPIsNoOp(t *testing.T) {
	b := NewBus("nodeA", "fd00::a", newRecordingDP(), false)
	natIP := &rbv1.PublicPrefix{
		Kind:          rbv1.PublicKind_PUBLIC_KIND_NAT_IP,
		Prefix:        "1.2.3.4/32",
		OwnerUnderlay: "fd00::b",
	}
	// Must not panic and must not touch learnedEdge.
	b.applyPublic(context.Background(), natIP, rbv1.RouteOp_ROUTE_OP_ADD)
	if len(b.LearnedEdge()) != 0 {
		t.Fatalf("NAT_IP must not populate learnedEdge, got %+v", b.LearnedEdge())
	}
}
