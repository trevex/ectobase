package agent

import (
	"testing"

	rbv1 "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
)

func TestDesiredPublicEdgeRecord(t *testing.T) {
	r := &Reconciler{underlay: "fd00:db8:0:9::e", edgeLoopback: "fd00:db8:0:9::1"}
	pubs := r.DesiredPublic()
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
	r := &Reconciler{underlay: "fd00::a"}
	if pubs := r.DesiredPublic(); len(pubs) != 0 {
		t.Fatalf("non-edge node must announce no public records, got %+v", pubs)
	}
}

func TestApplyPublicEdgeUnderlayAddThenWithdraw(t *testing.T) {
	b := NewBus("nodeA", "fd00::a", newFakeDP())

	add := &rbv1.PublicPrefix{
		Kind:          rbv1.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY,
		Prefix:        "fd00:db8:0:9::e/128",
		OwnerUnderlay: "fd00:db8:0:9::1",
	}
	b.applyPublic(add, rbv1.RouteOp_ROUTE_OP_ADD)

	if got := b.LearnedEdge()["fd00:db8:0:9::e"]; got != "fd00:db8:0:9::1" {
		t.Fatalf("learnedEdge[anycast] = %q, want fd00:db8:0:9::1", got)
	}

	b.applyPublic(add, rbv1.RouteOp_ROUTE_OP_WITHDRAW)
	if _, ok := b.LearnedEdge()["fd00:db8:0:9::e"]; ok {
		t.Fatalf("learnedEdge still has anycast entry after withdraw")
	}
}

func TestApplyPublicNatIPIsNoOp(t *testing.T) {
	b := NewBus("nodeA", "fd00::a", newFakeDP())
	natIP := &rbv1.PublicPrefix{
		Kind:          rbv1.PublicKind_PUBLIC_KIND_NAT_IP,
		Prefix:        "1.2.3.4/32",
		OwnerUnderlay: "fd00::b",
	}
	// Must not panic and must not touch learnedEdge.
	b.applyPublic(natIP, rbv1.RouteOp_ROUTE_OP_ADD)
	if len(b.LearnedEdge()) != 0 {
		t.Fatalf("NAT_IP must not populate learnedEdge, got %+v", b.LearnedEdge())
	}
}
