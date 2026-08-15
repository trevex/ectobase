package reflector

import (
	"testing"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// lastOpFor returns the last RouteUpdate op the sink saw for prefix.
func lastOpFor(f *fakeSink, prefix string) (pb.RouteOp, bool) {
	var op pb.RouteOp
	seen := false
	for _, u := range updates(f) {
		if u.Prefix == prefix {
			op = u.Op
			seen = true
		}
	}
	return op, seen
}

// Anycast HA edges BOTH announce the same (vni, prefix) (e.g. 0.0.0.0/0 -> the anycast
// edge underlay). The route must be reference-counted per origin: it stays advertised
// while ANY origin announces it, and is only withdrawn when the LAST origin drops.
func TestAnycastRouteRefcountedByOrigin(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "src"}
	r.Subscribe(100, sub)

	r.Announce("edge1", 100, "0.0.0.0/0", []string{"fd00:db8:0:9::e"}, true)
	r.Announce("edge2", 100, "0.0.0.0/0", []string{"fd00:db8:0:9::e"}, true)

	// One edge's session is lost — the route MUST remain (edge2 still announces it).
	r.DropOrigin("edge1")
	if op, ok := lastOpFor(sub, "0.0.0.0/0"); !ok || op != pb.RouteOp_ROUTE_OP_ADD {
		t.Fatalf("after 1 of 2 anycast origins drops, route must stay ADD; got op=%v seen=%v", op, ok)
	}

	// An explicit withdraw from the remaining origin also must not remove it prematurely
	// if a third origin exists — but here edge2 is the last, so it goes away.
	r.Withdraw("edge2", 100, "0.0.0.0/0")
	if op, ok := lastOpFor(sub, "0.0.0.0/0"); !ok || op != pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("after the last origin withdraws, route must be WITHDRAW; got op=%v seen=%v", op, ok)
	}
}

// A second origin announcing an identical (vni, prefix, nexthop) must NOT churn the
// route to existing subscribers (no redundant ADD/WITHDRAW flapping).
func TestDuplicateAnycastAnnounceDoesNotChurn(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "src"}
	r.Subscribe(100, sub)

	r.Announce("edge1", 100, "0.0.0.0/0", []string{"fd00:db8:0:9::e"}, true)
	n := len(updates(sub)) // exactly one ADD expected
	r.Announce("edge2", 100, "0.0.0.0/0", []string{"fd00:db8:0:9::e"}, true)
	if got := len(updates(sub)); got != n {
		t.Fatalf("duplicate anycast announce must not emit another update; before=%d after=%d", n, got)
	}
}
