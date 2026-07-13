package reflector

import (
	"testing"

	pb "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
)

// fakeSink records everything the RIB sends it.
type fakeSink struct {
	id   string
	msgs []*pb.ServerMsg
}

func (f *fakeSink) ID() string          { return f.id }
func (f *fakeSink) Send(m *pb.ServerMsg) { f.msgs = append(f.msgs, m) }

func updates(f *fakeSink) []*pb.RouteUpdate {
	var out []*pb.RouteUpdate
	for _, m := range f.msgs {
		if ru := m.GetRouteUpdate(); ru != nil {
			out = append(out, ru)
		}
	}
	return out
}

func TestSubscribeGetsSnapshotThenEndOfRIB(t *testing.T) {
	r := NewRIB()
	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"})
	r.Announce("nodeA", 100, "10.0.0.2/32", []string{"fd00::a"})
	r.Announce("nodeA", 200, "10.0.0.9/32", []string{"fd00::a"}) // different vni, must not appear

	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)

	us := updates(sub)
	if len(us) != 2 {
		t.Fatalf("want 2 snapshot routes, got %d", len(us))
	}
	// EndOfRIB is the last message and names vni 100.
	last := sub.msgs[len(sub.msgs)-1].GetEndOfRib()
	if last == nil || last.Vni != 100 {
		t.Fatalf("want trailing EndOfRIB for vni 100, got %+v", sub.msgs[len(sub.msgs)-1])
	}
}

func TestAnnounceFansOutToSubscribersNotOrigin(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	origin := &fakeSink{id: "nodeA"}
	r.Subscribe(100, sub)
	r.Subscribe(100, origin)

	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"})

	if got := updates(sub); len(got) != 1 || got[0].Op != pb.RouteOp_ROUTE_OP_ADD || got[0].Prefix != "10.0.0.1/32" {
		t.Fatalf("subscriber should see one ADD, got %+v", got)
	}
	if got := updates(origin); len(got) != 0 {
		t.Fatalf("origin must NOT receive its own route, got %+v", got)
	}
}

func TestWithdrawFansOut(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)
	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"})
	r.Withdraw("nodeA", 100, "10.0.0.1/32")

	us := updates(sub)
	if len(us) != 2 || us[1].Op != pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("want ADD then WITHDRAW, got %+v", us)
	}
}

func TestDropOriginWithdrawsAllItsRoutes(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)
	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"})
	r.Announce("nodeA", 100, "10.0.0.2/32", []string{"fd00::a"})

	r.DropOrigin("nodeA")

	var withdraws int
	for _, ru := range updates(sub) {
		if ru.Op == pb.RouteOp_ROUTE_OP_WITHDRAW {
			withdraws++
		}
	}
	if withdraws != 2 {
		t.Fatalf("want 2 withdraws after DropOrigin, got %d", withdraws)
	}
}
