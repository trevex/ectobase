package reflector

import (
	"testing"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// fakeSink records everything the RIB sends it; snapshots also keep their batch boundaries.
type fakeSink struct {
	id        string
	msgs      []*pb.ServerMsg
	snapshots [][]*pb.ServerMsg
}

func (f *fakeSink) ID() string           { return f.id }
func (f *fakeSink) Send(m *pb.ServerMsg) { f.msgs = append(f.msgs, m) }
func (f *fakeSink) SendSnapshot(ms []*pb.ServerMsg) {
	f.snapshots = append(f.snapshots, ms)
	f.msgs = append(f.msgs, ms...)
}

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
	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"}, false)
	r.Announce("nodeA", 100, "10.0.0.2/32", []string{"fd00::a"}, false)
	r.Announce("nodeA", 200, "10.0.0.9/32", []string{"fd00::a"}, false) // different vni, must not appear

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

	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"}, false)

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
	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"}, false)
	r.Withdraw("nodeA", 100, "10.0.0.1/32")

	us := updates(sub)
	if len(us) != 2 || us[1].Op != pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("want ADD then WITHDRAW, got %+v", us)
	}
}

func TestExternalFlagIsDeliveredInFanoutAndSnapshot(t *testing.T) {
	r := NewRIB()

	// Live fanout: a subscriber present before the announce sees external=true.
	live := &fakeSink{id: "nodeB"}
	r.Subscribe(100, live)
	r.Announce("nodeA", 100, "0.0.0.0/0", []string{"fd00::edge"}, true)

	lu := updates(live)
	if len(lu) != 1 || lu[0].Op != pb.RouteOp_ROUTE_OP_ADD || lu[0].Prefix != "0.0.0.0/0" {
		t.Fatalf("live subscriber should see one ADD for the default route, got %+v", lu)
	}
	if !lu[0].External {
		t.Fatalf("live fanout RouteUpdate.External = false, want true")
	}

	// Subscribe snapshot: a subscriber joining afterwards also gets external=true.
	snap := &fakeSink{id: "nodeC"}
	r.Subscribe(100, snap)
	su := updates(snap)
	if len(su) != 1 || su[0].Prefix != "0.0.0.0/0" {
		t.Fatalf("snapshot should replay the default route, got %+v", su)
	}
	if !su[0].External {
		t.Fatalf("snapshot RouteUpdate.External = false, want true")
	}
}

func TestDropOriginWithdrawsAllItsRoutes(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)
	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"}, false)
	r.Announce("nodeA", 100, "10.0.0.2/32", []string{"fd00::a"}, false)

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

// A VNI's replay reaches the sink as ONE snapshot ending in its marker, never as deltas: a sink
// may drop deltas, and a replay missing records or its EndOfRIB never converges.
func TestSubscribeReplaysOneSnapshotEndingInEndOfRIB(t *testing.T) {
	r := NewRIB()
	for _, p := range []string{"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"} {
		r.Announce("nodeA", 100, p, []string{"fd00::a"}, false)
	}
	s := &fakeSink{id: "nodeB"}
	r.Subscribe(100, s)
	if len(s.snapshots) != 1 || len(s.msgs) != len(s.snapshots[0]) {
		t.Fatalf("want the replay as exactly one snapshot and nothing else, got %d snapshots / %d messages", len(s.snapshots), len(s.msgs))
	}
	snap := s.snapshots[0]
	eor := snap[len(snap)-1].GetEndOfRib()
	if eor == nil || eor.Vni != 100 || eor.RecordCount != 3 || len(snap) != 4 {
		t.Fatalf("want 3 routes then EndOfRIB{vni 100, count 3}, got %d messages ending in %+v", len(snap), snap[len(snap)-1].Msg)
	}
}
