package reflector

import (
	"sync"
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

	r.dropOrigin("nodeA")

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

// A node whose path went quiet reconnects before the reflector's keepalive (2 s ping + 3 s
// timeout) kills the old session. Everything is keyed by node id, so the old session's cleanup
// used to unregister the NEW session's sink, drop its subscriptions and withdraw its freshly
// announced state fabric-wide — leaving it connected but deaf until it reconnected again.
func TestAReconnectSurvivesItsStaleSessionsCleanup(t *testing.T) {
	r := NewRIB()
	stale := r.ClaimOrigin("nodeA")
	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"}, false)

	// The node reconnects and re-announces on the new session.
	live := r.ClaimOrigin("nodeA")
	fresh := &fakeSink{id: "nodeA"}
	r.RegisterSink(fresh)
	r.Subscribe(100, fresh)
	r.Announce("nodeA", 100, "10.0.0.2/32", []string{"fd00::a"}, false)

	// Only now does the old session's cleanup run.
	r.ReleaseOrigin("nodeA", stale)

	if !r.HasRoute(100, "10.0.0.2/32") {
		t.Fatal("the reconnect's route must survive its stale session's cleanup")
	}
	r.AnnounceNat("nodeB", natBlock(100, "10.0.0.9", "1.2.3.4", 1024, 2048, "fd00::b"))
	if len(natUpdates(fresh)) == 0 {
		t.Fatal("the reconnect must still be registered for the global feed")
	}
	// fanout skips the announcing origin, so proving fresh is still subscribed needs an announce
	// from someone ELSE — nodeA announcing its own route would tell us nothing (fanout would skip
	// it regardless of whether it is even still subscribed).
	beforeRoute := len(updates(fresh))
	r.Announce("nodeB", 100, "10.0.0.3/32", []string{"fd00::b"}, false)
	if len(updates(fresh)) <= beforeRoute {
		t.Fatal("the reconnect must still be subscribed to its VNI")
	}

	// And the live session's own release does tear its state down.
	r.ReleaseOrigin("nodeA", live)
	if r.HasRoute(100, "10.0.0.2/32") {
		t.Fatal("releasing the live session must withdraw its routes")
	}
	// ReleaseOrigin unregisters the sink too: fresh must not go on receiving global fanout.
	beforeNat := len(natUpdates(fresh))
	r.AnnounceNat("nodeC", natBlock(100, "10.0.0.10", "1.2.3.5", 1024, 2048, "fd00::c"))
	if len(natUpdates(fresh)) != beforeNat {
		t.Fatal("releasing the live session must unregister its sink from the global feed")
	}
}

// Claiming the id is also what clears what the previous session left: the agent re-announces its
// whole desired set on reconnect but never withdraws what it no longer wants, so a route the node
// has dropped would otherwise linger in the RIB for good.
func TestClaimingAnOriginDropsWhatTheLastSessionLeft(t *testing.T) {
	r := NewRIB()
	r.ClaimOrigin("nodeA")
	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"}, false)
	r.ClaimOrigin("nodeA")
	if r.HasRoute(100, "10.0.0.1/32") {
		t.Fatal("a new session's claim must drop the previous session's routes")
	}
}

// The critical-section fix (ClaimOrigin/ReleaseOrigin deciding-and-tearing-down under one lock) is
// what makes the stale-session-wipes-the-reconnect race IMPOSSIBLE, not merely unlikely — so the
// only honest assertion here is zero violations over many repetitions, run fresh each time since
// the outcome depends on how the scheduler interleaves the two goroutines. No sleeps: the run time
// is bounded purely by the iteration count.
func TestClaimReleaseRaceNeverLosesAReconnect(t *testing.T) {
	const iterations = 5000
	var lost int
	for i := 0; i < iterations; i++ {
		r := NewRIB()
		stale := r.ClaimOrigin("nodeA")

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			r.ReleaseOrigin("nodeA", stale)
		}()
		go func() {
			defer wg.Done()
			r.ClaimOrigin("nodeA")
			r.Announce("nodeA", 100, "10.0.0.2/32", []string{"fd00::a"}, false)
		}()
		wg.Wait()

		if !r.HasRoute(100, "10.0.0.2/32") {
			lost++
		}
	}
	if lost != 0 {
		t.Fatalf("the stale session's release wiped the reconnect's route in %d/%d iterations", lost, iterations)
	}
}

// ClaimOrigin's delete(r.sinks, nodeID) on supersede has to run even when the NEW session opts out
// of the global feed and so never calls RegisterSink itself: otherwise the predecessor's sink is
// still in r.sinks and keeps receiving broadcast NAT/public updates for a node that, as far as the
// fabric is concerned, no longer has a registered global-feed sink at all.
func TestClaimOriginRemovesTheOldSinkEvenWhenTheSuccessorOptsOutOfTheGlobalFeed(t *testing.T) {
	r := NewRIB()
	r.ClaimOrigin("nodeA")
	old := &fakeSink{id: "nodeA"}
	r.RegisterSink(old)

	// The node reconnects, but the NEW session opted out of the global feed: it never registers a
	// replacement sink for nodeA.
	r.ClaimOrigin("nodeA")

	r.AnnounceNat("nodeB", natBlock(100, "10.0.0.9", "1.2.3.4", 1024, 2048, "fd00::b"))
	if len(natUpdates(old)) != 0 {
		t.Fatalf("the superseded session's sink must be gone from the global feed, got %+v", old.msgs)
	}
}

// ReleaseOrigin's `cur, ok := r.origins[nodeID]` guard exists because a bare map lookup for an
// ABSENT node id returns the zero value: comparing that zero value against a zero-valued token
// (e.g. one that was never assigned because the caller never actually claimed) would read as "this
// IS the live session" and tear down state that has nothing to do with the claim/release lifecycle
// at all — for instance a route announced directly, the way many tests in this package do.
func TestReleaseOriginWithAZeroTokenOnAnUnclaimedIDIsANoOp(t *testing.T) {
	r := NewRIB()
	r.Announce("nodeA", 100, "10.0.0.1/32", []string{"fd00::a"}, false) // never went through ClaimOrigin

	r.ReleaseOrigin("nodeA", 0)

	if !r.HasRoute(100, "10.0.0.1/32") {
		t.Fatal("releasing an unclaimed id with a zero token must not tear down its state")
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
