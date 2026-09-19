package reflector

import (
	"testing"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

func natUpdates(f *fakeSink) []*pb.NatUpdate {
	var out []*pb.NatUpdate
	for _, m := range f.msgs {
		if nu := m.GetNatUpdate(); nu != nil {
			out = append(out, nu)
		}
	}
	return out
}

func natBlock(vni uint32, src, natIP string, min, max uint32, owner string) NatBlock {
	return NatBlock{Vni: vni, SourceIP: src, NatIP: natIP, PortMin: min, PortMax: max, OwnerUnderlay: owner}
}

func TestAnnounceNatFansOutToAllSinks(t *testing.T) {
	r := NewRIB()
	a := &fakeSink{id: "nodeA"}
	b := &fakeSink{id: "nodeB"}
	r.RegisterSink(a)
	r.RegisterSink(b)

	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))

	// The announcing sink also learns it (unlike routes, NAT blocks broadcast to ALL).
	for _, s := range []*fakeSink{a, b} {
		us := natUpdates(s)
		if len(us) != 1 {
			t.Fatalf("sink %s: want 1 NatUpdate, got %d", s.id, len(us))
		}
		nu := us[0]
		if nu.Op != pb.RouteOp_ROUTE_OP_ADD || nu.NatIp != "1.2.3.4" || nu.PortMin != 1024 ||
			nu.PortMax != 2048 || nu.OwnerUnderlay != "fd00::a" || nu.SourceIp != "10.0.0.1" || nu.Vni != 100 {
			t.Fatalf("sink %s: bad NatUpdate %+v", s.id, nu)
		}
	}
}

func TestRegisterSinkReplaysNatSnapshot(t *testing.T) {
	r := NewRIB()
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.2", "1.2.3.4", 2048, 3072, "fd00::a"))

	late := &fakeSink{id: "nodeB"}
	r.RegisterSink(late)

	us := natUpdates(late)
	if len(us) != 2 {
		t.Fatalf("late sink should replay 2 blocks, got %d: %+v", len(us), us)
	}
	for _, nu := range us {
		if nu.Op != pb.RouteOp_ROUTE_OP_ADD {
			t.Fatalf("snapshot blocks must be ADDs, got %+v", nu)
		}
	}
}

func TestWithdrawNatFansOut(t *testing.T) {
	r := NewRIB()
	b := &fakeSink{id: "nodeB"}
	r.RegisterSink(b)
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))
	r.WithdrawNat("nodeA", "1.2.3.4", 1024, 2048)

	us := natUpdates(b)
	if len(us) != 2 || us[1].Op != pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("want ADD then WITHDRAW, got %+v", us)
	}
}

func TestDropOriginWithdrawsNatBlocks(t *testing.T) {
	r := NewRIB()
	b := &fakeSink{id: "nodeB"}
	r.RegisterSink(b)
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.2", "1.2.3.4", 2048, 3072, "fd00::a"))

	r.DropOrigin("nodeA")

	var withdraws int
	for _, nu := range natUpdates(b) {
		if nu.Op == pb.RouteOp_ROUTE_OP_WITHDRAW {
			withdraws++
		}
	}
	if withdraws != 2 {
		t.Fatalf("want 2 NAT withdraws after DropOrigin, got %d", withdraws)
	}
}

func TestUnregisterSinkStopsNatFanout(t *testing.T) {
	r := NewRIB()
	b := &fakeSink{id: "nodeB"}
	r.RegisterSink(b)
	r.UnregisterSink(b.ID())
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))
	if us := natUpdates(b); len(us) != 0 {
		t.Fatalf("unregistered sink must not receive NAT updates, got %+v", us)
	}
}

// The EndOfGlobal marker is what lets a consumer prune the global channel, and its count is what
// lets it distinguish a complete snapshot from one the sink dropped records from. Both have to be
// exact, and the marker has to come LAST — a consumer counts records up to it.
func TestRegisterSinkClosesTheSnapshotWithAnAccurateEndOfGlobal(t *testing.T) {
	r := NewRIB()
	// Two NAT blocks and one public record, announced before anyone registers.
	seed := &fakeSink{id: "seed"}
	r.RegisterSink(seed)
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))
	r.AnnounceNat("nodeC", natBlock(100, "10.0.0.2", "1.2.3.5", 2048, 3072, "fd00::c"))
	r.AnnouncePublic("nodeA", PublicRecord{
		Kind: pb.PublicKind_PUBLIC_KIND_LB_IP, Prefix: "203.0.113.50/32",
		OwnerUnderlay: "fd00::a", OverlayIP: "10.0.0.1", Vni: 100,
	})

	// A LATE joiner gets the whole snapshot, then the marker.
	late := &fakeSink{id: "late"}
	r.RegisterSink(late)

	if len(late.msgs) == 0 {
		t.Fatal("late joiner got no snapshot at all")
	}
	last := late.msgs[len(late.msgs)-1]
	eog := last.GetEndOfGlobal()
	if eog == nil {
		t.Fatalf("EndOfGlobal must be the LAST message of the snapshot, got %T", last.Msg)
	}
	// Every message before the marker is a global record, and the count must match exactly.
	records := uint32(len(late.msgs) - 1)
	if eog.RecordCount != records {
		t.Fatalf("EndOfGlobal.record_count = %d, but %d records were replayed", eog.RecordCount, records)
	}
	if records != 3 {
		t.Fatalf("want 3 replayed records (2 NAT + 1 public), got %d", records)
	}
}

// An empty fabric still has to close its snapshot: without a marker a consumer could never prune,
// and "no records at all" is exactly the case where everything it holds is stale.
func TestRegisterSinkSendsEndOfGlobalOnAnEmptyRIB(t *testing.T) {
	r := NewRIB()
	s := &fakeSink{id: "nodeA"}
	r.RegisterSink(s)

	if len(s.msgs) != 1 {
		t.Fatalf("want exactly the EndOfGlobal marker, got %d messages", len(s.msgs))
	}
	eog := s.msgs[0].GetEndOfGlobal()
	if eog == nil || eog.RecordCount != 0 {
		t.Fatalf("want EndOfGlobal{record_count: 0}, got %+v", s.msgs[0].Msg)
	}
}

// The global replay reaches the sink as ONE snapshot ending in EndOfGlobal, never as deltas.
func TestRegisterSinkReplaysOneSnapshotEndingInEndOfGlobal(t *testing.T) {
	r := NewRIB()
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.2", "1.2.3.5", 1024, 2048, "fd00::a"))
	r.AnnouncePublic("nodeA", PublicRecord{
		Kind: pb.PublicKind_PUBLIC_KIND_LB_IP, Prefix: "203.0.113.50/32",
		OwnerUnderlay: "fd00::a", OverlayIP: "10.0.0.1", Vni: 100,
	})
	s := &fakeSink{id: "late"}
	r.RegisterSink(s)
	if len(s.snapshots) != 1 || len(s.msgs) != len(s.snapshots[0]) {
		t.Fatalf("want the replay as exactly one snapshot and nothing else, got %d snapshots / %d messages", len(s.snapshots), len(s.msgs))
	}
	snap := s.snapshots[0]
	if eog := snap[len(snap)-1].GetEndOfGlobal(); eog == nil || eog.RecordCount != 3 || len(snap) != 4 {
		t.Fatalf("want 3 records then EndOfGlobal{3}, got %d messages ending in %+v", len(snap), snap[len(snap)-1].Msg)
	}
}
