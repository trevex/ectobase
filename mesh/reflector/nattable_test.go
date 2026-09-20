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
	r.WithdrawNat("nodeA", "1.2.3.4", 1024, 2048, nil)

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

	r.dropOrigin("nodeA")

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

// node_id is self-asserted, so ownership alone cannot protect a block: the certificate guard is
// what binds a withdraw to the node that holds the address. Both checks, both directions.
func TestWithdrawNatIsRefusedUnlessTheBlockIsYours(t *testing.T) {
	r := NewRIB()
	b := &fakeSink{id: "nodeB"}
	r.RegisterSink(b)
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))

	// Another origin cannot withdraw it, even with a certificate that permits the owner.
	if got := r.WithdrawNat("nodeC", "1.2.3.4", 1024, 2048, nil); got != WithdrawRefused {
		t.Fatalf("a foreign origin must be refused, got %v", got)
	}
	// Nor can someone claiming nodeA's id without a certificate for the owner underlay.
	deny := OwnerPermit(func(owner string) bool { return owner == "fd00::impostor" })
	if got := r.WithdrawNat("nodeA", "1.2.3.4", 1024, 2048, deny); got != WithdrawRefused {
		t.Fatalf("a certificate that does not speak for the owner must be refused, got %v", got)
	}
	if us := natUpdates(b); len(us) != 1 || us[0].Op != pb.RouteOp_ROUTE_OP_ADD {
		t.Fatalf("a refused withdraw must not reach the fabric: %+v", us)
	}

	// The owner, with a certificate for it, withdraws it.
	allow := OwnerPermit(func(owner string) bool { return owner == "fd00::a" })
	if got := r.WithdrawNat("nodeA", "1.2.3.4", 1024, 2048, allow); got != WithdrawApplied {
		t.Fatalf("the announcing origin must be able to withdraw its block, got %v", got)
	}
	us := natUpdates(b)
	if len(us) != 2 || us[1].Op != pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("want the WITHDRAW fanned out, got %+v", us)
	}
	// Withdrawing what is not there is not a refusal, just nothing to do.
	if got := r.WithdrawNat("nodeA", "1.2.3.4", 1024, 2048, allow); got != WithdrawAbsent {
		t.Fatalf("want WithdrawAbsent for a block that is already gone, got %v", got)
	}
}

// A block moves when its owner drains and another node takes the range over. The key must move to
// the new origin, or the old one's disconnect withdraws the new owner's block.
func TestAnnounceNatMovesTheBlockToItsNewOrigin(t *testing.T) {
	r := NewRIB()
	s := &fakeSink{id: "sub"}
	r.RegisterSink(s)
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))
	r.AnnounceNat("nodeC", natBlock(100, "10.0.0.9", "1.2.3.4", 1024, 2048, "fd00::c"))

	// nodeA disconnects: it no longer owns the block, so nothing is withdrawn.
	r.dropOrigin("nodeA")
	if us := natUpdates(s); us[len(us)-1].Op == pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("the previous origin's disconnect must not withdraw the new owner's block: %+v", us)
	}
	// And the new origin still owns it: its own withdraw works.
	if got := r.WithdrawNat("nodeC", "1.2.3.4", 1024, 2048, nil); got != WithdrawApplied {
		t.Fatalf("the new origin must own the block it took over, got %v", got)
	}
}

// WithdrawNat must remove k from THIS origin's natByOrigin set too, not just from the RIB: an
// origin that once announced a key and later withdrew it must not still "own" it for cleanup
// purposes once someone else has taken it over. Skipping that delete leaves a stale entry in the
// ORIGINAL owner's set, so its later disconnect silently withdraws the CURRENT owner's block.
func TestWithdrawNatThenReannounceSurvivesTheOriginalOwnersDisconnect(t *testing.T) {
	r := NewRIB()
	s := &fakeSink{id: "sub"}
	r.RegisterSink(s)
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))
	if got := r.WithdrawNat("nodeA", "1.2.3.4", 1024, 2048, nil); got != WithdrawApplied {
		t.Fatalf("nodeA must be able to withdraw its own block, got %v", got)
	}
	r.AnnounceNat("nodeC", natBlock(100, "10.0.0.9", "1.2.3.4", 1024, 2048, "fd00::c"))

	// nodeA disconnects: it withdrew this key itself long ago and no longer owns it.
	r.dropOrigin("nodeA")
	if us := natUpdates(s); us[len(us)-1].Op == pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("the ORIGINAL owner's disconnect must not withdraw the CURRENT owner's block: %+v", us)
	}
	if got := r.WithdrawNat("nodeC", "1.2.3.4", 1024, 2048, nil); got != WithdrawApplied {
		t.Fatalf("nodeC must still own the block it announced after nodeA withdrew, got %v", got)
	}
}

func TestUnregisterSinkStopsNatFanout(t *testing.T) {
	r := NewRIB()
	b := &fakeSink{id: "nodeB"}
	r.RegisterSink(b)
	r.unregisterSink(b.ID())
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

// Two sessions registered without a mutation between them must receive the SAME messages, not two
// copies: after a reflector restart every edge reconnects at once, and a copy per session made the
// peak sessions x records.
func TestGlobalSnapshotIsSharedBetweenSessions(t *testing.T) {
	r := NewRIB()
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))
	r.AnnouncePublic("nodeA", publicRecord(pb.PublicKind_PUBLIC_KIND_LB_IP, "203.0.113.50/32", "fd00::a", 100, 0, 0))

	a, b := &fakeSink{id: "edgeA"}, &fakeSink{id: "edgeB"}
	r.RegisterSink(a)
	r.RegisterSink(b)

	if len(a.snapshots) != 1 || len(b.snapshots) != 1 {
		t.Fatalf("want one snapshot each, got %d and %d", len(a.snapshots), len(b.snapshots))
	}
	sa, sb := a.snapshots[0], b.snapshots[0]
	if len(sa) != 3 { // one NAT record, one public record, one EndOfGlobal
		t.Fatalf("want 3 messages in the replay, got %d", len(sa))
	}
	if len(sa) != len(sb) {
		t.Fatalf("replays differ in length: %d vs %d", len(sa), len(sb))
	}
	for i := range sa {
		if sa[i] != sb[i] {
			t.Fatalf("message %d is not shared: %p vs %p", i, sa[i], sb[i])
		}
	}
}

// A session copies the pointers it is handed, so one session's drain — which nils each message as
// it sends it, so a huge snapshot can be GC'd as it goes — must not blank another session's copy
// of the shared replay.
func TestDrainingOneSessionLeavesTheSharedSnapshotIntact(t *testing.T) {
	r := NewRIB()
	r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))

	a, b := newSessionQueue("edgeA"), newSessionQueue("edgeB")
	r.RegisterSink(a)
	r.RegisterSink(b)

	batch, ok := a.take()
	if !ok {
		t.Fatal("edgeA should have a batch")
	}
	for i := range batch { // exactly what the drain in server.go does
		batch[i] = nil
	}

	other, ok := b.take()
	if !ok {
		t.Fatal("edgeB should have a batch")
	}
	for i, m := range other {
		if m == nil {
			t.Fatalf("edgeB's message %d was blanked by edgeA's drain", i)
		}
	}
}

// Every mutation of the global tables must be visible to a session that registers after it. The
// shared snapshot is cached, so a mutation that forgets to drop it would serve a stale replay to
// every session that connects next — the one way this optimisation can go wrong.
func TestEveryGlobalMutationIsVisibleToALaterSession(t *testing.T) {
	rec := publicRecord(pb.PublicKind_PUBLIC_KIND_LB_IP, "203.0.113.50/32", "fd00::a", 100, 0, 0)
	for _, tc := range []struct {
		name  string
		setup func(r *RIB)
		apply func(r *RIB)
		want  int // records (not counting EndOfGlobal) a session registering afterwards sees
	}{
		{
			name:  "announce nat",
			setup: func(r *RIB) {},
			apply: func(r *RIB) {
				r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))
			},
			want: 1,
		},
		{
			name: "withdraw nat",
			setup: func(r *RIB) {
				r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))
			},
			apply: func(r *RIB) { r.WithdrawNat("nodeA", "1.2.3.4", 1024, 2048, nil) },
			want:  0,
		},
		{
			name: "drop a nat origin",
			setup: func(r *RIB) {
				r.AnnounceNat("nodeA", natBlock(100, "10.0.0.1", "1.2.3.4", 1024, 2048, "fd00::a"))
			},
			apply: func(r *RIB) { r.dropOrigin("nodeA") },
			want:  0,
		},
		{
			name:  "announce public",
			setup: func(r *RIB) {},
			apply: func(r *RIB) { r.AnnouncePublic("nodeA", rec) },
			want:  1,
		},
		{
			name:  "withdraw public",
			setup: func(r *RIB) { r.AnnouncePublic("nodeA", rec) },
			apply: func(r *RIB) { r.WithdrawPublic("nodeA", rec, nil) },
			want:  0,
		},
		{
			name:  "drop a public origin",
			setup: func(r *RIB) { r.AnnouncePublic("nodeA", rec) },
			apply: func(r *RIB) { r.dropOrigin("nodeA") },
			want:  0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRIB()
			tc.setup(r)
			// An early session forces the snapshot to be built and cached.
			r.RegisterSink(&fakeSink{id: "early"})
			tc.apply(r)

			late := &fakeSink{id: "late"}
			r.RegisterSink(late)
			if len(late.snapshots) != 1 {
				t.Fatalf("want one snapshot, got %d", len(late.snapshots))
			}
			if got := len(late.snapshots[0]) - 1; got != tc.want {
				t.Fatalf("a session registering after the mutation saw %d record(s), want %d", got, tc.want)
			}
		})
	}
}
