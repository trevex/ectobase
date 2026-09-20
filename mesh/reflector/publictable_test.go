package reflector

import (
	"testing"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

func publicUpdates(f *fakeSink) []*pb.PublicUpdate {
	var out []*pb.PublicUpdate
	for _, m := range f.msgs {
		if pu := m.GetPublicUpdate(); pu != nil {
			out = append(out, pu)
		}
	}
	return out
}

func publicRecord(kind pb.PublicKind, prefix, owner string, vni, min, max uint32) PublicRecord {
	return PublicRecord{Kind: kind, Prefix: prefix, OwnerUnderlay: owner, Vni: vni, PortMin: min, PortMax: max}
}

func TestAnnouncePublicRelaysOverlayIP(t *testing.T) {
	r := NewRIB()
	a := &fakeSink{id: "nodeA"}
	r.RegisterSink(a)

	rec := publicRecord(pb.PublicKind_PUBLIC_KIND_LB_IP, "203.0.113.50/32", "2001:db8::dd", 100, 0, 0)
	rec.OverlayIP = "10.0.10.5"
	r.AnnouncePublic("nodeA", rec)

	us := publicUpdates(a)
	if len(us) != 1 || us[0].Prefix.OverlayIp != "10.0.10.5" || us[0].Prefix.Vni != 100 {
		t.Fatalf("reflector must relay overlay_ip/vni through fanout, got %+v", us)
	}
}

func TestAnnouncePublicFansOutToAllSinks(t *testing.T) {
	r := NewRIB()
	a := &fakeSink{id: "nodeA"}
	b := &fakeSink{id: "nodeB"}
	r.RegisterSink(a)
	r.RegisterSink(b)

	r.AnnouncePublic("nodeA", publicRecord(pb.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY, "fd00:db8:0:9::e/128", "fd00:db8:0:9::1", 0, 0, 0))

	// The announcing sink also learns it (public records broadcast to ALL, like NAT).
	for _, s := range []*fakeSink{a, b} {
		us := publicUpdates(s)
		if len(us) != 1 {
			t.Fatalf("sink %s: want 1 PublicUpdate, got %d", s.id, len(us))
		}
		pu := us[0]
		if pu.Op != pb.RouteOp_ROUTE_OP_ADD || pu.Prefix == nil ||
			pu.Prefix.Kind != pb.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY ||
			pu.Prefix.Prefix != "fd00:db8:0:9::e/128" || pu.Prefix.OwnerUnderlay != "fd00:db8:0:9::1" {
			t.Fatalf("sink %s: bad PublicUpdate %+v", s.id, pu)
		}
	}
}

func TestRegisterSinkReplaysPublicSnapshot(t *testing.T) {
	r := NewRIB()
	r.AnnouncePublic("nodeA", publicRecord(pb.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY, "fd00:db8:0:9::e/128", "fd00:db8:0:9::1", 0, 0, 0))
	r.AnnouncePublic("nodeA", publicRecord(pb.PublicKind_PUBLIC_KIND_NAT_IP, "1.2.3.4/32", "fd00:db8:0:9::1", 100, 1024, 2048))

	late := &fakeSink{id: "nodeB"}
	r.RegisterSink(late)

	us := publicUpdates(late)
	if len(us) != 2 {
		t.Fatalf("late sink should replay 2 records, got %d: %+v", len(us), us)
	}
	for _, pu := range us {
		if pu.Op != pb.RouteOp_ROUTE_OP_ADD {
			t.Fatalf("snapshot records must be ADDs, got %+v", pu)
		}
	}
}

func TestWithdrawPublicFansOut(t *testing.T) {
	r := NewRIB()
	b := &fakeSink{id: "nodeB"}
	r.RegisterSink(b)
	rec := publicRecord(pb.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY, "fd00:db8:0:9::e/128", "fd00:db8:0:9::1", 0, 0, 0)
	r.AnnouncePublic("nodeA", rec)
	r.WithdrawPublic("nodeA", rec, nil)

	us := publicUpdates(b)
	if len(us) != 2 || us[1].Op != pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("want ADD then WITHDRAW, got %+v", us)
	}
}

// The public channel gets the same ownership rule as NAT: only the announcing origin, and only a
// certificate that speaks for the record's owner, may withdraw it.
func TestWithdrawPublicIsRefusedUnlessTheRecordIsYours(t *testing.T) {
	r := NewRIB()
	s := &fakeSink{id: "sub"}
	r.RegisterSink(s)
	rec := PublicRecord{
		Kind: pb.PublicKind_PUBLIC_KIND_LB_IP, Prefix: "203.0.113.50/32",
		OwnerUnderlay: "fd00::a", OverlayIP: "10.0.0.1", Vni: 100,
	}
	r.AnnouncePublic("nodeA", rec)

	if got := r.WithdrawPublic("nodeC", rec, nil); got != WithdrawRefused {
		t.Fatalf("a foreign origin must be refused, got %v", got)
	}
	deny := OwnerPermit(func(owner string) bool { return owner == "fd00::impostor" })
	if got := r.WithdrawPublic("nodeA", rec, deny); got != WithdrawRefused {
		t.Fatalf("a certificate that does not speak for the owner must be refused, got %v", got)
	}
	if us := publicUpdates(s); len(us) != 1 || us[0].Op != pb.RouteOp_ROUTE_OP_ADD {
		t.Fatalf("a refused withdraw must not reach the fabric: %+v", us)
	}

	allow := OwnerPermit(func(owner string) bool { return owner == "fd00::a" })
	if got := r.WithdrawPublic("nodeA", rec, allow); got != WithdrawApplied {
		t.Fatalf("the announcing origin must be able to withdraw its record, got %v", got)
	}
	// Withdrawing what is not there is not a refusal, just nothing to do.
	if got := r.WithdrawPublic("nodeA", rec, allow); got != WithdrawAbsent {
		t.Fatalf("want WithdrawAbsent for a record that is already gone, got %v", got)
	}
}

// A record moves when its owner drains and another node — one whose cert ALSO speaks for that
// owner underlay — takes it over. The key must move to the new origin, or the old one's
// disconnect withdraws the new owner's record. Unlike NAT (keyed on nat_ip/port only), publicKey
// includes the owner, so this needs two origins announcing on behalf of the SAME owner: rarer,
// same hazard.
func TestAnnouncePublicMovesTheRecordToItsNewOrigin(t *testing.T) {
	r := NewRIB()
	s := &fakeSink{id: "sub"}
	r.RegisterSink(s)
	rec := PublicRecord{
		Kind: pb.PublicKind_PUBLIC_KIND_LB_IP, Prefix: "203.0.113.50/32",
		OwnerUnderlay: "fd00::a", OverlayIP: "10.0.0.1", Vni: 100,
	}
	r.AnnouncePublic("nodeA", rec)
	r.AnnouncePublic("nodeC", rec)

	// nodeA disconnects: it no longer owns the record, so nothing is withdrawn.
	r.dropOrigin("nodeA")
	if us := publicUpdates(s); us[len(us)-1].Op == pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("the previous origin's disconnect must not withdraw the new owner's record: %+v", us)
	}
	// And the new origin still owns it: its own withdraw works.
	if got := r.WithdrawPublic("nodeC", rec, nil); got != WithdrawApplied {
		t.Fatalf("the new origin must own the record it took over, got %v", got)
	}
}

func TestAnnouncePublicIsIdempotent(t *testing.T) {
	r := NewRIB()
	rec := publicRecord(pb.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY, "fd00:db8:0:9::e/128", "fd00:db8:0:9::1", 0, 0, 0)
	r.AnnouncePublic("nodeA", rec)
	r.AnnouncePublic("nodeA", rec) // duplicate: same (kind, prefix, owner)

	late := &fakeSink{id: "nodeB"}
	r.RegisterSink(late)
	if us := publicUpdates(late); len(us) != 1 {
		t.Fatalf("duplicate announce must be idempotent, snapshot has %d records: %+v", len(us), us)
	}
}

func TestDropOriginWithdrawsPublicRecords(t *testing.T) {
	r := NewRIB()
	b := &fakeSink{id: "nodeB"}
	r.RegisterSink(b)
	r.AnnouncePublic("nodeA", publicRecord(pb.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY, "fd00:db8:0:9::e/128", "fd00:db8:0:9::1", 0, 0, 0))
	r.AnnouncePublic("nodeA", publicRecord(pb.PublicKind_PUBLIC_KIND_NAT_IP, "1.2.3.4/32", "fd00:db8:0:9::1", 100, 1024, 2048))

	r.dropOrigin("nodeA")

	var withdraws int
	for _, pu := range publicUpdates(b) {
		if pu.Op == pb.RouteOp_ROUTE_OP_WITHDRAW {
			withdraws++
		}
	}
	if withdraws != 2 {
		t.Fatalf("want 2 public withdraws after DropOrigin, got %d", withdraws)
	}
}

// TestSameNodeLBBackendsDistinctOverlayCoexistAndWithdrawIndependently proves the reflector half of
// the same-node-multi-backend fix: two LB_IP records with the SAME (kind, prefix, owner) but
// DIFFERENT overlay IPs (two pods of one Service on the same node) must both persist in the RIB (a
// late-joining sink must replay BOTH), and withdrawing one by its exact record (including overlay
// IP) must leave the other intact.
func TestSameNodeLBBackendsDistinctOverlayCoexistAndWithdrawIndependently(t *testing.T) {
	r := NewRIB()
	recA := publicRecord(pb.PublicKind_PUBLIC_KIND_LB_IP, "203.0.113.50/32", "fd00::a", 100, 0, 0)
	recA.OverlayIP = "10.0.0.5"
	recB := publicRecord(pb.PublicKind_PUBLIC_KIND_LB_IP, "203.0.113.50/32", "fd00::a", 100, 0, 0)
	recB.OverlayIP = "10.0.0.7"

	r.AnnouncePublic("nodeA", recA)
	r.AnnouncePublic("nodeA", recB)

	// A late-joining sink must replay BOTH backends — they must not have collapsed to one RIB entry.
	late := &fakeSink{id: "nodeC"}
	r.RegisterSink(late)
	us := publicUpdates(late)
	if len(us) != 2 {
		t.Fatalf("want 2 distinct LB_IP backends replayed, got %d: %+v", len(us), us)
	}
	overlays := map[string]bool{}
	for _, pu := range us {
		overlays[pu.Prefix.OverlayIp] = true
	}
	if !overlays["10.0.0.5"] || !overlays["10.0.0.7"] {
		t.Fatalf("both overlay IPs must be present in the replayed snapshot, got %+v", us)
	}

	// Withdraw recA only: recB must survive.
	r.WithdrawPublic("nodeA", recA, nil)
	afterWithdraw := &fakeSink{id: "nodeD"}
	r.RegisterSink(afterWithdraw)
	us2 := publicUpdates(afterWithdraw)
	if len(us2) != 1 || us2[0].Prefix.OverlayIp != "10.0.0.7" {
		t.Fatalf("after withdrawing 10.0.0.5, only 10.0.0.7 must remain, got %+v", us2)
	}
}

func TestUnregisterSinkStopsPublicFanout(t *testing.T) {
	r := NewRIB()
	b := &fakeSink{id: "nodeB"}
	r.RegisterSink(b)
	r.unregisterSink(b.ID())
	r.AnnouncePublic("nodeA", publicRecord(pb.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY, "fd00:db8:0:9::e/128", "fd00:db8:0:9::1", 0, 0, 0))
	if us := publicUpdates(b); len(us) != 0 {
		t.Fatalf("unregistered sink must not receive public updates, got %+v", us)
	}
}
