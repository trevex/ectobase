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

	rec := publicRecord(pb.PublicKind_PUBLIC_KIND_LB_VIP, "203.0.113.50/32", "2001:db8::dd", 100, 0, 0)
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
	r.WithdrawPublic("nodeA", rec)

	us := publicUpdates(b)
	if len(us) != 2 || us[1].Op != pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("want ADD then WITHDRAW, got %+v", us)
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

	r.DropOrigin("nodeA")

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
// the same-node-multi-backend fix: two LB_VIP records with the SAME (kind, prefix, owner) but
// DIFFERENT overlay IPs (two pods of one Service on the same node) must both persist in the RIB (a
// late-joining sink must replay BOTH), and withdrawing one by its exact record (including overlay
// IP) must leave the other intact.
func TestSameNodeLBBackendsDistinctOverlayCoexistAndWithdrawIndependently(t *testing.T) {
	r := NewRIB()
	recA := publicRecord(pb.PublicKind_PUBLIC_KIND_LB_VIP, "203.0.113.50/32", "fd00::a", 100, 0, 0)
	recA.OverlayIP = "10.0.0.5"
	recB := publicRecord(pb.PublicKind_PUBLIC_KIND_LB_VIP, "203.0.113.50/32", "fd00::a", 100, 0, 0)
	recB.OverlayIP = "10.0.0.7"

	r.AnnouncePublic("nodeA", recA)
	r.AnnouncePublic("nodeA", recB)

	// A late-joining sink must replay BOTH backends — they must not have collapsed to one RIB entry.
	late := &fakeSink{id: "nodeC"}
	r.RegisterSink(late)
	us := publicUpdates(late)
	if len(us) != 2 {
		t.Fatalf("want 2 distinct LB_VIP backends replayed, got %d: %+v", len(us), us)
	}
	overlays := map[string]bool{}
	for _, pu := range us {
		overlays[pu.Prefix.OverlayIp] = true
	}
	if !overlays["10.0.0.5"] || !overlays["10.0.0.7"] {
		t.Fatalf("both overlay IPs must be present in the replayed snapshot, got %+v", us)
	}

	// Withdraw recA only: recB must survive.
	r.WithdrawPublic("nodeA", recA)
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
	r.UnregisterSink(b.ID())
	r.AnnouncePublic("nodeA", publicRecord(pb.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY, "fd00:db8:0:9::e/128", "fd00:db8:0:9::1", 0, 0, 0))
	if us := publicUpdates(b); len(us) != 0 {
		t.Fatalf("unregistered sink must not receive public updates, got %+v", us)
	}
}
