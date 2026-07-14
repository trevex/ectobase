package reflector

import (
	"testing"

	pb "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
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
