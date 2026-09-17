package agent

import (
	"context"
	"testing"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// lbVipRec builds one LB_VIP PublicPrefix as a backend node announces it: the VIP + its service
// ports (for AddLbVip) alongside this backend's identity (for AddLbBackend).
func lbVipRec(vip, owner, overlay string, vni uint32, ports ...LbPort) *rbv1.PublicPrefix {
	return &rbv1.PublicPrefix{
		Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: vip, OwnerUnderlay: owner,
		OverlayIp: overlay, Vni: vni, Ports: portsPB(ports),
	}
}

// The core of the bus-driven edge: one backend announcement must register the load balancer AND
// attach the backend to it, in that order — add_lb_target rejects an unknown LB.
func TestApplyPublicLBVIP_RegistersVipBeforeBackend(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("edge1", "fd00:ffff::e1", dp, true)

	b.applyPublic(context.Background(),
		lbVipRec("203.0.113.50/32", "2001:db8::dd", "10.0.0.5", 100, LbPort{Port: 80, Proto: 6}),
		rbv1.RouteOp_ROUTE_OP_ADD)

	reg, ok := dp.lbRegistered["203.0.113.50"]
	if !ok {
		t.Fatalf("VIP was never AddLbVip'd; registered=%+v", dp.lbRegistered)
	}
	// vni 0 is the WAN/public VNI and lb_underlay is the EDGE's own anycast underlay — not the
	// backend's. create_lb skips the UNDERLAY write for vni==0, which is what keeps this from
	// clobbering attach_edge's LOCAL_DELIVER entry.
	if reg.vni != 0 || reg.vip != "203.0.113.50" || reg.lbUnderlay != "fd00:ffff::e1" {
		t.Errorf("AddLbVip = %+v, want vni=0 vip=203.0.113.50 lbUnderlay=fd00:ffff::e1", reg)
	}
	if len(reg.ports) != 1 || reg.ports[0] != (LbPort{Port: 80, Proto: 6}) {
		t.Errorf("ports = %+v, want [{80 6}]", reg.ports)
	}
	if got := dp.lbBackends["203.0.113.50"]; len(got) != 1 || got[0] != "2001:db8::dd" {
		t.Errorf("backend not attached: %+v", got)
	}
}

// Every backend of a VIP announces the same ports, and the reflector replays the whole snapshot on
// reconnect — so the edge sees the same record many times. create_lb rejects a duplicate id, so a
// re-announce must not re-register.
func TestApplyPublicLBVIP_IsIdempotent(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("edge1", "fd00:ffff::e1", dp, true)
	rec := lbVipRec("203.0.113.50/32", "2001:db8::dd", "10.0.0.5", 100, LbPort{Port: 80, Proto: 6})

	for range 3 {
		b.applyPublic(context.Background(), rec, rbv1.RouteOp_ROUTE_OP_ADD)
	}

	if len(dp.lbVips) != 1 {
		t.Errorf("AddLbVip called %d times, want 1: %+v", len(dp.lbVips), dp.lbVips)
	}
	if got := dp.lbBackends["203.0.113.50"]; len(got) != 1 {
		t.Errorf("AddLbBackend called %d times, want 1: %+v", len(got), got)
	}
}

// A second backend on a different node joins the EXISTING load balancer; it must not try to
// register the VIP again.
func TestApplyPublicLBVIP_SecondBackendJoinsExistingVip(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("edge1", "fd00:ffff::e1", dp, true)
	ctx := context.Background()

	b.applyPublic(ctx, lbVipRec("203.0.113.50/32", "2001:db8::dd", "10.0.0.5", 100, LbPort{Port: 80, Proto: 6}), rbv1.RouteOp_ROUTE_OP_ADD)
	b.applyPublic(ctx, lbVipRec("203.0.113.50/32", "2001:db8::ee", "10.0.0.6", 100, LbPort{Port: 80, Proto: 6}), rbv1.RouteOp_ROUTE_OP_ADD)

	if len(dp.lbVips) != 1 {
		t.Errorf("AddLbVip called %d times for one VIP, want 1", len(dp.lbVips))
	}
	if got := dp.lbBackends["203.0.113.50"]; len(got) != 2 {
		t.Errorf("want 2 backends, got %+v", got)
	}
}

// Withdrawing the LAST backend tears the VIP down too: an edge that Maglev-hashes to an empty
// backend set can only blackhole, and leaving the id registered would make a later re-add fail.
func TestApplyPublicLBVIP_LastBackendWithdrawDeletesVip(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("edge1", "fd00:ffff::e1", dp, true)
	ctx := context.Background()
	a := lbVipRec("203.0.113.50/32", "2001:db8::dd", "10.0.0.5", 100, LbPort{Port: 80, Proto: 6})
	c := lbVipRec("203.0.113.50/32", "2001:db8::ee", "10.0.0.6", 100, LbPort{Port: 80, Proto: 6})

	b.applyPublic(ctx, a, rbv1.RouteOp_ROUTE_OP_ADD)
	b.applyPublic(ctx, c, rbv1.RouteOp_ROUTE_OP_ADD)

	b.applyPublic(ctx, a, rbv1.RouteOp_ROUTE_OP_WITHDRAW)
	if _, ok := dp.lbRegistered["203.0.113.50"]; !ok {
		t.Fatal("VIP deleted while a backend remained")
	}

	b.applyPublic(ctx, c, rbv1.RouteOp_ROUTE_OP_WITHDRAW)
	if _, ok := dp.lbRegistered["203.0.113.50"]; ok {
		t.Fatal("VIP still registered after its last backend withdrew")
	}

	// And it must be re-addable afterwards — the proof that the edge's bookkeeping dropped with it.
	b.applyPublic(ctx, a, rbv1.RouteOp_ROUTE_OP_ADD)
	if _, ok := dp.lbRegistered["203.0.113.50"]; !ok {
		t.Fatal("VIP could not be re-registered after a full withdraw")
	}
}

// A port-set edit re-announces under the SAME key. create_lb cannot update in place, so the edge
// must delete and re-create — and re-attach the backends the delete took with it.
func TestApplyPublicLBVIP_PortChangeReregistersAndKeepsBackends(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("edge1", "fd00:ffff::e1", dp, true)
	ctx := context.Background()

	b.applyPublic(ctx, lbVipRec("203.0.113.50/32", "2001:db8::dd", "10.0.0.5", 100, LbPort{Port: 80, Proto: 6}), rbv1.RouteOp_ROUTE_OP_ADD)
	b.applyPublic(ctx, lbVipRec("203.0.113.50/32", "2001:db8::ee", "10.0.0.6", 100, LbPort{Port: 80, Proto: 6}), rbv1.RouteOp_ROUTE_OP_ADD)

	// The LoadBalancer gains a port; every backend re-announces with the new set.
	b.applyPublic(ctx, lbVipRec("203.0.113.50/32", "2001:db8::dd", "10.0.0.5", 100,
		LbPort{Port: 80, Proto: 6}, LbPort{Port: 443, Proto: 6}), rbv1.RouteOp_ROUTE_OP_ADD)

	reg := dp.lbRegistered["203.0.113.50"]
	if len(reg.ports) != 2 || reg.ports[1] != (LbPort{Port: 443, Proto: 6}) {
		t.Fatalf("ports not updated: %+v", reg.ports)
	}
	if len(dp.lbDels) != 1 {
		t.Errorf("want exactly one DelLbVip for the re-register, got %+v", dp.lbDels)
	}
	// BOTH backends must survive the re-register, including the one that did not re-announce yet.
	if got := dp.lbBackends["203.0.113.50"]; len(got) != 2 {
		t.Fatalf("backends lost across the port change: %+v", got)
	}
}

// The agent and the dataplane have independent lifetimes: flowplane pins its maps and adopts them
// across a restart, and the agent can restart on its own (a crash, a config change, waiting for its
// PKI material) while flowplane keeps running. So a fresh agent routinely meets a dataplane that
// ALREADY has the load balancer registered — and create_lb rejects a duplicate id.
//
// Without a recovery path that is terminal: the edge would log "already exists", never reach
// AddLbBackend, and serve the VIP with an empty backend set until flowplane itself restarted.
func TestApplyPublicLBVIP_AdoptsAnLbLeftByAPreviousAgent(t *testing.T) {
	dp := newRecordingDP()
	ctx := context.Background()
	recA := lbVipRec("203.0.113.50/32", "2001:db8::dd", "10.0.0.5", 100, LbPort{Port: 80, Proto: 6})
	recB := lbVipRec("203.0.113.50/32", "2001:db8::ee", "10.0.0.6", 100, LbPort{Port: 80, Proto: 6})

	// A previous agent incarnation registered the VIP and both backends.
	old := NewBus("edge1", "fd00:ffff::e1", dp, true)
	old.applyPublic(ctx, recA, rbv1.RouteOp_ROUTE_OP_ADD)
	old.applyPublic(ctx, recB, rbv1.RouteOp_ROUTE_OP_ADD)
	if _, ok := dp.lbRegistered["203.0.113.50"]; !ok {
		t.Fatal("precondition: the previous agent should have registered the VIP")
	}

	// The agent restarts. Its bookkeeping is gone; the dataplane's is not. On the new session the
	// reflector replays the whole snapshot, so every record arrives again.
	fresh := NewBus("edge1", "fd00:ffff::e1", dp, true)
	fresh.applyPublic(ctx, recA, rbv1.RouteOp_ROUTE_OP_ADD)
	fresh.applyPublic(ctx, recB, rbv1.RouteOp_ROUTE_OP_ADD)

	if _, ok := dp.lbRegistered["203.0.113.50"]; !ok {
		t.Fatal("VIP is not registered after the agent restart")
	}
	if got := dp.lbBackends["203.0.113.50"]; len(got) != 2 {
		t.Fatalf("both backends must be attached after the restart, got %+v", got)
	}

	// The real casualty is everything AFTER the restart. If the agent gave up on the duplicate
	// AddLbVip it holds no record of this VIP, so a backend that scales up next is never attached —
	// and the VIP keeps serving a stale set until flowplane itself restarts.
	recC := lbVipRec("203.0.113.50/32", "2001:db8::ff", "10.0.0.7", 100, LbPort{Port: 80, Proto: 6})
	fresh.applyPublic(ctx, recC, rbv1.RouteOp_ROUTE_OP_ADD)
	if got := dp.lbBackends["203.0.113.50"]; len(got) != 3 {
		t.Fatalf("a backend appearing after the restart must be attached, got %+v", got)
	}

	// ...and a scale-DOWN must still be honored.
	fresh.applyPublic(ctx, recA, rbv1.RouteOp_ROUTE_OP_WITHDRAW)
	if got := dp.lbBackendOverlaysFor("203.0.113.50"); len(got) != 2 {
		t.Fatalf("a withdraw after the restart must remove exactly one backend, got %+v", got)
	}
}

// A non-edge node must not touch maglev at all — it reaches a VIP over the plain E/W anycast route.
func TestApplyPublicLBVIP_NonEdgeIgnores(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("nodeA", "2001:db8::a", dp, false)

	b.applyPublic(context.Background(),
		lbVipRec("203.0.113.50/32", "2001:db8::dd", "10.0.0.5", 100, LbPort{Port: 80, Proto: 6}),
		rbv1.RouteOp_ROUTE_OP_ADD)

	if len(dp.lbVips) != 0 || len(dp.lbBackends) != 0 {
		t.Fatalf("non-edge programmed LB state: vips=%+v backends=%+v", dp.lbVips, dp.lbBackends)
	}
}

// A v6 VIP flows through the same path unchanged (id == VIP, family-agnostic). This is the
// behaviour the retired ReconcileLB's own v6 test guarded.
func TestApplyPublicLBVIP_V6VIP(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("edge1", "fd00:ffff::e1", dp, true)

	b.applyPublic(context.Background(),
		lbVipRec("2001:db8:2b::1/128", "2001:db8::dd", "2001:db8:1::5", 100, LbPort{Port: 80, Proto: 6}),
		rbv1.RouteOp_ROUTE_OP_ADD)

	if _, ok := dp.lbRegistered["2001:db8:2b::1"]; !ok {
		t.Fatalf("v6 VIP not registered: %+v", dp.lbRegistered)
	}
}
