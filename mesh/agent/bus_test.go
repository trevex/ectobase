package agent

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"github.com/trevex/ectobase/mesh/reflector"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestFakeDP_LBImplementsInterface(t *testing.T) {
	var _ Dataplane = newRecordingDP()
}

func dialReflector(t *testing.T) rbv1.RouteBusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	rbv1.RegisterRouteBusServer(srv, reflector.NewServer(reflector.NewRIB()))
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return rbv1.NewRouteBusClient(conn)
}

func TestAgentLearnsRemoteRouteAndProgramsDataplane(t *testing.T) {
	cl := dialReflector(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Agent A announces one local route (no dataplane needed for the announcer here).
	dpA := newRecordingDP()
	busA := NewBus("nodeA", "fd00::a", dpA, false)
	busA.reconcileEvery = 50 * time.Millisecond
	reconcileA := func(context.Context) (DesiredState, error) {
		return DesiredState{Routes: []Route{{Vni: 100, Prefix: "10.0.0.1/32", Nexthop: "fd00::a"}}}, nil
	}
	go busA.Run(ctx, cl, reconcileA)

	// Agent B subscribes to vni 100 and must program A's route on its dataplane.
	dpB := newRecordingDP()
	busB := NewBus("nodeB", "fd00::b", dpB, false)
	busB.reconcileEvery = 50 * time.Millisecond
	reconcileB := func(context.Context) (DesiredState, error) { return DesiredState{Subs: []uint32{100}}, nil }
	go busB.Run(ctx, cl, reconcileB)

	// Poll for the learned route.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if nh, ok := dpB.get(100, "10.0.0.1/32"); ok {
			if nh != "fd00::a" {
				t.Fatalf("nexthop = %q, want fd00::a", nh)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("agent B never programmed A's route")
}

// TestAgentWithdrawsRemovedRouteToSubscriber proves steady-state reconcile: a route the announcer
// STOPS desiring (e.g. its NIC was descheduled) is withdrawn on the live stream and the subscriber
// removes it — without either side reconnecting. The old one-shot Run could never do this.
func TestAgentWithdrawsRemovedRouteToSubscriber(t *testing.T) {
	cl := dialReflector(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Announcer A: desired route present until `present` is flipped false.
	var mu sync.Mutex
	present := true
	dpA := newRecordingDP()
	busA := NewBus("nodeA", "fd00::a", dpA, false)
	busA.reconcileEvery = 30 * time.Millisecond
	reconcileA := func(context.Context) (DesiredState, error) {
		mu.Lock()
		defer mu.Unlock()
		if !present {
			return DesiredState{}, nil
		}
		return DesiredState{Routes: []Route{{Vni: 100, Prefix: "10.0.0.1/32", Nexthop: "fd00::a"}}}, nil
	}
	go busA.Run(ctx, cl, reconcileA)

	dpB := newRecordingDP()
	busB := NewBus("nodeB", "fd00::b", dpB, false)
	busB.reconcileEvery = 30 * time.Millisecond
	go busB.Run(ctx, cl, func(context.Context) (DesiredState, error) { return DesiredState{Subs: []uint32{100}}, nil })

	// B learns the route.
	waitFor(t, 3*time.Second, func() bool { _, ok := dpB.get(100, "10.0.0.1/32"); return ok })

	// A stops desiring the route → next reconcile tick withdraws it → B removes it.
	mu.Lock()
	present = false
	mu.Unlock()
	waitFor(t, 3*time.Second, func() bool {
		dpB.mu.Lock()
		defer dpB.mu.Unlock()
		return dpB.withdrew[key(100, "10.0.0.1/32")]
	})
}

// TestPruneOnEndOfRIB proves the learner side: a route installed in a prior session that is NOT
// replayed in the new session's snapshot is withdrawn when EndOfRIB arrives; one that IS replayed
// survives. This is what removes routes that left the RIB while the agent was disconnected.
func TestPruneOnEndOfRIB(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeB", "fd00::b", dp, false)

	// Session 1: learn two routes in vni 100.
	stale := &rbv1.RouteUpdate{Vni: 100, Prefix: "10.0.0.1/32", Nexthops: []string{"fd00::a"}, Op: rbv1.RouteOp_ROUTE_OP_ADD}
	kept := &rbv1.RouteUpdate{Vni: 100, Prefix: "10.0.0.2/32", Nexthops: []string{"fd00::a"}, Op: rbv1.RouteOp_ROUTE_OP_ADD}
	b.apply(ctx, stale)
	b.apply(ctx, kept)

	// Reconnect: Run resets the per-session seen set (done inline here). Only 10.0.0.2 is replayed.
	b.seen = map[uint32]map[string]bool{}
	b.apply(ctx, kept)

	// EndOfRIB(100): 10.0.0.1 was not re-seen → pruned; 10.0.0.2 was → kept.
	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{EndOfRib: &rbv1.EndOfRIB{Vni: 100}}})

	if !dp.withdrew[key(100, "10.0.0.1/32")] {
		t.Fatalf("stale route (not replayed) must be pruned on EndOfRIB")
	}
	if dp.withdrew[key(100, "10.0.0.2/32")] {
		t.Fatalf("replayed route must NOT be pruned")
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func TestApplyPublic_LBVIP_EdgeAddsBackend(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("edge1", "2001:db8::e", dp, true) // isEdge = true
	b.applyPublic(context.Background(), &rbv1.PublicPrefix{
		Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "2001:db8::dd",
	}, rbv1.RouteOp_ROUTE_OP_ADD)
	if got := dp.lbBackends["203.0.113.50"]; len(got) != 1 || got[0] != "2001:db8::dd" {
		t.Fatalf("edge AddLbBackend not recorded: %+v", dp.lbBackends)
	}
}

func TestApplyPublic_LBVIP_NonEdgeIgnores(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("nodeA", "2001:db8::dd", dp, false) // not edge
	b.applyPublic(context.Background(), &rbv1.PublicPrefix{
		Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "2001:db8::dd",
	}, rbv1.RouteOp_ROUTE_OP_ADD)
	if len(dp.lbBackends) != 0 {
		t.Fatalf("non-edge must ignore LB_VIP; got %+v", dp.lbBackends)
	}
}

func TestApplyNatInstallsNeighborNatOnlyForRemoteOwners(t *testing.T) {
	dp := newRecordingDP()
	// This node's underlay is fd00::b.
	b := NewBus("nodeB", "fd00::b", dp, false)
	ctx := context.Background()

	// A block owned by a PEER (fd00::a) -> installs a neighbor-nat return route.
	b.applyNat(ctx, &rbv1.NatUpdate{
		Vni: 100, SourceIp: "10.0.0.1", NatIp: "1.2.3.4",
		PortMin: 1024, PortMax: 2048, OwnerUnderlay: "fd00::a", Op: rbv1.RouteOp_ROUTE_OP_ADD,
	})
	if owner, ok := dp.getNbrNat("1.2.3.4", 1024, 2048); !ok || owner != "fd00::a" {
		t.Fatalf("remote-owned block should install AddNeighborNat -> fd00::a, got %q ok=%v", owner, ok)
	}

	// A block owned by THIS node -> must NOT install a neighbor-nat (local SNAT is
	// programmed by the reconciler, not here).
	b.applyNat(ctx, &rbv1.NatUpdate{
		Vni: 100, SourceIp: "10.0.0.9", NatIp: "5.6.7.8",
		PortMin: 4096, PortMax: 5120, OwnerUnderlay: "fd00::b", Op: rbv1.RouteOp_ROUTE_OP_ADD,
	})
	if _, ok := dp.getNbrNat("5.6.7.8", 4096, 5120); ok {
		t.Fatalf("locally-owned block must NOT install a neighbor-nat")
	}
}

func TestApplyPublicVNIRoute_ImportsIntoEgressVNIs(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	b.egressVNIs = []uint32{100, 200} // set by Run() in production

	b.apply(context.Background(), &rbv1.RouteUpdate{
		Vni: 0, Prefix: "0.0.0.0/0", Nexthops: []string{"fd00::e"}, Op: rbv1.RouteOp_ROUTE_OP_ADD,
	})

	// Imported 0.0.0.0/0 -> fd00::e into BOTH egress VNIs (external), and NOT into VNI 0.
	if got := dp.routeAdds; len(got) != 2 {
		t.Fatalf("want 2 imported routes, got %d: %+v", len(got), got)
	}
	for _, ra := range dp.routeAdds {
		if ra.prefix != "0.0.0.0/0" || ra.nexthop != "fd00::e" || !ra.external || ra.vni == 0 {
			t.Fatalf("bad imported route: %+v", ra)
		}
	}
	if b.LearnedPublic()["0.0.0.0/0"] != "fd00::e" {
		t.Fatalf("learnedPublic not recorded: %+v", b.LearnedPublic())
	}
}

func TestApplyNonPublicRoute_InstallsDirectly(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	b.egressVNIs = []uint32{100}
	b.apply(context.Background(), &rbv1.RouteUpdate{
		Vni: 100, Prefix: "10.0.0.5/32", Nexthops: []string{"fd00::d"}, Op: rbv1.RouteOp_ROUTE_OP_ADD,
	})
	if len(dp.routeAdds) != 1 || dp.routeAdds[0].vni != 100 || dp.routeAdds[0].external {
		t.Fatalf("non-public route must install directly (vni=100, external=false): %+v", dp.routeAdds)
	}
}
