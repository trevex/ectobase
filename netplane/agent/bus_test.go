package agent

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	rbv1 "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
	"github.com/trevex/xdp-dp/netplane/reflector"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// fakeDP records the routes the agent programs on the local dataplane.
type fakeDP struct {
	mu       sync.Mutex
	added    map[string]string // "vni prefix" -> nexthop
	external map[string]bool   // "vni prefix" -> external flag as programmed
	withdrew map[string]bool
	nbrNat   map[string]string // "natIp min max" -> ownerUnderlay
	nbrNatWd map[string]bool
	fwAdds   []fwCall
	fwDels   []struct{ iface, ruleID string }
	// fwInstalled models the real dataplane: a rule id is unique per interface, and AddFwRule on an
	// existing id fails (ALREADY_EXISTS) — so a correct reconcile must NOT re-add unchanged rules.
	fwInstalled map[string]bool
	lbVips      []string            // ids added
	lbDels      []string            // ids deleted
	lbBackends  map[string][]string // id -> backends
	routeAdds   []routeCall         // every AddRoute call, in order
}

type fwCall struct {
	iface  string
	ruleID string
	rule   FwRule
}

type routeCall struct {
	vni      uint32
	prefix   string
	nexthop  string
	external bool
}

func newFakeDP() *fakeDP {
	return &fakeDP{
		added: map[string]string{}, external: map[string]bool{}, withdrew: map[string]bool{},
		nbrNat: map[string]string{}, nbrNatWd: map[string]bool{},
		fwInstalled: map[string]bool{},
		lbBackends:  map[string][]string{},
	}
}

func natKeyStr(natIp string, min, max uint32) string {
	return fmt.Sprintf("%s %d %d", natIp, min, max)
}

func (f *fakeDP) AddNeighborNat(_ context.Context, natIp string, min, max uint32, ownerUnderlay string, _ uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nbrNat[natKeyStr(natIp, min, max)] = ownerUnderlay
	return nil
}
func (f *fakeDP) WithdrawNeighborNat(_ context.Context, natIp string, min, max uint32, _ uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nbrNatWd[natKeyStr(natIp, min, max)] = true
	return nil
}
func (f *fakeDP) getNbrNat(natIp string, min, max uint32) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.nbrNat[natKeyStr(natIp, min, max)]
	return v, ok
}

func (f *fakeDP) AddRoute(_ context.Context, vni uint32, prefix, nexthop string, external bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added[key(vni, prefix)] = nexthop
	f.external[key(vni, prefix)] = external
	f.routeAdds = append(f.routeAdds, routeCall{vni, prefix, nexthop, external})
	return nil
}
func (f *fakeDP) AddNatSource(_ context.Context, _ uint32, _, _ string, _, _ uint32) error {
	return nil
}
func (f *fakeDP) AddFwRule(_ context.Context, iface, ruleID string, r FwRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := iface + "|" + ruleID
	if f.fwInstalled[k] {
		return fmt.Errorf("fwrule %s already exists", k) // model dataplane ALREADY_EXISTS
	}
	f.fwInstalled[k] = true
	f.fwAdds = append(f.fwAdds, fwCall{iface, ruleID, r})
	return nil
}
func (f *fakeDP) DelFwRule(_ context.Context, iface, ruleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.fwInstalled, iface+"|"+ruleID)
	f.fwDels = append(f.fwDels, struct{ iface, ruleID string }{iface, ruleID})
	return nil
}
func (f *fakeDP) WithdrawRoute(_ context.Context, vni uint32, prefix string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdrew[key(vni, prefix)] = true
	return nil
}
func (f *fakeDP) get(vni uint32, prefix string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.added[key(vni, prefix)]
	return v, ok
}
func key(vni uint32, prefix string) string { return prefix } // vni fixed at 100 in the test

func (f *fakeDP) AddLbVip(ctx context.Context, id string, vni uint32, vip, lbUnderlay string, ports []LbPort) error {
	f.lbVips = append(f.lbVips, id)
	return nil
}
func (f *fakeDP) DelLbVip(ctx context.Context, id string) error {
	f.lbDels = append(f.lbDels, id)
	return nil
}
func (f *fakeDP) AddLbBackend(ctx context.Context, id, backendUnderlay string) error {
	f.lbBackends[id] = append(f.lbBackends[id], backendUnderlay)
	return nil
}
func (f *fakeDP) DelLbBackend(ctx context.Context, id, backendUnderlay string) error {
	cur := f.lbBackends[id][:0]
	for _, b := range f.lbBackends[id] {
		if b != backendUnderlay {
			cur = append(cur, b)
		}
	}
	f.lbBackends[id] = cur
	return nil
}

func TestFakeDP_LBImplementsInterface(t *testing.T) {
	var _ Dataplane = newFakeDP()
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
	dpA := newFakeDP()
	busA := NewBus("nodeA", "fd00::a", dpA, false)
	go busA.Run(ctx, cl, nil, []Route{{Vni: 100, Prefix: "10.0.0.1/32", Nexthop: "fd00::a"}}, nil, nil, nil)

	// Agent B subscribes to vni 100 and must program A's route on its dataplane.
	dpB := newFakeDP()
	busB := NewBus("nodeB", "fd00::b", dpB, false)
	go busB.Run(ctx, cl, []uint32{100}, nil, nil, nil, nil)

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

func TestApplyPublic_LBVIP_EdgeAddsBackend(t *testing.T) {
	dp := newFakeDP()
	b := NewBus("edge1", "2001:db8::e", dp, true) // isEdge = true
	b.applyPublic(&rbv1.PublicPrefix{
		Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "2001:db8::dd",
	}, rbv1.RouteOp_ROUTE_OP_ADD)
	if got := dp.lbBackends["203.0.113.50"]; len(got) != 1 || got[0] != "2001:db8::dd" {
		t.Fatalf("edge AddLbBackend not recorded: %+v", dp.lbBackends)
	}
}

func TestApplyPublic_LBVIP_NonEdgeIgnores(t *testing.T) {
	dp := newFakeDP()
	b := NewBus("nodeA", "2001:db8::dd", dp, false) // not edge
	b.applyPublic(&rbv1.PublicPrefix{
		Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "2001:db8::dd",
	}, rbv1.RouteOp_ROUTE_OP_ADD)
	if len(dp.lbBackends) != 0 {
		t.Fatalf("non-edge must ignore LB_VIP; got %+v", dp.lbBackends)
	}
}

func TestApplyNatInstallsNeighborNatOnlyForRemoteOwners(t *testing.T) {
	dp := newFakeDP()
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
	dp := newFakeDP()
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
	dp := newFakeDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	b.egressVNIs = []uint32{100}
	b.apply(context.Background(), &rbv1.RouteUpdate{
		Vni: 100, Prefix: "10.0.0.5/32", Nexthops: []string{"fd00::d"}, Op: rbv1.RouteOp_ROUTE_OP_ADD,
	})
	if len(dp.routeAdds) != 1 || dp.routeAdds[0].vni != 100 || dp.routeAdds[0].external {
		t.Fatalf("non-public route must install directly (vni=100, external=false): %+v", dp.routeAdds)
	}
}
