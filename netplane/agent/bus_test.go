package agent

import (
	"context"
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
}

func newFakeDP() *fakeDP {
	return &fakeDP{added: map[string]string{}, external: map[string]bool{}, withdrew: map[string]bool{}}
}

func (f *fakeDP) AddRoute(_ context.Context, vni uint32, prefix, nexthop string, external bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added[key(vni, prefix)] = nexthop
	f.external[key(vni, prefix)] = external
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
	busA := NewBus("nodeA", "fd00::a", dpA)
	go busA.Run(ctx, cl, nil, []Route{{Vni: 100, Prefix: "10.0.0.1/32", Nexthop: "fd00::a"}})

	// Agent B subscribes to vni 100 and must program A's route on its dataplane.
	dpB := newFakeDP()
	busB := NewBus("nodeB", "fd00::b", dpB)
	go busB.Run(ctx, cl, []uint32{100}, nil)

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
