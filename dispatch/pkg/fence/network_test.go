// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package fence

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/trevex/ectobase/dispatch/pkg/failover"
	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"github.com/trevex/ectobase/mesh/reflector"
)

// adminOver serves admin over an in-memory listener and returns a client of it.
func adminOver(t *testing.T, admin pb.RouteBusAdminServer) pb.RouteBusAdminClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterRouteBusAdminServer(srv, admin)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewRouteBusAdminClient(conn)
}

func TestNetworkFencer_FenceCallsAdmin(t *testing.T) {
	rib := reflector.NewRIB()
	rib.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	f := NewNetworkFencer(adminOver(t, reflector.NewAdminServer(rib)))
	if err := f.Fence(context.Background(), "2001:db8:0:1::/64"); err != nil {
		t.Fatalf("Fence: %v", err)
	}
	if rib.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("Fence should have hidden the route via admin RPC")
	}
	if err := f.Release(context.Background(), "2001:db8:0:1::/64"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !rib.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("Release should have re-advertised the route without a re-announce")
	}
}

// The route gate's question goes over the same admin client: what a fenced /64 still announces.
func TestNetworkFencer_AnnouncedFromAsksTheReflector(t *testing.T) {
	rib := reflector.NewRIB()
	rib.Announce("source", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	rib.Announce("target", 100, "10.0.0.6/32", []string{"2001:db8:0:2::b"}, false)
	f := NewNetworkFencer(adminOver(t, reflector.NewAdminServer(rib)))
	if err := f.Fence(context.Background(), "2001:db8:0:1::/64"); err != nil {
		t.Fatal(err)
	}

	held, err := f.AnnouncedFrom(context.Background(), "2001:db8:0:1::/64",
		[]failover.RouteKey{{VNI: 100, Prefix: "10.0.0.5/32"}, {VNI: 100, Prefix: "10.0.0.6/32"}})
	if err != nil {
		t.Fatalf("AnnouncedFrom: %v", err)
	}
	if want := (failover.RouteHolding{Key: failover.RouteKey{VNI: 100, Prefix: "10.0.0.5/32"}, Origin: "source", Nexthop: "2001:db8:0:1::a"}); len(held) != 1 || held[0] != want {
		t.Fatalf("want only the fenced source's key, got %v", held)
	}
}

// keysOnlyAdmin answers AnnouncedFrom with held keys but no holdings.
type keysOnlyAdmin struct {
	pb.UnimplementedRouteBusAdminServer
}

func (keysOnlyAdmin) AnnouncedFrom(_ context.Context, req *pb.AnnouncedFromRequest) (*pb.AnnouncedFromReply, error) {
	return &pb.AnnouncedFromReply{Keys: req.GetKeys()}, nil
}

// A held key without a named holder still holds: it is reported with the origin left empty.
func TestNetworkFencer_AnnouncedFromKeepsKeysWithoutHolders(t *testing.T) {
	f := NewNetworkFencer(adminOver(t, keysOnlyAdmin{}))
	held, err := f.AnnouncedFrom(context.Background(), "2001:db8:0:1::/64", []failover.RouteKey{{VNI: 100, Prefix: "10.0.0.5/32"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held[0] != (failover.RouteHolding{Key: failover.RouteKey{VNI: 100, Prefix: "10.0.0.5/32"}}) {
		t.Fatalf("want the key held with no origin, got %v", held)
	}
}

// A reflector that predates the RPC answers Unimplemented. That is an error, not "nothing held":
// the release it gates must not go ahead on it.
func TestNetworkFencer_AnnouncedFromOnAnOlderReflectorFails(t *testing.T) {
	f := NewNetworkFencer(adminOver(t, pb.UnimplementedRouteBusAdminServer{}))
	if _, err := f.AnnouncedFrom(context.Background(), "2001:db8:0:1::/64",
		[]failover.RouteKey{{VNI: 100, Prefix: "10.0.0.5/32"}}); err == nil {
		t.Fatal("an unanswered AnnouncedFrom must be an error")
	}
}
