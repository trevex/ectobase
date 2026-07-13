package reflector

import (
	"context"
	"net"
	"testing"
	"time"

	pb "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func startServer(t *testing.T) pb.RouteBusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterRouteBusServer(srv, NewServer(NewRIB()))
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewRouteBusClient(conn)
}

func hello(t *testing.T, s pb.RouteBus_SessionClient, id string) {
	t.Helper()
	if err := s.Send(&pb.ClientMsg{Msg: &pb.ClientMsg_Hello{Hello: &pb.Hello{NodeId: id}}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
}

func TestSessionAnnounceReachesSubscriber(t *testing.T) {
	cl := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Subscriber first, so it is registered before A announces.
	subStream, err := cl.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, subStream, "nodeB")
	if err := subStream.Send(&pb.ClientMsg{Msg: &pb.ClientMsg_Subscribe{Subscribe: &pb.Subscribe{Vni: 100}}}); err != nil {
		t.Fatal(err)
	}
	// Drain the (empty) snapshot's EndOfRIB.
	if m, err := subStream.Recv(); err != nil || m.GetEndOfRib() == nil {
		t.Fatalf("want EndOfRIB, got %+v err=%v", m, err)
	}

	// Announcer.
	annStream, err := cl.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, annStream, "nodeA")
	if err := annStream.Send(&pb.ClientMsg{Msg: &pb.ClientMsg_Announce{Announce: &pb.Announce{
		Vni: 100, Prefix: "10.0.0.1/32", NexthopUnderlay: "fd00::a",
	}}}); err != nil {
		t.Fatal(err)
	}

	m, err := subStream.Recv()
	if err != nil {
		t.Fatalf("recv update: %v", err)
	}
	ru := m.GetRouteUpdate()
	if ru == nil || ru.Op != pb.RouteOp_ROUTE_OP_ADD || ru.Prefix != "10.0.0.1/32" || ru.Nexthops[0] != "fd00::a" {
		t.Fatalf("bad RouteUpdate: %+v", m)
	}

	// Closing the announcer's stream fast-withdraws its route.
	annStream.CloseSend()
	m, err = subStream.Recv()
	if err != nil {
		t.Fatalf("recv withdraw: %v", err)
	}
	if ru := m.GetRouteUpdate(); ru == nil || ru.Op != pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("want WITHDRAW after peer close, got %+v", m)
	}
}
