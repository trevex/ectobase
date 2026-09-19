package reflector

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func startServerWithRIB(t *testing.T) (pb.RouteBusClient, *RIB) {
	t.Helper()
	rib := NewRIB()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterRouteBusServer(srv, NewServer(rib))
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewRouteBusClient(conn), rib
}

func startServer(t *testing.T) pb.RouteBusClient {
	t.Helper()
	cl, _ := startServerWithRIB(t)
	return cl
}

func hello(t *testing.T, s pb.RouteBus_SessionClient, id string) {
	t.Helper()
	if err := s.Send(&pb.ClientMsg{Msg: &pb.ClientMsg_Hello{Hello: &pb.Hello{NodeId: id}}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
}

// recvSubstantive returns the next message that is not an EndOfGlobal snapshot marker. Every
// session now gets one of those on Hello (and one per reconnect), which would otherwise shift every
// positional Recv in these tests by one. The marker's own contract — that it closes the snapshot
// and carries an accurate record count — is asserted in nattable_test.go, not here.
func recvSubstantive(t *testing.T, s pb.RouteBus_SessionClient) *pb.ServerMsg {
	t.Helper()
	for {
		m, err := s.Recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		if m.GetEndOfGlobal() != nil {
			continue
		}
		return m
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
	if m := recvSubstantive(t, subStream); m.GetEndOfRib() == nil {
		t.Fatalf("want EndOfRIB, got %+v", m)
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

func TestSessionAnnounceNatBroadcastsAndSnapshots(t *testing.T) {
	cl := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// B connects first (no VNI subscription needed: NAT is global).
	bStream, err := cl.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, bStream, "nodeB")

	// A announces a NAT block.
	aStream, err := cl.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, aStream, "nodeA")
	if err := aStream.Send(&pb.ClientMsg{Msg: &pb.ClientMsg_AnnounceNat{AnnounceNat: &pb.AnnounceNat{
		Vni: 100, SourceIp: "10.0.0.1", NatIp: "1.2.3.4", PortMin: 1024, PortMax: 2048, OwnerUnderlay: "fd00::a",
	}}}); err != nil {
		t.Fatal(err)
	}

	// B receives the NatUpdate ADD without ever subscribing to a VNI.
	m := recvSubstantive(t, bStream)
	nu := m.GetNatUpdate()
	if nu == nil || nu.Op != pb.RouteOp_ROUTE_OP_ADD || nu.NatIp != "1.2.3.4" ||
		nu.PortMin != 1024 || nu.OwnerUnderlay != "fd00::a" {
		t.Fatalf("bad NatUpdate: %+v", m)
	}

	// A late joiner gets the NAT snapshot right after Hello.
	cStream, err := cl.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, cStream, "nodeC")
	m = recvSubstantive(t, cStream)
	if snap := m.GetNatUpdate(); snap == nil || snap.NatIp != "1.2.3.4" || snap.Op != pb.RouteOp_ROUTE_OP_ADD {
		t.Fatalf("late joiner should replay the NAT snapshot, got %+v", m)
	}

	// A disconnects -> its NAT block is withdrawn to the survivors.
	aStream.CloseSend()
	m = recvSubstantive(t, bStream)
	if nu := m.GetNatUpdate(); nu == nil || nu.Op != pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("want NAT WITHDRAW after owner disconnect, got %+v", m)
	}
}

// bigSnapshot is several times the old 1024-slot sink, which dropped the tail of any larger replay
// — usually its marker too, so the session never pruned and never reported converged.
const bigSnapshot = 5000

// A late joiner receives every global record and the EndOfGlobal marker, whose count matches.
func TestSessionDeliversAWholeGlobalSnapshot(t *testing.T) {
	cl, rib := startServerWithRIB(t)
	for i := 0; i < bigSnapshot; i++ {
		rib.AnnounceNat("seed", NatBlock{
			Vni: 100, SourceIP: fmt.Sprintf("10.0.%d.%d", i>>8, i&0xff),
			NatIP: fmt.Sprintf("198.51.%d.%d", i>>8, i&0xff), PortMin: 1024, PortMax: 2048,
			OwnerUnderlay: "fd00::a",
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := cl.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, st, "late")
	got := 0
	for {
		m, err := st.Recv()
		if err != nil {
			t.Fatalf("no EndOfGlobal after %d of %d records: %v", got, bigSnapshot, err)
		}
		if m.GetNatUpdate() != nil {
			got++
			continue
		}
		eog := m.GetEndOfGlobal()
		if eog == nil {
			t.Fatalf("unexpected message inside the snapshot: %+v", m.Msg)
		}
		if got != bigSnapshot || eog.RecordCount != uint32(bigSnapshot) {
			t.Fatalf("received %d records, marker says %d, want %d", got, eog.RecordCount, bigSnapshot)
		}
		return
	}
}

// A subscriber receives every route of the VNI and the EndOfRIB marker, whose count matches.
func TestSessionDeliversAWholeVNISnapshot(t *testing.T) {
	cl, rib := startServerWithRIB(t)
	for i := 0; i < bigSnapshot; i++ {
		rib.Announce("seed", 100, fmt.Sprintf("10.1.%d.%d/32", i>>8, i&0xff), []string{"fd00::a"}, false)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := cl.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, st, "sub")
	if err := st.Send(&pb.ClientMsg{Msg: &pb.ClientMsg_Subscribe{Subscribe: &pb.Subscribe{Vni: 100}}}); err != nil {
		t.Fatal(err)
	}
	got := 0
	for {
		m, err := st.Recv()
		if err != nil {
			t.Fatalf("no EndOfRIB after %d of %d routes: %v", got, bigSnapshot, err)
		}
		switch {
		case m.GetEndOfGlobal() != nil:
			continue // the (empty) global snapshot every session gets on Hello
		case m.GetRouteUpdate() != nil:
			got++
			continue
		}
		eor := m.GetEndOfRib()
		if eor == nil {
			t.Fatalf("unexpected message inside the snapshot: %+v", m.Msg)
		}
		if got != bigSnapshot || eor.RecordCount != uint32(bigSnapshot) {
			t.Fatalf("received %d routes, marker says %d, want %d", got, eor.RecordCount, bigSnapshot)
		}
		return
	}
}

// A session that opts out of the global feed gets the marker — its consumer waits for it — and no
// NAT or public record, neither replayed nor live.
func TestSessionWithoutTheGlobalFeedGetsOnlyTheMarker(t *testing.T) {
	cl, rib := startServerWithRIB(t)
	rib.AnnounceNat("seed", NatBlock{Vni: 100, SourceIP: "10.0.0.1", NatIP: "198.51.100.1", PortMin: 1024, PortMax: 2048, OwnerUnderlay: "fd00::a"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	compute, err := cl.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := compute.Send(&pb.ClientMsg{Msg: &pb.ClientMsg_Hello{Hello: &pb.Hello{
		NodeId: "compute", GlobalFeed: pb.GlobalFeed_GLOBAL_FEED_NONE,
	}}}); err != nil {
		t.Fatal(err)
	}
	if err := compute.Send(&pb.ClientMsg{Msg: &pb.ClientMsg_Subscribe{Subscribe: &pb.Subscribe{Vni: 100}}}); err != nil {
		t.Fatal(err)
	}
	next := func() *pb.ServerMsg {
		t.Helper()
		m, err := compute.Recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		return m
	}
	if eog := next().GetEndOfGlobal(); eog == nil || eog.RecordCount != 0 {
		t.Fatal("want EndOfGlobal{0} first: the replayed NAT block must not reach an opted-out session")
	}
	if next().GetEndOfRib() == nil {
		t.Fatal("want the VNI's EndOfRIB next")
	}

	// A live NAT block, then a route in the subscribed VNI, from another session: the route arrives,
	// the NAT block never does.
	edge, err := cl.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, edge, "announcer")
	for _, m := range []*pb.ClientMsg{
		{Msg: &pb.ClientMsg_AnnounceNat{AnnounceNat: &pb.AnnounceNat{
			Vni: 100, SourceIp: "10.0.0.2", NatIp: "198.51.100.2", PortMin: 1024, PortMax: 2048, OwnerUnderlay: "fd00::b",
		}}},
		{Msg: &pb.ClientMsg_Announce{Announce: &pb.Announce{Vni: 100, Prefix: "10.0.0.2/32", NexthopUnderlay: "fd00::b"}}},
	} {
		if err := edge.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	if m := next(); m.GetRouteUpdate() == nil {
		t.Fatalf("want the route, and no NAT record before it; got %+v", m.Msg)
	}
}
