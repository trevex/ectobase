package reflector

import (
	"io"
	"sync"

	pb "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server adapts the RIB to the RouteBus.Session bidi stream.
type Server struct {
	pb.UnimplementedRouteBusServer
	rib *RIB
}

func NewServer(rib *RIB) *Server { return &Server{rib: rib} }

// chanSink is a subscriber's non-blocking outbound queue. A dedicated goroutine
// drains it onto the stream (gRPC allows only one concurrent Send per stream).
type chanSink struct {
	id string
	ch chan *pb.ServerMsg
}

func (c *chanSink) ID() string { return c.id }
func (c *chanSink) Send(m *pb.ServerMsg) {
	select {
	case c.ch <- m:
	default:
		// Slow consumer: drop. Recovered on the next full-table resync (reconnect).
	}
}

func (s *Server) Session(stream pb.RouteBus_SessionServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	h := first.GetHello()
	if h == nil || h.NodeId == "" {
		return status.Error(codes.InvalidArgument, "first message must be Hello with node_id")
	}
	sink := &chanSink{id: h.NodeId, ch: make(chan *pb.ServerMsg, 1024)}
	// Register globally on Hello: NAT blocks broadcast to every session (not just
	// VNI subscribers), and this replays the current NAT snapshot to the new peer.
	s.rib.RegisterSink(sink)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for m := range sink.ch {
			if err := stream.Send(m); err != nil {
				return
			}
		}
	}()
	defer func() {
		s.rib.UnregisterSink(sink.id) // stop broadcasting NAT updates to this dead session
		s.rib.DropOrigin(sink.id)     // fast-withdraw this node's routes AND NAT blocks on disconnect
		close(sink.ch)
		wg.Wait()
	}()

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch m := msg.Msg.(type) {
		case *pb.ClientMsg_Subscribe:
			s.rib.Subscribe(m.Subscribe.Vni, sink)
		case *pb.ClientMsg_Unsubscribe:
			s.rib.Unsubscribe(m.Unsubscribe.Vni, sink.id)
		case *pb.ClientMsg_Announce:
			a := m.Announce
			nh := append([]string{a.NexthopUnderlay}, a.ExtraNexthops...)
			s.rib.Announce(sink.id, a.Vni, a.Prefix, nh, a.External)
		case *pb.ClientMsg_Withdraw:
			s.rib.Withdraw(sink.id, m.Withdraw.Vni, m.Withdraw.Prefix)
		case *pb.ClientMsg_AnnounceNat:
			a := m.AnnounceNat
			s.rib.AnnounceNat(sink.id, NatBlock{
				Vni: a.Vni, SourceIP: a.SourceIp, NatIP: a.NatIp,
				PortMin: a.PortMin, PortMax: a.PortMax, OwnerUnderlay: a.OwnerUnderlay,
			})
		case *pb.ClientMsg_WithdrawNat:
			w := m.WithdrawNat
			s.rib.WithdrawNat(sink.id, w.NatIp, w.PortMin, w.PortMax)
		case *pb.ClientMsg_KeepAlive, *pb.ClientMsg_Hello:
			// keepalive: transport-level for v1; duplicate hello ignored.
		}
	}
}
