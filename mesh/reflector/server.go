package reflector

import (
	"io"
	"log"
	"sync"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server adapts the RIB to the RouteBus.Session bidi stream.
type Server struct {
	pb.UnimplementedRouteBusServer
	rib *RIB
}

func NewServer(rib *RIB) *Server { return &Server{rib: rib} }

func (s *Server) Session(stream pb.RouteBus_SessionServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	h := first.GetHello()
	if h == nil || h.NodeId == "" {
		return status.Error(codes.InvalidArgument, "first message must be Hello with node_id")
	}
	// Underlay authz: the session may only announce nexthops/owners equal to its client cert's
	// IP SANs (the node's underlay /128). No-op when mTLS is off (no verified cert).
	guard := newUnderlayGuard(stream.Context())

	sink := newSessionQueue(h.NodeId)
	// Register globally on Hello: NAT + public records broadcast to every session (not just
	// VNI subscribers), and this replays the current global snapshot to the new peer.
	s.rib.RegisterSink(sink)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			batch, ok := sink.take()
			if !ok {
				return
			}
			for i, m := range batch {
				if err := stream.Send(m); err != nil {
					log.Printf("reflector: session %s: send: %v", sink.id, err)
					sink.close() // the stream is gone: stop queueing for it
					return
				}
				batch[i] = nil // sent: let a huge snapshot's messages be GC'd as the batch drains
			}
		}
	}()
	defer func() {
		s.rib.UnregisterSink(sink.id) // stop broadcasting NAT/public updates to this dead session
		s.rib.DropOrigin(sink.id)     // fast-withdraw this node's routes AND NAT/public records on disconnect
		sink.close()
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
			if !guard.permits(a.NexthopUnderlay) {
				log.Printf("reflector: reject Announce from %s: nexthop %q not authorized by client cert", sink.id, a.NexthopUnderlay)
				continue
			}
			nh := append([]string{a.NexthopUnderlay}, a.ExtraNexthops...)
			s.rib.Announce(sink.id, a.Vni, a.Prefix, nh, a.External)
		case *pb.ClientMsg_Withdraw:
			s.rib.Withdraw(sink.id, m.Withdraw.Vni, m.Withdraw.Prefix)
		case *pb.ClientMsg_AnnounceNat:
			a := m.AnnounceNat
			if !guard.permits(a.OwnerUnderlay) {
				log.Printf("reflector: reject AnnounceNat from %s: owner %q not authorized by client cert", sink.id, a.OwnerUnderlay)
				continue
			}
			s.rib.AnnounceNat(sink.id, NatBlock{
				Vni: a.Vni, SourceIP: a.SourceIp, NatIP: a.NatIp,
				PortMin: a.PortMin, PortMax: a.PortMax, OwnerUnderlay: a.OwnerUnderlay,
			})
		case *pb.ClientMsg_WithdrawNat:
			w := m.WithdrawNat
			s.rib.WithdrawNat(sink.id, w.NatIp, w.PortMin, w.PortMax)
		case *pb.ClientMsg_AnnouncePublic:
			p := m.AnnouncePublic
			if !guard.permits(p.OwnerUnderlay) {
				log.Printf("reflector: reject AnnouncePublic from %s: owner %q not authorized by client cert", sink.id, p.OwnerUnderlay)
				continue
			}
			s.rib.AnnouncePublic(sink.id, publicRecordFromPB(p))
		case *pb.ClientMsg_WithdrawPublic:
			p := m.WithdrawPublic
			s.rib.WithdrawPublic(sink.id, publicRecordFromPB(p))
		case *pb.ClientMsg_KeepAlive, *pb.ClientMsg_Hello:
			// keepalive: transport-level for v1; duplicate hello ignored.
		}
	}
}
