package reflector

import (
	"io"
	"log"
	"slices"
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

	// Claim the node id for THIS session: a reconnect that beat its predecessor's timeout drops
	// what that session left, and the predecessor's cleanup will not touch this one's state.
	token := s.rib.ClaimOrigin(h.NodeId)

	sink := newSessionQueue(h.NodeId)
	if h.GetGlobalFeed() == pb.GlobalFeed_GLOBAL_FEED_NONE {
		// Opted out of the global channel (a compute node): never registered for NAT + public
		// fanout, but still sent the marker — its consumer waits for it to converge.
		sink.SendSnapshot([]*pb.ServerMsg{{Msg: &pb.ServerMsg_EndOfGlobal{EndOfGlobal: &pb.EndOfGlobal{}}}})
	} else {
		// Register globally on Hello: NAT + public records broadcast to every such session, and
		// this replays the current snapshot to the new peer.
		s.rib.RegisterSink(sink)
	}

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
		s.rib.ReleaseOrigin(sink.id, token) // unregister + fast-withdraw, unless superseded
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
			// Every nexthop is checked, not just the primary: agents program the first of the
			// reflector's sorted nexthop set, so an unchecked extra could name a peer's VTEP and
			// draw its traffic. One bad nexthop rejects the whole Announce rather than leaving a
			// partial route set. (The RIB dedups and sorts on advertise, so nothing else to do.)
			nh := append([]string{a.NexthopUnderlay}, a.ExtraNexthops...)
			if bad := slices.IndexFunc(nh, func(n string) bool { return !guard.permits(n) }); bad >= 0 {
				log.Printf("reflector: reject Announce from %s: nexthop %q not authorized by client cert", sink.id, nh[bad])
				continue
			}
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
			if out := s.rib.WithdrawNat(sink.id, w.NatIp, w.PortMin, w.PortMax, guard.permits); out == WithdrawRefused {
				log.Printf("reflector: reject WithdrawNat from %s: %s:[%d,%d) is not its block, or its certificate does not speak for the owner",
					sink.id, w.NatIp, w.PortMin, w.PortMax)
			}
		case *pb.ClientMsg_AnnouncePublic:
			p := m.AnnouncePublic
			if !guard.permits(p.OwnerUnderlay) {
				log.Printf("reflector: reject AnnouncePublic from %s: owner %q not authorized by client cert", sink.id, p.OwnerUnderlay)
				continue
			}
			// An EDGE_UNDERLAY record's prefix is an underlay address too (the edge's anycast
			// datapath /128, which agents map to the owner loopback), so the cert must cover it.
			if p.Kind == pb.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY && !guard.permits(hostAddr(p.Prefix)) {
				log.Printf("reflector: reject AnnouncePublic from %s: EDGE_UNDERLAY prefix %q not authorized by client cert", sink.id, p.Prefix)
				continue
			}
			s.rib.AnnouncePublic(sink.id, publicRecordFromPB(p))
		case *pb.ClientMsg_WithdrawPublic:
			p := m.WithdrawPublic
			rec := publicRecordFromPB(p)
			if out := s.rib.WithdrawPublic(sink.id, rec, guard.permits); out == WithdrawRefused {
				log.Printf("reflector: reject WithdrawPublic from %s: %s %s is not its record, or its certificate does not speak for the owner",
					sink.id, rec.Kind, rec.Prefix)
			}
		case *pb.ClientMsg_KeepAlive, *pb.ClientMsg_Hello:
			// keepalive: transport-level for v1; duplicate hello ignored.
		}
	}
}
