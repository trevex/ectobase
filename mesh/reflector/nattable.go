package reflector

import (
	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"github.com/trevex/ectobase/mesh/routebus"
)

// NatBlock aliases the shared routebus.NatBlock: a deterministic egress SNAT
// block where overlay SourceIP (in Vni) is SNATed onto NatIP:[PortMin,PortMax)
// and owned by the node at OwnerUnderlay. Blocks are GLOBAL rather than per-VNI: every session
// registered for the global feed learns every block, so a return packet landing on it can re-route
// to the owner. Only WAN edges register (see Hello.global_feed); every node still announces its own.
type NatBlock = routebus.NatBlock

// natKey identifies a block by its NAT (public-IP, port-block-start).
type natKey struct {
	natIP   string
	portMin uint32
}

// RegisterSink adds s to the global sink set — the sessions that asked for the global feed,
// regardless of the VNIs they subscribe to — and replays the current NAT + public snapshot,
// closing it with EndOfGlobal. Called on Hello, for a session that did not opt out; one that did
// is sent the bare marker instead and never joins this set.
//
// The replay and its marker go to the sink as ONE snapshot, handed over while r.mu is still
// held. The sink queues a snapshot whole (see Sink), and a concurrent Announce/Withdraw fanout
// cannot interleave with it or slip in ahead of the marker — so the marker's record count is
// exactly what the consumer receives before it. The consumer still checks that count before it
// prunes (see the EndOfGlobal doc in routebus.proto): an older reflector dropped snapshot
// records, and pruning against a lossy snapshot would withdraw live state.
func (r *RIB) RegisterSink(s Sink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sinks[s.ID()] = s
	snap := make([]*pb.ServerMsg, 0, len(r.nat)+len(r.public)+1)
	var n uint32
	for k := range r.nat {
		snap = append(snap, natUpdate(r.nat[k], pb.RouteOp_ROUTE_OP_ADD))
		n++
	}
	for k := range r.public {
		snap = append(snap, publicUpdate(r.public[k], pb.RouteOp_ROUTE_OP_ADD))
		n++
	}
	snap = append(snap, &pb.ServerMsg{Msg: &pb.ServerMsg_EndOfGlobal{
		EndOfGlobal: &pb.EndOfGlobal{RecordCount: n},
	}})
	s.SendSnapshot(snap)
}

// UnregisterSink removes s from the global sink set (on disconnect). Its NAT
// blocks are withdrawn separately via DropOrigin.
func (r *RIB) UnregisterSink(sinkID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sinks, sinkID)
}

// AnnounceNat records a global NAT block owned by origin and broadcasts an ADD
// to ALL sinks (including the origin, so the owner learns its canonical block).
func (r *RIB) AnnounceNat(origin string, b NatBlock) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := natKey{b.NatIP, b.PortMin}
	r.nat[k] = b
	if r.natByOrigin[origin] == nil {
		r.natByOrigin[origin] = map[natKey]struct{}{}
	}
	r.natByOrigin[origin][k] = struct{}{}
	r.natFanout(b, pb.RouteOp_ROUTE_OP_ADD)
}

// WithdrawNat removes a global NAT block and broadcasts a WITHDRAW to all sinks.
func (r *RIB) WithdrawNat(origin, natIP string, portMin, portMax uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := natKey{natIP, portMin}
	b, ok := r.nat[k]
	if !ok {
		return
	}
	delete(r.nat, k)
	if m := r.natByOrigin[origin]; m != nil {
		delete(m, k)
	}
	r.natFanout(b, pb.RouteOp_ROUTE_OP_WITHDRAW)
}

// dropOriginNat withdraws every NAT block a node originated. Caller holds r.mu.
func (r *RIB) dropOriginNat(origin string) {
	owned := r.natByOrigin[origin]
	delete(r.natByOrigin, origin)
	for k := range owned {
		if b, ok := r.nat[k]; ok {
			delete(r.nat, k)
			r.natFanout(b, pb.RouteOp_ROUTE_OP_WITHDRAW)
		}
	}
}

// natFanout sends a NatUpdate to ALL sinks. Caller holds r.mu. Sink.Send is
// non-blocking, so holding the lock is safe.
func (r *RIB) natFanout(b NatBlock, op pb.RouteOp) {
	m := natUpdate(b, op)
	for _, s := range r.sinks {
		s.Send(m)
	}
}

func natUpdate(b NatBlock, op pb.RouteOp) *pb.ServerMsg {
	return &pb.ServerMsg{Msg: &pb.ServerMsg_NatUpdate{NatUpdate: &pb.NatUpdate{
		Vni:           b.Vni,
		SourceIp:      b.SourceIP,
		NatIp:         b.NatIP,
		PortMin:       b.PortMin,
		PortMax:       b.PortMax,
		OwnerUnderlay: b.OwnerUnderlay,
		Op:            op,
	}}}
}
