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
//
// The replay itself is shared with every other session on the feed (see globalSnapshotLocked), so
// registering costs the messages only once no matter how many edges reconnect at the same time.
func (r *RIB) RegisterSink(s Sink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sinks[s.ID()] = s
	s.SendSnapshot(r.globalSnapshotLocked())
}

// globalSnapshotLocked returns the shared NAT + public replay and its EndOfGlobal marker,
// rebuilding it if a mutation dropped the last one. Caller holds r.mu. The returned slice is
// shared with every other session on the feed and must never be mutated by a caller.
func (r *RIB) globalSnapshotLocked() []*pb.ServerMsg {
	if r.globalSnap != nil {
		return r.globalSnap
	}
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
	r.globalSnap = snap
	return snap
}

// unregisterSink removes s from the global sink set. A live session's teardown goes through
// ReleaseOrigin, which removes it from r.sinks itself inside its own critical section; this
// locking form exists for callers exercising the global-feed bookkeeping directly.
func (r *RIB) unregisterSink(sinkID string) {
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
	// A block moves when its owner drains and another node takes the range over. Move the key to
	// the new origin: left in the old one's set, that origin's disconnect would withdraw the NEW
	// owner's block.
	if prev, ok := r.natOrigin[k]; ok && prev != origin {
		delete(r.natByOrigin[prev], k)
	}
	r.nat[k] = b
	r.natOrigin[k] = origin
	if r.natByOrigin[origin] == nil {
		r.natByOrigin[origin] = map[natKey]struct{}{}
	}
	r.natByOrigin[origin][k] = struct{}{}
	r.natFanout(b, pb.RouteOp_ROUTE_OP_ADD)
}

// WithdrawNat removes a global NAT block and broadcasts a WITHDRAW to every session that takes
// the global feed — but only if the block is the caller's to withdraw: announced by THIS origin,
// and with an owner underlay the session's certificate speaks for. Both matter: `node_id` is
// self-asserted, so the origin check alone falls to anyone who claims a node's id, and the
// certificate is what actually binds the record to the node that holds its address.
func (r *RIB) WithdrawNat(origin, natIP string, portMin, portMax uint32, permit OwnerPermit) WithdrawOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := natKey{natIP, portMin}
	b, ok := r.nat[k]
	if !ok {
		return WithdrawAbsent
	}
	if r.natOrigin[k] != origin || !permit.allows(b.OwnerUnderlay) {
		return WithdrawRefused
	}
	delete(r.nat, k)
	delete(r.natOrigin, k)
	delete(r.natByOrigin[origin], k)
	r.natFanout(b, pb.RouteOp_ROUTE_OP_WITHDRAW)
	return WithdrawApplied
}

// dropOriginNat withdraws every NAT block a node originated. Caller holds r.mu.
func (r *RIB) dropOriginNat(origin string) {
	owned := r.natByOrigin[origin]
	delete(r.natByOrigin, origin)
	for k := range owned {
		// Defense in depth: natByOrigin says origin once held k, but the reverse index is the
		// authority on who holds it NOW. A future bug that leaves a stale entry in the wrong
		// origin's set must be a no-op here, not a withdraw of whoever actually owns k.
		if r.natOrigin[k] != origin {
			continue
		}
		if b, ok := r.nat[k]; ok {
			delete(r.nat, k)
			delete(r.natOrigin, k)
			r.natFanout(b, pb.RouteOp_ROUTE_OP_WITHDRAW)
		}
	}
}

// natFanout sends a NatUpdate to ALL sinks. Caller holds r.mu. Sink.Send is
// non-blocking, so holding the lock is safe.
func (r *RIB) natFanout(b NatBlock, op pb.RouteOp) {
	// The table just changed, so the shared replay is stale. This is the one place every write to
	// r.nat passes through under r.mu (announce, withdraw and each key of a dropped origin), which
	// is why the invalidation lives here rather than at each mutation site. A fanout without a
	// mutation would only cost one rebuild.
	r.globalSnap = nil
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
