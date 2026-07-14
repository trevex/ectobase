package reflector

import pb "github.com/trevex/xdp-dp/netplane/gen/routebusv1"

// NatBlock is a deterministic egress SNAT block: overlay SourceIP (in Vni) is
// SNATed onto NatIP:[PortMin,PortMax) and owned by the node at OwnerUnderlay.
// NAT blocks are GLOBAL (not per-VNI): every node learns every block so a return
// packet that lands on the wrong node can re-route to the owner.
type NatBlock struct {
	Vni           uint32
	SourceIP      string
	NatIP         string
	PortMin       uint32
	PortMax       uint32
	OwnerUnderlay string
}

// natKey identifies a block by its NAT (public-IP, port-block-start).
type natKey struct {
	natIP   string
	portMin uint32
}

// RegisterSink adds s to the global sink set (every session, regardless of the
// VNIs it subscribes to) and replays the current NAT snapshot. Called on Hello.
func (r *RIB) RegisterSink(s Sink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sinks[s.ID()] = s
	for k := range r.nat {
		b := r.nat[k]
		s.Send(natUpdate(b, pb.RouteOp_ROUTE_OP_ADD))
	}
	for k := range r.public {
		s.Send(publicUpdate(r.public[k], pb.RouteOp_ROUTE_OP_ADD))
	}
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
