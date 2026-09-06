package reflector

import pb "github.com/trevex/ectobase/mesh/gen/routebusv1"

// PublicRecord is a globally-relevant "public" prefix advertised on the typed
// PublicPrefix channel: an edge anycast /128, a distributed-SNAT nat_ip block,
// an LB VIP, or a floating IP. Like NAT blocks, public records are GLOBAL (not
// per-VNI): every node learns every record so it can steer traffic to the owner.
type PublicRecord struct {
	Kind          pb.PublicKind
	Prefix        string
	OwnerUnderlay string
	Vni           uint32
	PortMin       uint32
	PortMax       uint32
	// OverlayIP is set for LB_VIP records: the backend guest's overlay IP, relayed
	// through so the learning edge can AddLbBackend with it.
	OverlayIP string
}

// publicKey identifies a record by (kind, prefix, owner). Duplicate announces
// with the same key are idempotent.
type publicKey struct {
	kind  pb.PublicKind
	pfx   string
	owner string
}

func (rec PublicRecord) key() publicKey {
	return publicKey{rec.Kind, rec.Prefix, rec.OwnerUnderlay}
}

// AnnouncePublic records a global public prefix owned by origin and broadcasts
// an ADD to ALL sinks (including the origin, so the owner learns its canonical
// record). Keyed by (kind, prefix, owner_underlay); re-announce is idempotent.
func (r *RIB) AnnouncePublic(origin string, rec PublicRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := rec.key()
	r.public[k] = rec
	if r.publicByOrigin[origin] == nil {
		r.publicByOrigin[origin] = map[publicKey]struct{}{}
	}
	r.publicByOrigin[origin][k] = struct{}{}
	r.publicFanout(rec, pb.RouteOp_ROUTE_OP_ADD)
}

// WithdrawPublic removes a global public prefix and broadcasts a WITHDRAW to all
// sinks. The record is matched by (kind, prefix, owner_underlay).
func (r *RIB) WithdrawPublic(origin string, rec PublicRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := rec.key()
	stored, ok := r.public[k]
	if !ok {
		return
	}
	delete(r.public, k)
	if m := r.publicByOrigin[origin]; m != nil {
		delete(m, k)
	}
	r.publicFanout(stored, pb.RouteOp_ROUTE_OP_WITHDRAW)
}

// dropOriginPublic withdraws every public record a node originated. Caller holds r.mu.
func (r *RIB) dropOriginPublic(origin string) {
	owned := r.publicByOrigin[origin]
	delete(r.publicByOrigin, origin)
	for k := range owned {
		if rec, ok := r.public[k]; ok {
			delete(r.public, k)
			r.publicFanout(rec, pb.RouteOp_ROUTE_OP_WITHDRAW)
		}
	}
}

// publicFanout sends a PublicUpdate to ALL sinks. Caller holds r.mu. Sink.Send
// is non-blocking, so holding the lock is safe.
func (r *RIB) publicFanout(rec PublicRecord, op pb.RouteOp) {
	m := publicUpdate(rec, op)
	for _, s := range r.sinks {
		s.Send(m)
	}
}

func publicUpdate(rec PublicRecord, op pb.RouteOp) *pb.ServerMsg {
	return &pb.ServerMsg{Msg: &pb.ServerMsg_PublicUpdate{PublicUpdate: &pb.PublicUpdate{
		Prefix: &pb.PublicPrefix{
			Kind:          rec.Kind,
			Prefix:        rec.Prefix,
			OwnerUnderlay: rec.OwnerUnderlay,
			Vni:           rec.Vni,
			PortMin:       rec.PortMin,
			PortMax:       rec.PortMax,
			OverlayIp:     rec.OverlayIP,
		},
		Op: op,
	}}}
}
