// Package reflector is the central route reflector: an in-memory per-VNI RIB
// (rib.go) exposed over the routebus.v1 gRPC Session stream (server.go).
package reflector

import (
	"net"
	"sort"
	"sync"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// Sink is a subscriber's outbound path. Neither method may block: the RIB calls both with its
// lock held.
//   - Send carries one live delta (a fanout). It may be dropped when the consumer has fallen far
//     behind; that consumer converges on its next reconnect's snapshot.
//   - SendSnapshot carries a whole replay — every record and the marker that closes it — and must
//     queue all of it, in order: a replay missing records or its marker can neither be pruned
//     against nor ever report converged.
type Sink interface {
	ID() string
	Send(*pb.ServerMsg)
	SendSnapshot([]*pb.ServerMsg)
}

type routeKey struct {
	vni    uint32
	prefix string
}

// routeEntry reference-counts a (vni, prefix) route by origin: HA anycast edges all
// announce the same route (e.g. 0.0.0.0/0 -> the anycast edge underlay), so the route
// must stay advertised while ANY origin announces it and only be withdrawn when the
// LAST origin drops. origins maps an origin id -> the nexthops it announced.
type routeEntry struct {
	origins  map[string][]string
	external bool
}

// mergeNexthops is the deduped, sorted union of every origin's nexthops (deterministic).
func mergeNexthops(origins map[string][]string) []string {
	set := map[string]struct{}{}
	for _, nhs := range origins {
		for _, nh := range nhs {
			set[nh] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for nh := range set {
		out = append(out, nh)
	}
	sort.Strings(out)
	return out
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// OwnerPermit reports whether the session asking may act on a record owned by `ownerUnderlay` —
// the session certificate's check (see underlayGuard.permits). A nil permit allows everything:
// mTLS-off dev mode, and tests that are not about the certificate.
type OwnerPermit func(ownerUnderlay string) bool

func (p OwnerPermit) allows(ownerUnderlay string) bool {
	return p == nil || p(ownerUnderlay)
}

// WithdrawOutcome distinguishes a withdraw that changed nothing because the record was already
// gone (routine — agents withdraw idempotently) from one that was refused, so only the latter is
// worth logging.
type WithdrawOutcome int

const (
	WithdrawApplied WithdrawOutcome = iota
	WithdrawAbsent
	WithdrawRefused
)

func (o WithdrawOutcome) String() string {
	switch o {
	case WithdrawApplied:
		return "applied"
	case WithdrawAbsent:
		return "absent"
	default:
		return "refused"
	}
}

// RIB is the reflector's global route table. Safe for concurrent use. It also
// holds the GLOBAL NAT table (nattable.go): per-VNI routes are fanned out to
// VNI subscribers, whereas NAT blocks broadcast to every session registered for the global feed
// (r.sinks) — the WAN edges, which are the only consumers.
type RIB struct {
	mu          sync.Mutex
	routes      map[routeKey]routeEntry
	byOrigin    map[string]map[routeKey]struct{}
	subscribers map[uint32]map[string]Sink

	// Global NAT state, broadcast to all sinks regardless of VNI subscription.
	nat         map[natKey]NatBlock
	natByOrigin map[string]map[natKey]struct{}

	// Global PublicPrefix state (publictable.go), broadcast to all sinks.
	public         map[publicKey]PublicRecord
	publicByOrigin map[string]map[publicKey]struct{}

	// natOrigin/publicOrigin name the origin that announced each record, so ownership is one
	// lookup and a takeover moves the key out of the previous origin's set in O(1).
	natOrigin    map[natKey]string
	publicOrigin map[publicKey]string

	// sinks is the global fanout set, keyed by node id: the connected sessions that ASKED for the
	// global feed on Hello, which is only the WAN edges — nothing else consumes NAT or public
	// records. A session that opted out is never added, so it costs the fanout nothing.
	sinks map[string]Sink

	// fenced blocks nexthops inside a node /64 (Tier-2 failover): announces whose
	// nexthop falls inside a fenced prefix are rejected, and stored matching routes
	// are withdrawn. Keyed by the /64 CIDR string.
	fenced map[string]*net.IPNet
}

func NewRIB() *RIB {
	return &RIB{
		routes:         map[routeKey]routeEntry{},
		byOrigin:       map[string]map[routeKey]struct{}{},
		subscribers:    map[uint32]map[string]Sink{},
		nat:            map[natKey]NatBlock{},
		natByOrigin:    map[string]map[natKey]struct{}{},
		public:         map[publicKey]PublicRecord{},
		publicByOrigin: map[string]map[publicKey]struct{}{},
		natOrigin:      map[natKey]string{},
		publicOrigin:   map[publicKey]string{},
		sinks:          map[string]Sink{},
		fenced:         map[string]*net.IPNet{},
	}
}

// Subscribe registers s for vni, streams the current table for that vni in a
// deterministic order, then EndOfRIB (a graceful-restart / prune marker).
//
// No fence filtering is needed here: a fenced /64 can never have a route in
// r.routes (Announce drops fenced-nexthop routes and SetFence withdraws any
// already-stored ones, both under r.mu), so the snapshot is inherently
// fence-clean. A subscriber that races an in-flight SetFence converges via the
// WITHDRAW dropRouteAllOrigins fans out to all current sinks.
func (r *RIB) Subscribe(vni uint32, s Sink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	subs := r.subscribers[vni]
	if subs == nil {
		subs = map[string]Sink{}
		r.subscribers[vni] = subs
	}
	subs[s.ID()] = s

	var keys []routeKey
	for k := range r.routes {
		if k.vni == vni {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].prefix < keys[j].prefix })
	snap := make([]*pb.ServerMsg, 0, len(keys)+1)
	var n uint32
	for _, k := range keys {
		e := r.routes[k]
		snap = append(snap, routeUpdate(k, mergeNexthops(e.origins), pb.RouteOp_ROUTE_OP_ADD, e.external))
		n++
	}
	// One snapshot, handed over while r.mu is still held: the sink queues all of it (see Sink), and
	// no concurrent fanout can interleave with it or slip in ahead of the marker, so the marker's
	// count is exactly what the subscriber receives before it.
	snap = append(snap, &pb.ServerMsg{Msg: &pb.ServerMsg_EndOfRib{EndOfRib: &pb.EndOfRIB{Vni: vni, RecordCount: n}}})
	s.SendSnapshot(snap)
}

func (r *RIB) Unsubscribe(vni uint32, sinkID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if subs := r.subscribers[vni]; subs != nil {
		delete(subs, sinkID)
		if len(subs) == 0 {
			delete(r.subscribers, vni)
		}
	}
}

// Announce inserts/replaces a route and fans out an ADD to subscribers of vni
// (except the origin, which already has it).
func (r *RIB) Announce(origin string, vni uint32, prefix string, nexthops []string, external bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if anyNexthopFenced(nexthops, r.fenced) {
		return // drop: this nexthop is fenced
	}
	k := routeKey{vni, prefix}
	e := r.routes[k]
	if e.origins == nil {
		e.origins = map[string][]string{}
	}
	before := mergeNexthops(e.origins)
	e.origins[origin] = nexthops
	e.external = external
	r.routes[k] = e
	if r.byOrigin[origin] == nil {
		r.byOrigin[origin] = map[routeKey]struct{}{}
	}
	r.byOrigin[origin][k] = struct{}{}
	// Only fan out when the effective advertised route actually changes — a second
	// anycast origin announcing an identical route must not churn subscribers.
	after := mergeNexthops(e.origins)
	if len(before) == 0 || !equalStrs(before, after) {
		r.fanout(k, after, pb.RouteOp_ROUTE_OP_ADD, origin, external)
	}
}

// Withdraw removes a route and fans out a WITHDRAW.
func (r *RIB) Withdraw(origin string, vni uint32, prefix string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := routeKey{vni, prefix}
	if m := r.byOrigin[origin]; m != nil {
		delete(m, k)
	}
	r.withdrawRouteOrigin(k, origin)
}

// withdrawRouteOrigin removes one origin from a route and fans out the minimal change:
// WITHDRAW only when the last origin is gone, otherwise re-ADD if the merged nexthops
// changed (else nothing). Caller holds r.mu; byOrigin bookkeeping is the caller's job.
func (r *RIB) withdrawRouteOrigin(k routeKey, origin string) {
	e, ok := r.routes[k]
	if !ok {
		return
	}
	if _, has := e.origins[origin]; !has {
		return
	}
	before := mergeNexthops(e.origins)
	delete(e.origins, origin)
	if len(e.origins) == 0 {
		delete(r.routes, k)
		r.fanout(k, nil, pb.RouteOp_ROUTE_OP_WITHDRAW, "", false)
		return
	}
	r.routes[k] = e
	if after := mergeNexthops(e.origins); !equalStrs(before, after) {
		r.fanout(k, after, pb.RouteOp_ROUTE_OP_ADD, "", e.external)
	}
}

// DropOrigin withdraws every route a node originated and clears its
// subscriptions (called when the node's session ends / liveness is lost).
func (r *RIB) DropOrigin(origin string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	owned := r.byOrigin[origin]
	delete(r.byOrigin, origin)
	for k := range owned {
		r.withdrawRouteOrigin(k, origin)
	}
	for vni, subs := range r.subscribers {
		delete(subs, origin)
		if len(subs) == 0 {
			delete(r.subscribers, vni)
		}
	}
	r.dropOriginNat(origin)
	r.dropOriginPublic(origin)
}

// fanout sends an update to all subscribers of k.vni except origin. Caller holds r.mu.
// Sink.Send is non-blocking, so holding the lock here is safe.
func (r *RIB) fanout(k routeKey, nexthops []string, op pb.RouteOp, origin string, external bool) {
	for id, s := range r.subscribers[k.vni] {
		if id == origin {
			continue
		}
		s.Send(routeUpdate(k, nexthops, op, external))
	}
}

// SetFence blocks a node /64: rejects future announces whose nexthop is inside it and
// withdraws already-stored matching routes. Idempotent. The fenced set is expected to be
// small (a handful of failed-over /64s), so the O(routes x fenced) scan is not a hot path.
func (r *RIB) SetFence(prefix string) {
	_, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return
	}
	r.mu.Lock()
	r.fenced[prefix] = ipnet
	var victims []routeKey
	for k, e := range r.routes {
		for _, nhs := range e.origins {
			if anyNexthopFenced(nhs, r.fenced) {
				victims = append(victims, k)
				break
			}
		}
	}
	r.mu.Unlock()
	for _, k := range victims {
		r.dropRouteAllOrigins(k)
	}
}

// ClearFence removes a /64 block. Routes are restored by the owning agents' next resync.
func (r *RIB) ClearFence(prefix string) {
	r.mu.Lock()
	delete(r.fenced, prefix)
	r.mu.Unlock()
}

// HasRoute reports whether (vni, prefix) is currently stored. Test/inspection helper.
func (r *RIB) HasRoute(vni uint32, prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.routes[routeKey{vni, prefix}]
	return ok
}

func anyNexthopFenced(nexthops []string, fenced map[string]*net.IPNet) bool {
	for _, nh := range nexthops {
		ip := net.ParseIP(nh)
		if ip == nil {
			continue
		}
		for _, ipnet := range fenced {
			if ipnet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// dropRouteAllOrigins removes a route entirely (all origins) and fans out a single
// WITHDRAW to subscribers. Used by SetFence to evict a fenced node's routes.
func (r *RIB) dropRouteAllOrigins(k routeKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.routes[k]
	if !ok {
		return
	}
	for origin := range e.origins {
		if s, ok := r.byOrigin[origin]; ok {
			delete(s, k)
		}
	}
	delete(r.routes, k)
	// fanout requires r.mu held (it reads r.subscribers); Sink.Send is non-blocking.
	r.fanout(k, nil, pb.RouteOp_ROUTE_OP_WITHDRAW, "", e.external)
}

func routeUpdate(k routeKey, nexthops []string, op pb.RouteOp, external bool) *pb.ServerMsg {
	return &pb.ServerMsg{Msg: &pb.ServerMsg_RouteUpdate{RouteUpdate: &pb.RouteUpdate{
		Vni:      k.vni,
		Prefix:   k.prefix,
		Nexthops: nexthops,
		Op:       op,
		External: external,
	}}}
}
