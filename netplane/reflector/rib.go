// Package reflector is the central route reflector: an in-memory per-VNI RIB
// (rib.go) exposed over the routebus.v1 gRPC Session stream (server.go).
package reflector

import (
	"sort"
	"sync"

	pb "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
)

// Sink is a subscriber's outbound path. Send MUST NOT block — implementations
// enqueue to a buffered channel and drop on overflow (recovered by a resync).
type Sink interface {
	ID() string
	Send(*pb.ServerMsg)
}

type routeKey struct {
	vni    uint32
	prefix string
}

type routeEntry struct {
	nexthops []string
	origin   string
	external bool
}

// RIB is the reflector's global route table. Safe for concurrent use. It also
// holds the GLOBAL NAT table (nattable.go): per-VNI routes are fanned out to
// VNI subscribers, whereas NAT blocks broadcast to every session (r.sinks).
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

	sinks map[string]Sink // every connected session, keyed by node id
}

func NewRIB() *RIB {
	return &RIB{
		routes:      map[routeKey]routeEntry{},
		byOrigin:    map[string]map[routeKey]struct{}{},
		subscribers: map[uint32]map[string]Sink{},
		nat:            map[natKey]NatBlock{},
		natByOrigin:    map[string]map[natKey]struct{}{},
		public:         map[publicKey]PublicRecord{},
		publicByOrigin: map[string]map[publicKey]struct{}{},
		sinks:          map[string]Sink{},
	}
}

// Subscribe registers s for vni, streams the current table for that vni in a
// deterministic order, then EndOfRIB (a graceful-restart / prune marker).
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
	for _, k := range keys {
		e := r.routes[k]
		s.Send(routeUpdate(k, e.nexthops, pb.RouteOp_ROUTE_OP_ADD, e.external))
	}
	s.Send(&pb.ServerMsg{Msg: &pb.ServerMsg_EndOfRib{EndOfRib: &pb.EndOfRIB{Vni: vni}}})
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
	k := routeKey{vni, prefix}
	r.routes[k] = routeEntry{nexthops: nexthops, origin: origin, external: external}
	if r.byOrigin[origin] == nil {
		r.byOrigin[origin] = map[routeKey]struct{}{}
	}
	r.byOrigin[origin][k] = struct{}{}
	r.fanout(k, nexthops, pb.RouteOp_ROUTE_OP_ADD, origin, external)
}

// Withdraw removes a route and fans out a WITHDRAW.
func (r *RIB) Withdraw(origin string, vni uint32, prefix string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := routeKey{vni, prefix}
	if _, ok := r.routes[k]; !ok {
		return
	}
	delete(r.routes, k)
	if m := r.byOrigin[origin]; m != nil {
		delete(m, k)
	}
	r.fanout(k, nil, pb.RouteOp_ROUTE_OP_WITHDRAW, "", false)
}

// DropOrigin withdraws every route a node originated and clears its
// subscriptions (called when the node's session ends / liveness is lost).
func (r *RIB) DropOrigin(origin string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	owned := r.byOrigin[origin]
	delete(r.byOrigin, origin)
	for k := range owned {
		if _, ok := r.routes[k]; ok {
			delete(r.routes, k)
			r.fanout(k, nil, pb.RouteOp_ROUTE_OP_WITHDRAW, "", false)
		}
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

func routeUpdate(k routeKey, nexthops []string, op pb.RouteOp, external bool) *pb.ServerMsg {
	return &pb.ServerMsg{Msg: &pb.ServerMsg_RouteUpdate{RouteUpdate: &pb.RouteUpdate{
		Vni:      k.vni,
		Prefix:   k.prefix,
		Nexthops: nexthops,
		Op:       op,
		External: external,
	}}}
}
