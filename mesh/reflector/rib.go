// Package reflector is the central route reflector: an in-memory per-VNI RIB
// (rib.go) exposed over the routebus.v1 gRPC Session stream (server.go).
package reflector

import (
	"log"
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
// LAST origin drops. origins maps an origin id -> the nexthops it announced — stored
// whether or not a fence currently hides them (see RIB.advertised).
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
// the session certificate's check (see underlayGuard.permits). A nil permit allows everything: a
// TEST-only shorthand for "skip the certificate check". mTLS-off dev mode never passes nil for
// this — it calls through guard.permits with enforce=false, which allows everything itself.
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

	// globalSnap is the NAT + public replay every session on the global feed receives, built once
	// and handed to all of them. The messages are immutable once built and a sink copies the
	// pointers it is given (sessionQueue appends them into its own pending), so sharing is free —
	// and it turns the peak after a reflector restart, when every edge reconnects at once, from
	// sessions x records into one copy. nil means "rebuild on the next registration".
	globalSnap []*pb.ServerMsg

	// fenced hides nexthops inside a node /64 (Tier-2 failover) from subscribers. It is a
	// filter on what is advertised, never a deletion: routes stay stored per origin, so
	// releasing a fence re-advertises them without the owning agent re-announcing — which
	// it would never do on a live session (it only sends its diff against what it already
	// sent). Keyed by the CIDR string.
	fenced map[string]*net.IPNet

	// origins names the session that currently speaks for each node id, so a session that has
	// been superseded cannot tear down its successor's state (everything else here is keyed by
	// node id alone). Tokens come from nextToken and are never reused.
	origins   map[string]uint64
	nextToken uint64
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
		origins:        map[string]uint64{},
	}
}

// Subscribe registers s for vni, streams the current table for that vni in a
// deterministic order, then EndOfRIB (a graceful-restart / prune marker).
//
// The snapshot carries each route as advertised — fence-filtered, and only the routes
// left with a nexthop — so it matches what the live fanout has told everyone else.
// SetFence and ClearFence recompute and fan out under r.mu too, so a subscriber can
// neither miss a fence change nor see one twice.
func (r *RIB) Subscribe(vni uint32, s Sink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	subs := r.subscribers[vni]
	if subs == nil {
		subs = map[string]Sink{}
		r.subscribers[vni] = subs
	}
	if held, ok := subs[s.ID()]; ok && held == s {
		// THIS session already has this VNI's table and every update since; replaying it would
		// queue another whole copy, and the only way to pile them up is a consumer that is not
		// draining. The agent diffs its desired set (mesh/agent/desired.go diffDesired), so it
		// never re-subscribes on a live session — and it resets its EndOfRIB epoch before each
		// Subscribe it sends, so one that got no replay would never converge. A client that wants
		// a fresh copy unsubscribes first.
		//
		// The sink identity, not just the node id, is what makes this a duplicate: the map is
		// keyed by node id, so a reconnect can find its predecessor's sink here and must replace
		// it and be replayed to like any new subscriber.
		log.Printf("reflector: session %s re-subscribed to VNI %d it already holds; not replaying", s.ID(), vni)
		return
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
		nhs := r.advertised(e)
		if len(nhs) == 0 {
			continue // fenced away
		}
		snap = append(snap, routeUpdate(k, nhs, pb.RouteOp_ROUTE_OP_ADD, e.external))
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
// (except the origin, which already has it). An announce whose nexthop is fenced is
// stored like any other; it is simply not advertised until the fence is released.
func (r *RIB) Announce(origin string, vni uint32, prefix string, nexthops []string, external bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := routeKey{vni, prefix}
	e := r.routes[k]
	if e.origins == nil {
		e.origins = map[string][]string{}
	}
	before := r.advertised(e)
	e.origins[origin] = nexthops
	e.external = external
	r.routes[k] = e
	if r.byOrigin[origin] == nil {
		r.byOrigin[origin] = map[routeKey]struct{}{}
	}
	r.byOrigin[origin][k] = struct{}{}
	// Only fan out when the effective advertised route actually changes — a second
	// anycast origin announcing an identical route must not churn subscribers, and an
	// announce hidden behind a fence has nothing to tell them yet.
	r.fanoutChange(k, before, r.advertised(e), origin, external)
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

// withdrawRouteOrigin removes one origin from a route and fans out the minimal change to
// what is advertised: WITHDRAW when nothing is left to advertise, otherwise re-ADD if the
// advertised nexthops changed (else nothing — including a withdraw of a route a fence
// already hides). Caller holds r.mu; byOrigin bookkeeping is the caller's job.
func (r *RIB) withdrawRouteOrigin(k routeKey, origin string) {
	e, ok := r.routes[k]
	if !ok {
		return
	}
	if _, has := e.origins[origin]; !has {
		return
	}
	before := r.advertised(e)
	delete(e.origins, origin)
	if len(e.origins) == 0 {
		delete(r.routes, k)
	} else {
		r.routes[k] = e
	}
	r.fanoutChange(k, before, r.advertised(e), "", e.external)
}

// dropOriginLocked withdraws every route, NAT block and public record a node originated, and
// clears its VNI subscriptions. Caller holds r.mu — ClaimOrigin and ReleaseOrigin both call this
// from inside the SAME critical section that decides whether this session still owns nodeID, so a
// decide-then-teardown split can never straddle a window where a successor claims, registers and
// announces before its predecessor's now-stale teardown runs and wipes it anyway.
func (r *RIB) dropOriginLocked(origin string) {
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

// dropOrigin is the locking wrapper over dropOriginLocked, for callers outside a session's
// claim/release lifecycle (tests exercising the RIB's bookkeeping directly). A live session's
// teardown goes through ReleaseOrigin, the one entry point for a session actually ending.
func (r *RIB) dropOrigin(origin string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropOriginLocked(origin)
}

// ClaimOrigin makes this session the live one for nodeID and returns its token. A node that
// reconnects while its previous session is still being timed out claims the id again: whatever
// that session left is dropped IN THIS SAME lock acquisition — installing the new token and
// tearing down the old session's state must be one critical section, or a successor that claims,
// registers a sink and announces before the predecessor's separately-locked cleanup runs gets
// wiped by it anyway. The sink delete also covers a predecessor that opted out of the global feed
// and so never registered one: deleting an absent key is a harmless no-op.
func (r *RIB) ClaimOrigin(nodeID string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, superseded := r.origins[nodeID]
	r.nextToken++
	token := r.nextToken
	r.origins[nodeID] = token
	if superseded {
		delete(r.sinks, nodeID)
		r.dropOriginLocked(nodeID)
	}
	return token
}

// ReleaseOrigin ends a session: it unregisters the sink and fast-withdraws everything the node
// announced — unless a newer session has already claimed the id, in which case this one has
// nothing left to tear down and must not touch its successor's state. The token check, the sink
// removal and the teardown all happen in ONE critical section for the same reason ClaimOrigin's
// does: split across separate lock acquisitions, a reconnect landing in the gap would be undone by
// its own predecessor's cleanup.
func (r *RIB) ReleaseOrigin(nodeID string, token uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, ok := r.origins[nodeID]
	if !ok || cur != token {
		return
	}
	delete(r.origins, nodeID)
	delete(r.sinks, nodeID)
	r.dropOriginLocked(nodeID)
}

// fanoutChange tells subscribers of k.vni (except origin) about a change in what is
// advertised for k: nothing when before and after agree, WITHDRAW when after is empty,
// otherwise ADD with the new set. Caller holds r.mu.
func (r *RIB) fanoutChange(k routeKey, before, after []string, origin string, external bool) {
	switch {
	case equalStrs(before, after):
	case len(after) == 0:
		r.fanout(k, nil, pb.RouteOp_ROUTE_OP_WITHDRAW, origin, external)
	default:
		r.fanout(k, after, pb.RouteOp_ROUTE_OP_ADD, origin, external)
	}
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

// SetFence hides every nexthop inside prefix (a node /64, or a pool's underlay aggregate)
// from subscribers and fans out each route that changes: WITHDRAW where nothing is left,
// ADD with the remaining nexthops where another origin still announces the key (an anycast
// route, or the pool a failed-over VM now runs on). Nothing is deleted — the owning agents
// never re-announce on a live session, so a deleted route would stay gone until their next
// reconnect. Idempotent. The fenced set is expected to be small (a handful of failed-over
// /64s), so the O(routes x fenced) scan is not a hot path.
func (r *RIB) SetFence(prefix string) {
	_, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.fenced[prefix]; ok {
		return
	}
	r.refilter(func() { r.fenced[prefix] = ipnet })
}

// ClearFence releases a fence and re-advertises every route it was hiding, from what the
// RIB still stores. That is exactly the set of workloads that stayed on the fenced nodes:
// failover releases a fence only once its /64 reports drained (no VMI left running there),
// and by then the recovered pool's agent has withdrawn the routes of the VMs that moved
// away — their interfaces are gone, and its level-triggered diff withdraws them within
// seconds — so nothing that failed over comes back. A release that ever outran that
// withdraw would advertise the stale nexthop beside the new pool's only until it lands.
func (r *RIB) ClearFence(prefix string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.fenced[prefix]; !ok {
		return
	}
	r.refilter(func() { delete(r.fenced, prefix) })
}

// refilter applies change to the fence set and fans out every route whose advertised
// nexthops it changed. Caller holds r.mu for the whole of it, so no announce, withdraw or
// subscribe can land between the before and after views.
func (r *RIB) refilter(change func()) {
	before := make(map[routeKey][]string, len(r.routes))
	for k, e := range r.routes {
		before[k] = r.advertised(e)
	}
	change()
	for k, e := range r.routes {
		r.fanoutChange(k, before[k], r.advertised(e), "", e.external)
	}
}

// advertised is the route subscribers see for e: the merged nexthops of every origin minus
// those inside a fenced prefix. Empty means the key is not advertised at all. Caller holds r.mu.
func (r *RIB) advertised(e routeEntry) []string {
	merged := mergeNexthops(e.origins)
	if len(r.fenced) == 0 {
		return merged
	}
	out := merged[:0]
	for _, nh := range merged {
		if !nexthopFenced(nh, r.fenced) {
			out = append(out, nh)
		}
	}
	return out
}

// HasRoute reports whether (vni, prefix) is currently advertised — stored AND left with a
// nexthop no fence hides — which is what a subscriber would see. Test/inspection helper.
func (r *RIB) HasRoute(vni uint32, prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.routes[routeKey{vni, prefix}]
	return ok && len(r.advertised(e)) > 0
}

func nexthopFenced(nh string, fenced map[string]*net.IPNet) bool {
	ip := net.ParseIP(nh)
	if ip == nil {
		return false
	}
	for _, ipnet := range fenced {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
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
