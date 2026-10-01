// Package agent is the per-node control plane: a route-bus client that announces
// local endpoint routes, subscribes by VNI, and drives the local flowplane datapath
// as remote routes arrive.
package agent

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	dpv1 "github.com/trevex/ectobase/cni/gen/dataplanev1"
	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"github.com/trevex/ectobase/mesh/routebus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Dataplane is the subset of flowplane the agent drives. dpAdapter wraps the real
// DataplaneNode gRPC client; tests supply a fake.
type Dataplane interface {
	// deliveryVNI is the on-wire Geneve VNI to stamp for this route; it may differ from vni (the
	// route's table key) for VPC-peering imports, where the key is the importer's local VNI but
	// delivery must be stamped with the peer's origin VNI. 0 ⇒ defaults to vni.
	AddRoute(ctx context.Context, vni uint32, prefix, nexthop string, external bool, deliveryVNI uint32) error
	WithdrawRoute(ctx context.Context, vni uint32, prefix string) error
	// AddNatSource programs LOCAL egress SNAT: (vni, sourceIP) is SNATed onto
	// natIP:[portMin,portMax). Delete-then-add, so re-calling is idempotent.
	AddNatSource(ctx context.Context, vni uint32, sourceIP, natIP string, portMin, portMax uint32) error
	// AddNeighborNat installs a return-route for a NAT block OWNED BY ANOTHER node:
	// a return landing here for natIp:[min,max) re-routes to ownerUnderlay.
	AddNeighborNat(ctx context.Context, natIp string, min, max uint32, ownerUnderlay string, vni uint32) error
	WithdrawNeighborNat(ctx context.Context, natIp string, min, max uint32, vni uint32) error
	// ReplaceNeighborNats makes this node's neighbor-NAT blocks exactly `blocks` — a complete
	// snapshot's set: unchanged blocks are left alone, absent ones removed, new ones added.
	ReplaceNeighborNats(ctx context.Context, blocks []NeighborNatBlock) error
	// ReplaceInterfaceFirewall replaces an interface's ENTIRE firewall rule set (ingress+egress,
	// v4+v6) in one call. Declarative + restart-safe: the agent pushes the full desired set every
	// reconcile, so a stale dataplane rule never survives an agent restart or in-place policy change.
	ReplaceInterfaceFirewall(ctx context.Context, interfaceID string, rules []FwRuleWithID) error
	// AddLoadBalancer registers a load balancer (id == its address). vni is the WAN/public VNI (0 at the edge);
	// lbUnderlay is the edge's own anycast underlay (unused-but-required for vni==0).
	AddLoadBalancer(ctx context.Context, id string, vni uint32, lbIP, lbUnderlay string, ports []LbPort) error
	// DelLoadBalancer removes a registered LB address by id.
	DelLoadBalancer(ctx context.Context, id string) error
	// AddLbBackend appends a backend underlay /128 to a registered LB address. backendOverlayIP and
	// backendVni are the backend NIC's overlay IP + VPC VNI, needed to Geneve-encap to it.
	AddLbBackend(ctx context.Context, id, backendUnderlay, backendOverlayIP string, backendVni uint32) error
	// DelLbBackend removes a backend underlay /128 from a registered LB address. backendOverlayIP
	// disambiguates two backends that share the same backendUnderlay (two guests backing the same LB address
	// on the SAME node — a normal K8s Service-with-2-pods-on-one-node case): without it the dataplane
	// cannot tell which of the two to remove. Empty is accepted for older/legacy callers and falls
	// back to matching by backendUnderlay alone (removing every backend on that node).
	DelLbBackend(ctx context.Context, id, backendUnderlay, backendOverlayIP string) error
	// ConfigureQoS sets the per-interface QoS lanes: egressMbps is EDT-shaped, publicMbps and
	// ingressMbps are policed. All 0 = unlimited (clears). Idempotent.
	ConfigureQoS(ctx context.Context, interfaceID string, egressMbps, publicMbps, ingressMbps uint32) error
	// ListInterfaces returns the interfaces currently attached on this node, each with its overlay
	// identity and this node's VTEP. The agent announces overlay routes from this (the underlay is
	// node-local dataplane state, not central config). The string is the dataplane's instance id,
	// new on every dataplane start ("" from a dataplane that predates it).
	ListInterfaces(ctx context.Context) ([]LocalInterface, string, error)
}

// LocalInterface is one interface attached on this node: its overlay identity (vni + IPs) and the
// underlay it is reachable at — this node's VTEP, shared by every interface on the node (nothing is
// allocated per endpoint). Reported by DataplaneNode.ListInterfaces.
type LocalInterface struct {
	InterfaceID string
	Vni         uint32
	OverlayIPs  []string // overlay IPv4 and/or IPv6
	Underlay    string   // this node's VTEP (same for every interface on the node)
}

// FwRule is one compiled firewall rule the agent installs on the dataplane.
type FwRule struct {
	SrcCIDR    string // empty = any
	DstCIDR    string // empty = any
	Proto      uint32 // 6=TCP, 17=UDP, 1=ICMP; 0 = any
	DstPortMin uint32
	DstPortMax uint32
	// IcmpType/IcmpCode select one ICMP(v6) message type/code; nil = any. Pointers because 0 is a
	// real type (echo reply).
	IcmpType *uint32
	IcmpCode *uint32
	Allow    bool // true = accept, false = drop
	Egress   bool // true = egress rule, false = ingress
}

// FwRuleWithID pairs a stable rule id (slot order = list position) with a rule, for
// ReplaceInterfaceFirewall.
type FwRuleWithID struct {
	ID   string
	Rule FwRule
}

// LbPort is one LB service tuple for AddLoadBalancer. Proto is the IP protocol number (6=TCP, 17=UDP).
// It aliases the shared routebus.LbPort so the agent and reflector use one canonical
// representation on the PublicPrefix channel.
type LbPort = routebus.LbPort

// Route is a local overlay route this node announces.
type Route struct {
	Vni      uint32
	Prefix   string // CIDR, e.g. "10.0.0.5/32"
	Nexthop  string // this node's underlay IPv6
	External bool   // if set, matching source traffic egress-SNATs (e.g. an external default route)
	// DeliveryVNI is the on-wire Geneve VNI for this route. For every route this node originates
	// (announces), delivery always equals its own Vni — VNI-differing delivery only arises on the
	// PEER-IMPORT path (see Bus.desiredRoute), which builds AddRoute calls directly, not via Route.
	DeliveryVNI uint32
}

// Bus is one agent's route-bus session driver.
type Bus struct {
	nodeID   string
	underlay string
	dp       Dataplane
	isEdge   bool

	mu sync.Mutex
	// learnedEdge maps an edge's anycast datapath /128 (address only) to its
	// UNIQUE control-plane loopback, learned from EDGE_UNDERLAY PublicPrefix
	// records. It is read to pin the WAN return path to the specific owning edge.
	learnedEdge map[string]string

	egressVNIs    []uint32          // local VNIs that import the public default(s); set each reconcile
	learnedPublic map[string]string // public-VNI prefix -> nexthop (recorded, imported into egressVNIs)

	// edgeLbs is the EDGE's bookkeeping for the load balancers it has programmed, keyed by LB address (==
	// the dataplane's LB id), built entirely from the LB_IP records backends announce. The
	// dataplane is not idempotent here (create_lb rejects a duplicate id, add_lb_target a duplicate
	// backend) and the edge sees each record repeatedly, so this is what makes applyPublic a diff.
	// Touched only from the Run goroutine (handleServerMsg), like programmed — no lock.
	//
	// It PERSISTS across reconnects, deliberately. Resetting it per session would make the first
	// record for each LB address re-create the LB (see registerLoadBalancer), which would in turn prune anything
	// stale — but at the cost of a real teardown/rebuild blip on EVERY reflector reconnect, and
	// reconnects are far more common than the staleness it would fix.
	//
	// Staleness across a reconnect is handled by the EndOfGlobal prune (see pruneGlobal), not by
	// resetting this: a backend WITHDRAWN while this edge was disconnected is absent from the
	// replayed snapshot and is withdrawn once the snapshot is known to be complete.
	edgeLbs map[string]*edgeLb

	// --- global (NAT + public) snapshot tracking, the EndOfGlobal counterpart to programmed/seen.
	// Touched only from the Run goroutine (handleServerMsg), like programmed — no lock.
	//
	// installedNat is what THIS agent programmed, and PERSISTS across reconnects (the dataplane
	// outlives a session). It is only the fallback path's diff basis now: against a dataplane that
	// can replace, the snapshot's set is authoritative and installedNat merely tracks it.
	// seenNat/seenPublic are the CURRENT session's snapshot and reset at each session open; seenNat
	// maps each block to its owner underlay, which the replace call carries.
	installedNat map[natEntry]bool
	seenNat      map[natEntry]string
	seenPublic   map[publicEntry]bool
	// replayingGlobal is true between a session's Hello and its EndOfGlobal: replayed NAT ADDs are
	// collected in seenNat and applied as one replace at the marker, not one by one. It starts true
	// so a Bus is never in a state a live session cannot be in — the first thing any session does is
	// open a snapshot, and a record arriving before one has been closed belongs to that snapshot.
	replayingGlobal bool
	// globalRecords counts the NAT + public records received in this session BEFORE EndOfGlobal.
	// It must equal the marker's count for the prune to be safe — see EndOfGlobal in the proto.
	globalRecords uint32

	// --- convergence, the signal a deployment gates an anycast advertisement on (see Converged).
	// Read from an HTTP readiness handler, so these ARE guarded by mu, unlike the snapshot sets.
	subscribedVNIs map[uint32]bool // what we asked for on this session
	eorSeen        map[uint32]bool // which of those have replayed fully (EndOfRIB)
	globalDone     bool            // the global snapshot has replayed fully (EndOfGlobal)
	converged      bool            // LATCHING: see Converged

	// peerImports is set each reconcile (localVNI -> imports; nil-safe): which peer VNIs' routes each
	// local VNI imports (VPC peering), and within which prefixes.
	peerImports map[uint32][]PeerImport

	// --- learned routes. Everything the route bus has taught this node about overlay routes is
	// learnedOwn + learnedPublic; what the dataplane should hold for any key follows from that, the
	// peering and egress config and the local interfaces alone (desiredRoute). apply programs a key
	// as its RouteUpdate arrives, and every reconcile tick converges the rest (syncRoutes): a failed
	// call, a changed peering or egress set, a dataplane that restarted. Run goroutine only.
	//
	// learnedOwn[vni][prefix] is the route last learned for (vni, prefix) on vni's own table, with
	// its whole nexthop set. It feeds vni's own table and every local VNI that imports vni. A
	// WITHDRAW, the EndOfRIB prune and an unsubscribe forget it, so nothing re-asserts a route the
	// bus has dropped.
	learnedOwn map[uint32]map[string]ownRoute
	// programmed[vni][prefix] is what this Bus last programmed for the key, so a tick calls the
	// dataplane only for the keys that drifted. It PERSISTS across reconnects (the dataplane
	// outlives a session).
	programmed map[uint32]map[string]dpRoute
	// seen[vni] is the set of prefixes received in the CURRENT session's snapshot of vni; reset at
	// each session open. On EndOfRIB(vni) a learned route not in seen[vni] left the RIB while we
	// were disconnected, and is forgotten.
	seen map[uint32]map[string]bool
	// rxRoutes[vni] counts route ADDs received for that VNI since we asked the reflector for its
	// table. It must equal EndOfRIB's record_count for the prune to be safe — same guard, same
	// reason, as globalRecords (see EndOfRIB in routebus.proto).
	rxRoutes map[uint32]uint32

	// localHosts[vni][prefix] is the host prefix (/32 or /128) of every interface attached on this
	// node, from the dataplane's ListInterfaces, refreshed every reconcile tick; ownUnderlays is this
	// node's VTEP(s) from the same read. A bus route for a local host prefix — the guest's own /32
	// announced by another node during a VM move, say — is passed to the dataplane like any other
	// key: flowplane HOLDS a local interface's key, applies a mesh add/withdraw for it to its shadow
	// only, and reinstalls the shadowed route when the interface detaches. The agent adds one
	// fallback on top: when the interface leaves, it re-asserts the bus route it holds for the key
	// (releaseLocalHost), in case flowplane lost its shadow across a restart.
	//
	// ROLLOUT: this relies on flowplane holding local keys, so that flowplane must be deployed
	// BEFORE this agent. Against an older flowplane, a passed-through AddRoute for a local key
	// replaces the self-route with an encap and a WithdrawRoute deletes it.
	localHosts   map[uint32]map[string]bool
	ownUnderlays map[string]bool

	// --- dataplane restarts. flowplane rebuilds its routes from its pinned maps on a restart, but
	// not a mesh route a self-route was holding back (the kernel never had it), and not anything at
	// all if the maps went too. So the agent re-sends every learned route when the dataplane's
	// instance id (from ListInterfaces) changes or it answers again after an outage, and on a slow
	// sweep (fullResyncEvery) for a dataplane that cannot say. A re-send is owed key by key
	// (resendQueue) and paid routeCallsPerTick at a time.
	dpInstance     string
	dpSeen         bool       // dpInstance has been read at least once
	dpUnreachable  bool       // the last ListInterfaces failed
	resendQueue    []routeRef // keys still owed a full re-send, held local host keys first
	lastFullResync time.Time  // when the last full re-send was queued

	// ticks counts syncRoutes runs; it is the clock retries back off on. retries holds each key
	// whose last call failed for a reason other than an unreachable dataplane (see routeRetry).
	ticks   int
	retries map[routeRef]*routeRetry
	// absentTicks[vni] counts the successful reconciles in a row whose subscriptions left out a VNI
	// that still has learned routes (see forgetUnsubscribed).
	absentTicks map[uint32]int

	// reconcileEvery is how often Run recomputes the desired announcement set and pushes deltas onto
	// the live stream. Tests override it for fast convergence.
	reconcileEvery time.Duration
}

// fullResyncEvery is how often the learned routes are re-sent to the dataplane in full when no
// restart was seen. It is the safety net behind the instance id — for a dataplane that predates it,
// or route state lost some other way — so it can be slow: each route costs one AddRoute (and a log
// line in flowplane), and a restart re-sends on the next tick anyway.
const fullResyncEvery = 5 * time.Minute

// routeCallsPerTick caps the dataplane calls one tick's resync makes. A tick runs on the Run
// goroutine, which meanwhile drains nothing from the route-bus stream: past recvCh's 64 messages
// the reflector's per-session queue fills, and it drops live deltas beyond 1024, which no resync
// can recover. One AddRoute is a local unix-socket RPC plus a linear scan of flowplane's route
// shadow, well under a millisecond each, so 256 of them hold Run for a fraction of a second — far
// shorter than it takes any realistic churn to queue a thousand deltas for one node. A full
// re-send of N routes takes N/256 ticks: about three minutes for 10k, with the keys a restart
// actually loses (held local host keys) sent on the first.
const routeCallsPerTick = 256

// retryMaxTicks caps a failing key's backoff: retries come 1, 2, 4, ... ticks apart, then every
// 60 ticks (five minutes at the default reconcileEvery).
const retryMaxTicks = 60

// retrySummaryTicks is how often the keys still failing are summarised in the log (about a
// minute), since each is logged only when it starts failing.
const retrySummaryTicks = 12

// unsubscribeAfterTicks is how many successful reconciles in a row must leave a VNI out of the
// subscriptions before its learned routes are forgotten and withdrawn. A guest pod that restarts
// detaches and re-attaches within a tick or two, and one reconcile can read the peering config
// without an import; dropping a VNI's routes on either would blackhole it until the re-subscribe
// replays them. Three ticks (~15 s) outlasts both, and costs only that much longer for a VNI that
// really left — its routes are frozen meanwhile (the unsubscribe has gone out), and a re-subscribe
// replays and prunes them anyway.
const unsubscribeAfterTicks = 3

// routeRetry is a key whose last dataplane call failed: how often in a row, the first tick it may
// be retried on, and the error, for the summary.
type routeRetry struct {
	failures  int
	nextTick  int
	lastError string
}

// natEntry is one learned neighbor-NAT block, keyed exactly as the dataplane programs it so a
// prune can withdraw it verbatim.
type natEntry struct {
	natIP            string
	portMin, portMax uint32
	vni              uint32
}

// ownRoute is one learned own-table bus route: its whole nexthop set, since the one programmed
// (the first) can be this node's own VTEP.
type ownRoute struct {
	nexthops []string
	external bool
}

// dpRoute is one route as programmed for a key: the AddRoute arguments, and where it came from.
// The zero value, never a wanted route, stands for "unknown, may hold anything" after a failed call
// (see syncKey).
type dpRoute struct {
	nexthop     string
	external    bool
	deliveryVNI uint32
	origin      routeOrigin
}

// routeOrigin is which learned route a key is programmed from: local routes win over peer imports,
// which win over the public default.
type routeOrigin string

const (
	originOwn    routeOrigin = "own"
	originPeer   routeOrigin = "peer"
	originPublic routeOrigin = "public"
)

// NeighborNatBlock is one neighbor-NAT block as ReplaceNeighborNats takes it.
type NeighborNatBlock struct {
	NatIP            string
	PortMin, PortMax uint32
	OwnerUnderlay    string
	Vni              uint32
}

// publicEntry is one learned PublicPrefix record, keyed by what the prune has to act on: the LB
// address plus the backend identity (a node VTEP alone is not enough — two backends of one service
// can share a node).
type publicEntry struct {
	lbIP    string
	owner   string
	overlay string
}

// resetGlobalSnapshot starts a new global-snapshot epoch: the reflector is about to replay this
// session's global records — every NAT block and public record for a session that takes the feed,
// nothing at all for one that opted out (a compute node, which gets only the marker) — so forget
// what THIS session has seen and re-count. installedNat and edgeLbs deliberately survive: they
// mirror dataplane state, which outlives the session. edgeLbs is what the LB prune diffs against,
// and installedNat is the fallback path's diff basis (see syncNeighborNats).
func (b *Bus) resetGlobalSnapshot() {
	b.seenNat = map[natEntry]string{}
	b.seenPublic = map[publicEntry]bool{}
	b.globalRecords = 0
	b.replayingGlobal = true
	b.mu.Lock()
	// Replay progress is per-session; `converged` deliberately is not (see Converged).
	b.globalDone = false
	b.eorSeen = map[uint32]bool{}
	b.mu.Unlock()
}

// Converged reports whether this session has received the FULL picture at least once: the global
// snapshot (EndOfGlobal — the NAT blocks and LB addresses/backends an edge actually forwards on) plus an
// EndOfRIB for every VNI it subscribed to.
//
// This is what an anycast advertisement must be gated on. An edge attracts its share of the ECMP
// the instant its prefix is advertised, and until the snapshot has landed it has no Maglev table
// for the LB addresses it is dispatching — a blackhole on every cold start.
//
// It LATCHES. Once true it stays true: a later reconnect (or a newly subscribed VNI) leaves the
// already-programmed tables in place, so dropping the advertisement would reshuffle every WAN flow
// across the remaining edges to fix nothing. The failure being prevented is the cold start, not
// steady-state churn. Un-converging on prolonged disconnection is a separate policy decision (it
// needs a staleness threshold) and is deliberately not made here.
func (b *Bus) Converged() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.converged
}

// noteSubscribed records the VNI set this session asked the reflector for. Convergence is measured
// against it, so it is the caller's (reconcileStep's) job to keep it current.
func (b *Bus) noteSubscribed(vnis []uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribedVNIs = make(map[uint32]bool, len(vnis))
	for _, v := range vnis {
		b.subscribedVNIs[v] = true
	}
	b.recomputeConvergedLocked()
}

// noteEndOfRIB / noteEndOfGlobal record replay progress and re-evaluate the latch.
func (b *Bus) noteEndOfRIB(vni uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.eorSeen[vni] = true
	b.recomputeConvergedLocked()
}

func (b *Bus) noteEndOfGlobal() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.globalDone = true
	b.recomputeConvergedLocked()
}

// recomputeConvergedLocked sets the latch once the global snapshot and every subscribed VNI have
// replayed. Never clears it — see Converged. Caller holds b.mu.
func (b *Bus) recomputeConvergedLocked() {
	if b.converged || !b.globalDone {
		return
	}
	for v := range b.subscribedVNIs {
		if !b.eorSeen[v] {
			return
		}
	}
	b.converged = true
	log.Printf("route-bus converged (global snapshot + %d subscribed VNI(s)); safe to advertise", len(b.subscribedVNIs))
}

// pruneGlobal closes this session's global snapshot, in two halves. The NAT blocks become exactly
// the snapshot's set, declaratively (syncNeighborNats). The LB backends are diffed and the ones
// NOT replayed are withdrawn (pruneLbBackends) — a backend that stopped announcing while this
// agent was disconnected. The EndOfRIB equivalent for the global channel.
//
// It first checks the snapshot was COMPLETE. The current reflector queues a snapshot whole, but an
// older one dropped records on overflow, so receiving fewer records than the reflector says it
// sent means the snapshot is lossy — and pruning against a lossy snapshot would withdraw LIVE
// state, which is strictly worse than the staleness being fixed. In that case do nothing and wait
// for the next reconnect, which replays from scratch.
func (b *Bus) pruneGlobal(ctx context.Context, want uint32) {
	b.replayingGlobal = false
	if b.globalRecords != want {
		log.Printf("EndOfGlobal: snapshot incomplete (got %d records, reflector sent %d) — skipping prune; will retry on the next resync",
			b.globalRecords, want)
		// Nothing is pruned, but what did arrive is programmed: those blocks are live.
		for e, owner := range b.seenNat {
			b.addNeighborNat(ctx, e, owner)
		}
		return
	}
	b.syncNeighborNats(ctx)
	b.pruneLbBackends(ctx)
}

// syncNeighborNats makes the dataplane's neighbor-NAT blocks exactly this complete snapshot's, in
// one declarative call: an unchanged block is never unprogrammed, a block that moved or left while
// this agent was disconnected is removed — and so is one the dataplane adopted after a restart
// that no agent remembers installing. A compute node's set is empty, which clears anything an
// older agent installed there. An older dataplane without the call gets per-block programming and
// the diff against what this agent installed. A transport failure changed nothing and is simply
// retried on the next resync; any other failure may have applied part of the set, so the blocks are
// programmed one by one to repair it, and nothing is pruned.
func (b *Bus) syncNeighborNats(ctx context.Context) {
	blocks := make([]NeighborNatBlock, 0, len(b.seenNat))
	for e, owner := range b.seenNat {
		blocks = append(blocks, NeighborNatBlock{NatIP: e.natIP, PortMin: e.portMin, PortMax: e.portMax, OwnerUnderlay: owner, Vni: e.vni})
	}
	err := b.dp.ReplaceNeighborNats(ctx, blocks)
	if err == nil {
		b.installedNat = make(map[natEntry]bool, len(b.seenNat))
		for e := range b.seenNat {
			b.installedNat[e] = true
		}
		return
	}
	if transientDataplaneError(err) {
		// The call never landed, so there is nothing to repair — and a per-block retry would meet
		// the same dead connection, one failed RPC per block in the whole snapshot.
		log.Printf("ReplaceNeighborNats (%d blocks): %v — dataplane unreachable, changed nothing; will retry on the next resync", len(blocks), err)
		return
	}
	for e, owner := range b.seenNat {
		b.addNeighborNat(ctx, e, owner)
	}
	if status.Code(err) != codes.Unimplemented {
		log.Printf("ReplaceNeighborNats (%d blocks): %v — programmed them one by one, pruned nothing; will retry on the next resync", len(blocks), err)
		return
	}
	for e := range b.installedNat {
		if _, ok := b.seenNat[e]; ok {
			continue
		}
		if err := b.dp.WithdrawNeighborNat(ctx, e.natIP, e.portMin, e.portMax, e.vni); err != nil {
			log.Printf("prune WithdrawNeighborNat %s:[%d,%d) vni=%d: %v", e.natIP, e.portMin, e.portMax, e.vni, err)
			continue
		}
		delete(b.installedNat, e)
		log.Printf("pruned stale NAT block %s:[%d,%d) vni=%d", e.natIP, e.portMin, e.portMax, e.vni)
	}
}

// transientDataplaneError reports whether err means the RPC never reached the dataplane's state —
// the socket was down, the deadline passed, or we are shutting down. Either nothing was applied or
// we can no longer tell and cannot retry on this context anyway, and retrying the same call per
// block would only fail N times. Nothing is pruned either way; the next resync replaces from
// scratch.
func transientDataplaneError(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		return true
	}
	return false
}

// defaultReconcileEvery bounds how stale this node's fabric-wide announcements can get after a CRD
// change while the bus session stays up (the K8s watch would make this event-driven; the ticker is
// the simple, robust floor).
const defaultReconcileEvery = 5 * time.Second

func NewBus(nodeID, underlay string, dp Dataplane, isEdge bool) *Bus {
	return &Bus{
		nodeID: nodeID, underlay: underlay, dp: dp, isEdge: isEdge,
		learnedEdge: map[string]string{}, learnedPublic: map[string]string{},
		edgeLbs:         map[string]*edgeLb{},
		installedNat:    map[natEntry]bool{},
		seenNat:         map[natEntry]string{},
		replayingGlobal: true,
		seenPublic:      map[publicEntry]bool{},
		subscribedVNIs:  map[uint32]bool{},
		eorSeen:         map[uint32]bool{},
		programmed:      map[uint32]map[string]dpRoute{},
		seen:            map[uint32]map[string]bool{},
		rxRoutes:        map[uint32]uint32{},
		localHosts:      map[uint32]map[string]bool{},
		ownUnderlays:    map[string]bool{},
		learnedOwn:      map[uint32]map[string]ownRoute{},
		peerImports:     map[uint32][]PeerImport{},
		lastFullResync:  time.Now(),
		retries:         map[routeRef]*routeRetry{},
		absentTicks:     map[uint32]int{},
		reconcileEvery:  defaultReconcileEvery,
	}
}

// hello is this session's opening message. A compute node opts out of the global channel: it
// neither relays NAT returns (only an edge does) nor runs Maglev, so every NAT and public record
// fanned out to it was work for nothing — O(records × nodes) fabric-wide.
func (b *Bus) hello() *rbv1.Hello {
	feed := rbv1.GlobalFeed_GLOBAL_FEED_NONE
	if b.isEdge {
		feed = rbv1.GlobalFeed_GLOBAL_FEED_ALL
	}
	return &rbv1.Hello{NodeId: b.nodeID, UnderlayIpv6: b.underlay, GlobalFeed: feed}
}

// Run drives one route-bus session to steady state. It opens a Session, sends Hello, then loops:
// on every reconcile tick it calls `reconcile` to recompute the full DesiredState and pushes only the
// deltas (announce new/changed, withdraw removed) onto the live stream, while concurrently applying
// inbound RouteUpdates to the dataplane. It returns when ctx is done or the stream errors (the caller
// reconnects, and the next Run re-announces the whole set because `applied` resets to empty).
//
// All stream.Send calls happen from THIS goroutine — the receive side is offloaded to a goroutine
// feeding recvCh, so there is never a concurrent Send on the gRPC stream.
func (b *Bus) Run(ctx context.Context, cc rbv1.RouteBusClient, reconcile func(context.Context) (DesiredState, error)) error {
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := cc.Session(sessCtx)
	if err != nil {
		return err
	}
	if err := stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_Hello{Hello: b.hello()}}); err != nil {
		return err
	}
	// New session: the reflector will replay each subscribed VNI's snapshot then send EndOfRIB. Reset
	// the per-session "seen" set so prune-on-EndOfRIB removes routes that left the RIB while we were
	// disconnected (learnedOwn and programmed persist across sessions, as the dataplane's routes do).
	b.seen = map[uint32]map[string]bool{}
	b.rxRoutes = map[uint32]uint32{}
	// Same for the GLOBAL channel: an edge's Hello registers it for the feed, which replays every
	// NAT block and public record and then EndOfGlobal; a compute node opted out and gets the bare
	// marker. (installedNat/edgeLbs persist for the same reason installed[] does.)
	b.resetGlobalSnapshot()

	recvCh := make(chan *rbv1.ServerMsg, 64)
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case recvCh <- msg:
			case <-sessCtx.Done():
				return
			}
		}
	}()

	ticker := time.NewTicker(b.reconcileEvery)
	defer ticker.Stop()

	// applied is what we have currently announced on THIS session; empty at session open so the first
	// reconcile announces the full desired set (and a reconnect re-announces everything).
	var applied DesiredState
	if err := b.reconcileStep(ctx, stream, reconcile, &applied); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			if err == io.EOF {
				return nil
			}
			return err
		case msg := <-recvCh:
			b.handleServerMsg(ctx, msg)
		case <-ticker.C:
			if err := b.reconcileStep(ctx, stream, reconcile, &applied); err != nil {
				return err
			}
		}
	}
}

// reconcileStep recomputes the desired set and pushes the delta to the stream. A `reconcile` error
// (e.g. a transient API-server read) is logged and swallowed so the session stays up and retries next
// tick; a stream Send error is returned so the caller reconnects (and re-announces from scratch).
// Either way the learned routes converge on the dataplane (syncRoutes): they need nothing from the
// reconcile but the egress and peering config, and the last good one stands.
func (b *Bus) reconcileStep(ctx context.Context, stream rbv1.RouteBus_SessionClient, reconcile func(context.Context) (DesiredState, error), applied *DesiredState) error {
	desired, err := reconcile(ctx)
	if err != nil {
		log.Printf("reconcile: %v", err)
		b.syncRoutes(ctx)
		return nil
	}
	b.mu.Lock()
	b.egressVNIs = append(b.egressVNIs[:0:0], desired.EgressVNIs...)
	b.setPeerImportsLocked(desired.PeeringImports)
	b.mu.Unlock()
	b.noteSubscribed(desired.Subs)
	b.forgetUnsubscribed(desired.Subs)
	b.syncRoutes(ctx)
	d := diffDesired(*applied, desired)
	if d.empty() {
		return nil
	}
	if err := b.sendDelta(stream, d); err != nil {
		return err
	}
	*applied = desired
	return nil
}

// syncRoutes is the level-triggered half of programming the learned routes (apply, as each
// RouteUpdate arrives, is the event-driven half). It re-reads the local interfaces, queues a full
// re-send when the dataplane restarted (or, for one without an instance id, the slow sweep is due),
// then converges the keys that drifted from what was programmed and pays down the re-send, within
// one tick's budget (see resyncRoutes).
//
// apply alone left gaps nothing closed short of a route-bus reconnect: a failed AddRoute or
// WithdrawRoute was only logged; a restarted flowplane never got back a mesh route a self-route had
// been holding (see dpInstance); and a key whose wanted route changes with no RouteUpdate at all —
// a VNI that becomes egress-needing after the public defaults were learned (an LB or NATGateway
// lands later, the steady-state ordering), a peering configured or removed, a guest arriving over a
// route that names this node — was programmed only if the session happened to replay.
func (b *Bus) syncRoutes(ctx context.Context) {
	b.ticks++
	if b.refreshLocalHosts(ctx) {
		log.Printf("dataplane restarted or answered again after an outage: re-sending every learned route")
		b.queueFullResend()
	}
	// A dataplane with an instance id announces its restarts, so only one without gets the sweep.
	if b.dpInstance == "" && len(b.resendQueue) == 0 && time.Since(b.lastFullResync) >= fullResyncEvery {
		b.queueFullResend()
	}
	b.resyncRoutes(ctx)
	if len(b.retries) > 0 && b.ticks%retrySummaryTicks == 0 {
		b.logRetrySummary()
	}
}

// queueFullResend owes every key a re-send, held local host keys first: they are what a restarted
// flowplane cannot recover from its pinned maps, so they lead the line when it is paid over ticks.
func (b *Bus) queueFullResend() {
	keys := make([]routeRef, 0, len(b.resendQueue))
	for k := range b.routeKeys() {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(x, y routeRef) int {
		if hx, hy := b.localHosts[x.Vni][x.Prefix], b.localHosts[y.Vni][y.Prefix]; hx != hy {
			if hx {
				return -1
			}
			return 1
		}
		if x.Vni != y.Vni {
			return int(x.Vni) - int(y.Vni)
		}
		return strings.Compare(x.Prefix, y.Prefix)
	})
	b.resendQueue = keys
	b.lastFullResync = time.Now()
}

// resyncRoutes converges the route keys within one tick's budget (routeCallsPerTick). First the
// diff: every key the learned routes want programmed, or that is programmed and no longer wanted,
// gets a call only if it drifted from what was last programmed and is not backing off — so a
// converged tick makes none. Then, with what is left of the budget, the owed full re-send (flowplane's
// AddRoute replaces in place, so re-sending a route it holds is a no-op upsert). What the budget
// does not reach is picked up next tick. It stops early at the first call that never reached the
// dataplane: the rest would fail the same way, one log line each.
func (b *Bus) resyncRoutes(ctx context.Context) {
	budget := routeCallsPerTick
	keys := b.routeKeys()
	for k := range b.retries {
		if !keys[k] {
			delete(b.retries, k) // nothing wants it and nothing is programmed there any more
		}
	}
	for k := range keys {
		if budget == 0 {
			return
		}
		if r := b.retries[k]; r != nil && b.ticks < r.nextTick {
			continue
		}
		sent, err := b.syncKey(ctx, k.Vni, k.Prefix, false)
		if sent {
			budget--
		}
		if err != nil && transientDataplaneError(err) {
			log.Printf("route resync: dataplane unreachable; resuming on the next tick")
			return
		}
	}
	for len(b.resendQueue) > 0 && budget > 0 {
		k := b.resendQueue[0]
		b.resendQueue = b.resendQueue[1:]
		sent, err := b.syncKey(ctx, k.Vni, k.Prefix, true)
		if sent {
			budget--
		}
		if err != nil && transientDataplaneError(err) {
			log.Printf("route resync: dataplane unreachable; resuming on the next tick")
			return
		}
	}
	if len(b.resendQueue) == 0 {
		b.resendQueue = nil
	}
}

// logRetrySummary logs how many keys are still failing, with one of them as an example.
func (b *Bus) logRetrySummary() {
	for k, r := range b.retries {
		log.Printf("route resync: %d route key(s) failing, backing off; e.g. vni=%d %s (%d failures): %s",
			len(b.retries), k.Vni, k.Prefix, r.failures, r.lastError)
		return
	}
}

// routeKeys is every key the learned routes reach — each own-table route, each peer import, the
// public defaults in each egress VNI — plus every key programmed, so one that is no longer wanted
// is withdrawn.
func (b *Bus) routeKeys() map[routeRef]bool {
	keys := map[routeRef]bool{}
	for vni, routes := range b.learnedOwn {
		for prefix := range routes {
			keys[routeRef{vni, prefix}] = true
		}
	}
	for local, imports := range b.peerImports {
		for _, im := range imports {
			for prefix := range b.learnedOwn[im.PeerVNI] {
				if prefixInCIDRs(prefix, im.ImportPrefixes) {
					keys[routeRef{local, prefix}] = true
				}
			}
		}
	}
	for _, vni := range b.egressVNIs {
		for prefix := range b.learnedPublic {
			keys[routeRef{vni, prefix}] = true
		}
	}
	for vni, routes := range b.programmed {
		for prefix := range routes {
			keys[routeRef{vni, prefix}] = true
		}
	}
	return keys
}

// forgetUnsubscribed forgets the routes learned for every VNI this node has no longer subscribed
// to for unsubscribeAfterTicks reconciles in a row: the reflector stops updating such a VNI, so
// they could only go stale. The resync then withdraws them, and whatever was imported from them.
// Level-triggered on the desired set rather than on the unsubscribe sent, so a VNI dropped while
// the session was down is forgotten too. The public VNI counts like any other.
func (b *Bus) forgetUnsubscribed(subs []uint32) {
	keep := vniSet(subs)
	absent := map[uint32]bool{}
	for vni := range b.learnedOwn {
		if !keep[vni] {
			absent[vni] = true
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !keep[PublicVNI] && len(b.learnedPublic) > 0 {
		absent[PublicVNI] = true
	}
	for vni := range b.absentTicks {
		if !absent[vni] {
			delete(b.absentTicks, vni)
		}
	}
	for vni := range absent {
		b.absentTicks[vni]++
		if b.absentTicks[vni] < unsubscribeAfterTicks {
			continue
		}
		delete(b.absentTicks, vni)
		if vni == PublicVNI {
			clear(b.learnedPublic)
		} else {
			delete(b.learnedOwn, vni)
		}
	}
}

func vniSet(vnis []uint32) map[uint32]bool {
	out := make(map[uint32]bool, len(vnis))
	for _, v := range vnis {
		out[v] = true
	}
	return out
}

// handleServerMsg applies one inbound server message to the local dataplane.
func (b *Bus) handleServerMsg(ctx context.Context, msg *rbv1.ServerMsg) {
	if ru := msg.GetRouteUpdate(); ru != nil {
		if ru.Op == rbv1.RouteOp_ROUTE_OP_ADD {
			b.rxRoutes[ru.Vni]++
		}
		b.apply(ctx, ru)
	}
	if nu := msg.GetNatUpdate(); nu != nil {
		b.globalRecords++
		b.applyNat(ctx, nu)
	}
	if pu := msg.GetPublicUpdate(); pu != nil {
		b.globalRecords++
		b.applyPublic(ctx, pu.GetPrefix(), pu.GetOp())
	}
	if eor := msg.GetEndOfRib(); eor != nil {
		b.pruneVNI(ctx, eor.GetVni(), eor.GetRecordCount())
		b.noteEndOfRIB(eor.GetVni())
	}
	if eog := msg.GetEndOfGlobal(); eog != nil {
		b.pruneGlobal(ctx, eog.GetRecordCount())
		b.noteEndOfGlobal()
	}
	// KeepAlive: no-op.
}

// resetRouteSnapshot starts a new replay epoch for one VNI: called when we ask the reflector for
// its table, so the count compared at EndOfRIB covers exactly that replay and is not inflated by
// ADDs received before we subscribed.
func (b *Bus) resetRouteSnapshot(vni uint32) {
	b.rxRoutes[vni] = 0
	b.seen[vni] = map[string]bool{}
}

// pruneVNI forgets every route learned on vni that was NOT (re)received in this session's snapshot
// — a route that left the RIB (peer withdrew, or its owner disconnected) while this node was
// disconnected — and withdraws what it fed, which would otherwise linger on the dataplane as a
// stale blackhole/misroute and be re-asserted by every resync. For the public VNI that is the
// defaults imported into the egress VNIs.
func (b *Bus) pruneVNI(ctx context.Context, vni uint32, want uint32) {
	// A lossy replay must not prune: an older reflector dropped snapshot records on overflow, and
	// withdrawing a live route is strictly worse than keeping a stale one. Same guard as pruneGlobal.
	if got := b.rxRoutes[vni]; got != want {
		log.Printf("EndOfRIB(vni=%d): snapshot incomplete (got %d routes, reflector sent %d) — skipping prune; will retry on the next resync",
			vni, got, want)
		return
	}
	seen := b.seen[vni]
	var stale []string
	if vni == PublicVNI {
		b.mu.Lock()
		for prefix := range b.learnedPublic {
			if !seen[prefix] {
				stale = append(stale, prefix)
				delete(b.learnedPublic, prefix)
			}
		}
		b.mu.Unlock()
	} else {
		for prefix := range b.learnedOwn[vni] {
			if !seen[prefix] {
				stale = append(stale, prefix)
			}
		}
		for _, prefix := range stale {
			b.delLearnedOwn(vni, prefix)
		}
	}
	for _, prefix := range stale {
		b.syncLearned(ctx, vni, prefix, false)
	}
}

// markSeen records a route ADD received in this session, for prune-on-EndOfRIB. It is marked on
// receipt, not on a successful install: a route whose AddRoute failed is still in the RIB, and
// the resync retries it. Called only from the Run goroutine (apply), so no locking.
func (b *Bus) markSeen(vni uint32, prefix string) {
	if b.seen[vni] == nil {
		b.seen[vni] = map[string]bool{}
	}
	b.seen[vni][prefix] = true
}

// sendDelta writes one busDelta to the stream: subscribes + announces first (so we start receiving
// and upsert changed records), then withdraws + unsubscribes. Returns the first Send error.
func (b *Bus) sendDelta(stream rbv1.RouteBus_SessionClient, d busDelta) error {
	for _, v := range d.subscribe {
		// About to be replayed this VNI's whole table: start its count/seen epoch here so the
		// EndOfRIB guard compares against exactly that replay.
		b.resetRouteSnapshot(v)
		if err := stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_Subscribe{Subscribe: &rbv1.Subscribe{Vni: v}}}); err != nil {
			return err
		}
	}
	for _, r := range d.announceR {
		if err := b.announce(stream, r); err != nil {
			return err
		}
	}
	for _, n := range d.announceN {
		if err := b.AnnounceNat(stream, n); err != nil {
			return err
		}
	}
	for _, p := range d.announceP {
		if err := b.AnnouncePublic(stream, p); err != nil {
			return err
		}
	}
	for _, k := range d.withdrawR {
		if err := stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_Withdraw{Withdraw: &rbv1.Withdraw{Vni: k.Vni, Prefix: k.Prefix}}}); err != nil {
			return err
		}
	}
	for _, k := range d.withdrawN {
		if err := stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_WithdrawNat{WithdrawNat: &rbv1.WithdrawNat{NatIp: k.NatIP, PortMin: k.PortMin, PortMax: k.PortMax}}}); err != nil {
			return err
		}
	}
	for _, p := range d.withdrawP {
		if err := stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_WithdrawPublic{WithdrawPublic: publicPrefixPB(p)}}); err != nil {
			return err
		}
	}
	for _, v := range d.unsubscribe {
		if err := stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_Unsubscribe{Unsubscribe: &rbv1.Unsubscribe{Vni: v}}}); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bus) announce(stream rbv1.RouteBus_SessionClient, r Route) error {
	return stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_Announce{Announce: &rbv1.Announce{
		Vni: r.Vni, Prefix: r.Prefix, NexthopUnderlay: r.Nexthop, External: r.External,
	}}})
}

// AnnounceNat sends this node's ownership of a deterministic egress NAT block on
// the given session stream.
func (b *Bus) AnnounceNat(stream rbv1.RouteBus_SessionClient, blk NatBlock) error {
	return stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_AnnounceNat{AnnounceNat: &rbv1.AnnounceNat{
		Vni: blk.Vni, SourceIp: blk.SourceIP, NatIp: blk.NatIP,
		PortMin: blk.PortMin, PortMax: blk.PortMax, OwnerUnderlay: blk.OwnerUnderlay,
	}}})
}

// AnnouncePublic sends one typed public-address record on the given session
// stream (e.g. this edge's EDGE_UNDERLAY anycast -> owner-loopback mapping).
func (b *Bus) AnnouncePublic(stream rbv1.RouteBus_SessionClient, pp PublicPrefix) error {
	return stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_AnnouncePublic{AnnouncePublic: publicPrefixPB(pp)}})
}

// publicPrefixPB is the single agent-side encoder for a PublicPrefix onto the wire, shared by
// announce and withdraw so a newly added field (like ports) cannot be carried by one and dropped
// by the other.
func publicPrefixPB(pp PublicPrefix) *rbv1.PublicPrefix {
	return &rbv1.PublicPrefix{
		Kind: pp.Kind, Prefix: pp.Prefix, OwnerUnderlay: pp.OwnerUnderlay,
		Vni: pp.Vni, PortMin: pp.PortMin, PortMax: pp.PortMax, OverlayIp: pp.OverlayIP,
		Ports: portsPB(pp.Ports),
	}
}

// portsPB / portsFromPB convert between the agent's LbPort slice and the wire PortProto slice.
func portsPB(ports []LbPort) []*rbv1.PortProto {
	if len(ports) == 0 {
		return nil
	}
	out := make([]*rbv1.PortProto, 0, len(ports))
	for _, p := range ports {
		out = append(out, &rbv1.PortProto{Port: p.Port, Proto: p.Proto})
	}
	return out
}

func portsFromPB(ports []*rbv1.PortProto) []LbPort {
	if len(ports) == 0 {
		return nil
	}
	out := make([]LbPort, 0, len(ports))
	for _, p := range ports {
		out = append(out, LbPort{Port: p.GetPort(), Proto: p.GetProto()})
	}
	return out
}

// applyNat programs a learned NAT block on an EDGE: only an edge relays a NAT return to the node
// that owns the block, so a compute node holds none (an older reflector may still send it NAT
// records — they are ignored). A block this node owns is never a neighbor-NAT entry: its local
// SNAT is programmed by the reconciler via AddNatSource. While the global snapshot is replaying,
// an ADD is only collected; the marker applies the whole set at once (see syncNeighborNats).
func (b *Bus) applyNat(ctx context.Context, nu *rbv1.NatUpdate) {
	if !b.isEdge || nu.OwnerUnderlay == b.underlay {
		return
	}
	e := natEntry{natIP: nu.NatIp, portMin: nu.PortMin, portMax: nu.PortMax, vni: nu.Vni}
	switch nu.Op {
	case rbv1.RouteOp_ROUTE_OP_ADD:
		// seenNat IS the desired set the marker hands to ReplaceNeighborNats, so record the block
		// whether or not anything is programmed now: during the replay nothing is, and on a live
		// delta the entry must survive a dataplane error rather than vanish from the next replace.
		b.seenNat[e] = nu.OwnerUnderlay
		if b.replayingGlobal {
			return
		}
		b.addNeighborNat(ctx, e, nu.OwnerUnderlay)
	case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
		delete(b.seenNat, e)
		if err := b.dp.WithdrawNeighborNat(ctx, nu.NatIp, nu.PortMin, nu.PortMax, nu.Vni); err != nil {
			log.Printf("WithdrawNeighborNat %s:[%d,%d) vni=%d: %v", nu.NatIp, nu.PortMin, nu.PortMax, nu.Vni, err)
			return
		}
		delete(b.installedNat, e)
	}
}

// addNeighborNat programs one block and records it as installed.
func (b *Bus) addNeighborNat(ctx context.Context, e natEntry, owner string) {
	if err := b.dp.AddNeighborNat(ctx, e.natIP, e.portMin, e.portMax, owner, e.vni); err != nil {
		log.Printf("AddNeighborNat %s:[%d,%d) -> %s vni=%d: %v", e.natIP, e.portMin, e.portMax, owner, e.vni, err)
		return
	}
	b.installedNat[e] = true
}

// apply records one RouteUpdate and programs the keys it feeds. A route on a public-VNI is an
// aggregation record, imported into each local egress VNI (a tenant node has no VNI-0 table). Any
// other route on ru.Vni is BOTH an own/direct route for ru.Vni's OWN table AND, if any LOCAL vni
// imports ru.Vni (VPC peering), a peer route for those importers' tables. These are ADDITIVE (they
// target different tables), not mutually exclusive — a node that hosts guests in two peered VPCs
// sees ru.Vni be its own table *and* a peer VNI at once.
func (b *Bus) apply(ctx context.Context, ru *rbv1.RouteUpdate) {
	switch ru.Op {
	case rbv1.RouteOp_ROUTE_OP_ADD:
		b.markSeen(ru.Vni, ru.Prefix)
		if ru.Vni == PublicVNI {
			nh := ""
			if len(ru.Nexthops) > 0 {
				nh = ru.Nexthops[0] // ECMP set carried; v1 programs the primary
			}
			b.mu.Lock()
			b.learnedPublic[ru.Prefix] = nh
			b.mu.Unlock()
		} else {
			b.setLearnedOwn(ru.Vni, ru.Prefix, ownRoute{nexthops: append([]string(nil), ru.Nexthops...), external: ru.External})
		}
	case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
		if ru.Vni == PublicVNI {
			b.mu.Lock()
			delete(b.learnedPublic, ru.Prefix)
			b.mu.Unlock()
		} else {
			b.delLearnedOwn(ru.Vni, ru.Prefix)
		}
	default:
		return
	}
	b.syncLearned(ctx, ru.Vni, ru.Prefix, true)
}

// syncLearned programs every key a learned route on (vni, prefix) feeds: the public defaults in
// each egress VNI, or vni's own table and each table importing vni. force applies to the own-table
// key only (see syncKey): the RouteUpdate is about that key, so it is passed through to the
// dataplane whatever this Bus last programmed there, as before. The keys it feeds by import change
// only if their wanted route did.
func (b *Bus) syncLearned(ctx context.Context, vni uint32, prefix string, force bool) {
	if vni == PublicVNI {
		for _, egress := range b.egressVNIs {
			_, _ = b.syncKey(ctx, egress, prefix, false)
		}
		return
	}
	_, _ = b.syncKey(ctx, vni, prefix, force)
	for _, im := range b.importersOf(vni) {
		if prefixInCIDRs(prefix, im.prefixes) {
			_, _ = b.syncKey(ctx, im.localVNI, prefix, false)
		}
	}
}

// desiredRoute is what the dataplane should hold for (vni, prefix) in vni's table, from what the
// bus has taught this node — the one rule apply, the release fallback and the resync all program:
//   - a route learned on vni's own table decides the key alone (local routes win), with its
//     delivery VNI = vni. A local guest's key whose only nexthop is this node wants nothing:
//     X->self must never sit in flowplane's shadow to be reinstalled on detach.
//   - else the first import of vni that covers the prefix and has a usable learned route for it.
//     Key = vni (the importer's table), but delivery is stamped with the peer's own VNI so the
//     datapath encaps toward the peer VPC — the load-bearing case for delivery_vni.
//   - else, in an egress VNI, the learned public default: external so SNAT sources follow it, and
//     delivery PublicVNI (0), which the dataplane reads as "the key vni" — there is no VPC to
//     deliver into at VNI 0. LB-address replies miss SNAT and stay public.
func (b *Bus) desiredRoute(vni uint32, prefix string) (dpRoute, bool) {
	if r, ok := b.learnedOwn[vni][prefix]; ok {
		nh, ok := b.nexthopFor(vni, prefix, r.nexthops)
		if !ok {
			return dpRoute{}, false
		}
		return dpRoute{nexthop: nh, external: r.external, deliveryVNI: vni, origin: originOwn}, true
	}
	for _, im := range b.peerImports[vni] {
		r, ok := b.learnedOwn[im.PeerVNI][prefix]
		if !ok || !prefixInCIDRs(prefix, im.ImportPrefixes) {
			continue
		}
		if nh, ok := b.nexthopFor(vni, prefix, r.nexthops); ok {
			return dpRoute{nexthop: nh, deliveryVNI: im.PeerVNI, origin: originPeer}, true
		}
	}
	if nh, ok := b.learnedPublic[prefix]; ok && slices.Contains(b.egressVNIs, vni) {
		return dpRoute{nexthop: nh, external: true, deliveryVNI: PublicVNI, origin: originPublic}, true
	}
	return dpRoute{}, false
}

// syncKey programs desiredRoute(vni, prefix) — an AddRoute, or a WithdrawRoute when nothing is
// wanted — and records it in programmed. Without force it calls the dataplane only when that
// differs from what was last programmed. With force it always does, a withdraw included: flowplane
// may hold a route for the key that this agent never programmed (a held key's shadow from before an
// agent restart). A failed call may or may not have landed (a deadline, say), so it leaves the key
// unknown — the zero dpRoute, which differs from every wanted route and from none — and the next
// resync sends whatever is wanted then. sent reports whether the dataplane was called.
func (b *Bus) syncKey(ctx context.Context, vni uint32, prefix string, force bool) (sent bool, err error) {
	want, ok := b.desiredRoute(vni, prefix)
	have, had := b.programmed[vni][prefix]
	k := routeRef{vni, prefix}
	if !ok {
		if !had && !force {
			return false, nil
		}
		if err := b.dp.WithdrawRoute(ctx, vni, prefix); err != nil {
			b.noteFailure(k, fmt.Sprintf("WithdrawRoute vni=%d %s", vni, prefix), err)
			b.setProgrammed(vni, prefix, dpRoute{})
			return true, err
		}
		b.noteSuccess(k)
		b.forgetProgrammed(vni, prefix)
		return true, nil
	}
	if had && have == want && !force {
		return false, nil
	}
	if err := b.dp.AddRoute(ctx, vni, prefix, want.nexthop, want.external, want.deliveryVNI); err != nil {
		b.noteFailure(k, fmt.Sprintf("AddRoute vni=%d %s -> %s external=%t delivery=%d (%s)",
			vni, prefix, want.nexthop, want.external, want.deliveryVNI, want.origin), err)
		b.setProgrammed(vni, prefix, dpRoute{})
		return true, err
	}
	b.noteSuccess(k)
	b.setProgrammed(vni, prefix, want)
	return true, nil
}

// noteFailure logs a failed call and backs the key off. An unreachable dataplane is not the key's
// fault: it is logged each time, as before, and not backed off, so the key goes out as soon as the
// dataplane is back. Any other failure — the dataplane refused this route — is logged once, when
// the key starts failing or fails differently, and retried 1, 2, 4, ... ticks later, up to
// retryMaxTicks apart; the summary keeps it visible meanwhile.
func (b *Bus) noteFailure(k routeRef, call string, err error) {
	if transientDataplaneError(err) {
		log.Printf("%s: %v", call, err)
		return
	}
	r := b.retries[k]
	if r == nil {
		r = &routeRetry{}
		b.retries[k] = r
	}
	r.failures++
	r.nextTick = b.ticks + min(1<<min(r.failures-1, 30), retryMaxTicks)
	if msg := err.Error(); msg != r.lastError {
		r.lastError = msg
		log.Printf("%s: %v — retrying with backoff", call, err)
	}
}

// noteSuccess ends a key's backoff, logging the recovery if it had been failing.
func (b *Bus) noteSuccess(k routeRef) {
	if r := b.retries[k]; r != nil {
		log.Printf("route vni=%d %s programmed after %d failed attempt(s)", k.Vni, k.Prefix, r.failures)
		delete(b.retries, k)
	}
}

func (b *Bus) setProgrammed(vni uint32, prefix string, r dpRoute) {
	if b.programmed[vni] == nil {
		b.programmed[vni] = map[string]dpRoute{}
	}
	b.programmed[vni][prefix] = r
}

func (b *Bus) forgetProgrammed(vni uint32, prefix string) {
	if m := b.programmed[vni]; m != nil {
		delete(m, prefix)
		if len(m) == 0 {
			delete(b.programmed, vni)
		}
	}
}

// importer is one local VNI importing the peer VNI of a RouteUpdate, with that import's prefixes.
type importer struct {
	localVNI uint32
	prefixes []string
}

// importersOf returns the local VNIs (with their import prefixes) that import peerVNI. Nil-safe.
func (b *Bus) importersOf(peerVNI uint32) []importer {
	var out []importer
	for local, imports := range b.peerImports {
		for _, im := range imports {
			if im.PeerVNI == peerVNI {
				out = append(out, importer{localVNI: local, prefixes: im.ImportPrefixes})
			}
		}
	}
	return out
}

// setPeerImportsLocked replaces the peer-import table (called under b.mu each reconcile). A copy is
// stored so a later mutation of the DesiredState map can't race the apply goroutine.
func (b *Bus) setPeerImportsLocked(m map[uint32][]PeerImport) {
	next := map[uint32][]PeerImport{}
	for local, imports := range m {
		cp := make([]PeerImport, len(imports))
		for i, im := range imports {
			cp[i] = PeerImport{PeerVNI: im.PeerVNI, ImportPrefixes: append([]string(nil), im.ImportPrefixes...)}
		}
		next[local] = cp
	}
	b.peerImports = next
}

// prefixInCIDRs reports whether the route prefix's host address is contained in any of cidrs. A
// route "10.1.0.5/32" is "within" "10.1.0.0/24" when the address 10.1.0.5 is inside the CIDR. An
// empty cidrs set never matches (fail-closed): an import with no prefixes exposes nothing.
func prefixInCIDRs(prefix string, cidrs []string) bool {
	addr, _, err := net.ParseCIDR(prefix)
	if err != nil {
		// prefix may be a bare address rather than CIDR form; try that.
		if addr = net.ParseIP(prefix); addr == nil {
			return false
		}
	}
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if ipnet.Contains(addr) {
			return true
		}
	}
	return false
}

// LearnedPublic returns a copy of the learned public-VNI prefix -> nexthop map
// (the external default routes imported into this node's egress VNIs).
func (b *Bus) LearnedPublic() map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]string, len(b.learnedPublic))
	for k, v := range b.learnedPublic {
		out[k] = v
	}
	return out
}

// dpAdapter wraps the real DataplaneNode gRPC client as a Dataplane.
type dpAdapter struct{ c dpv1.DataplaneNodeClient }

// NewDataplaneAdapter adapts a DataplaneNode client to the agent's Dataplane interface.
func NewDataplaneAdapter(c dpv1.DataplaneNodeClient) Dataplane { return dpAdapter{c: c} }

func (d dpAdapter) AddRoute(ctx context.Context, vni uint32, prefix, nexthop string, external bool, deliveryVNI uint32) error {
	_, err := d.c.AddRoute(ctx, &dpv1.AddRouteRequest{
		Vni: vni, Prefix: prefix, NexthopUnderlay: nexthop, External: external, DeliveryVni: deliveryVNI,
	})
	return err
}
func (d dpAdapter) WithdrawRoute(ctx context.Context, vni uint32, prefix string) error {
	_, err := d.c.WithdrawRoute(ctx, &dpv1.WithdrawRouteRequest{Vni: vni, Prefix: prefix})
	return err
}
func (d dpAdapter) AddNatSource(ctx context.Context, vni uint32, sourceIP, natIP string, portMin, portMax uint32) error {
	_, err := d.c.AddNatSource(ctx, &dpv1.AddNatSourceRequest{
		Vni: vni, SourceIp: sourceIP, NatIp: natIP, PortMin: portMin, PortMax: portMax,
	})
	return err
}
func (d dpAdapter) AddNeighborNat(ctx context.Context, natIp string, min, max uint32, ownerUnderlay string, vni uint32) error {
	_, err := d.c.AddNeighborNat(ctx, &dpv1.AddNeighborNatRequest{
		NatIp: natIp, PortMin: min, PortMax: max, OwnerUnderlay: ownerUnderlay, Vni: vni,
	})
	return err
}
func (d dpAdapter) WithdrawNeighborNat(ctx context.Context, natIp string, min, max uint32, vni uint32) error {
	_, err := d.c.WithdrawNeighborNat(ctx, &dpv1.WithdrawNeighborNatRequest{
		NatIp: natIp, PortMin: min, PortMax: max, Vni: vni,
	})
	return err
}
func (d dpAdapter) ReplaceNeighborNats(ctx context.Context, blocks []NeighborNatBlock) error {
	req := &dpv1.ReplaceNeighborNatsRequest{Blocks: make([]*dpv1.NeighborNatBlock, 0, len(blocks))}
	for _, b := range blocks {
		req.Blocks = append(req.Blocks, &dpv1.NeighborNatBlock{
			NatIp: b.NatIP, PortMin: b.PortMin, PortMax: b.PortMax, OwnerUnderlay: b.OwnerUnderlay, Vni: b.Vni,
		})
	}
	_, err := d.c.ReplaceNeighborNats(ctx, req)
	return err
}
func (d dpAdapter) ReplaceInterfaceFirewall(ctx context.Context, interfaceID string, rules []FwRuleWithID) error {
	specs := make([]*dpv1.FwRuleSpec, 0, len(rules))
	for _, rr := range rules {
		specs = append(specs, &dpv1.FwRuleSpec{
			RuleId:     rr.ID,
			SrcCidr:    rr.Rule.SrcCIDR,
			DstCidr:    rr.Rule.DstCIDR,
			Proto:      rr.Rule.Proto,
			DstPortMin: rr.Rule.DstPortMin,
			DstPortMax: rr.Rule.DstPortMax,
			IcmpType:   rr.Rule.IcmpType,
			IcmpCode:   rr.Rule.IcmpCode,
			Allow:      rr.Rule.Allow,
			Egress:     rr.Rule.Egress,
		})
	}
	_, err := d.c.ReplaceInterfaceFirewall(ctx, &dpv1.ReplaceInterfaceFirewallRequest{
		InterfaceId: interfaceID,
		Rules:       specs,
	})
	return err
}
func (d dpAdapter) AddLoadBalancer(ctx context.Context, id string, vni uint32, lbIP, lbUnderlay string, ports []LbPort) error {
	pp := make([]*dpv1.PortProto, 0, len(ports))
	for _, p := range ports {
		pp = append(pp, &dpv1.PortProto{Port: p.Port, Proto: p.Proto})
	}
	_, err := d.c.AddLoadBalancer(ctx, &dpv1.AddLoadBalancerRequest{Id: id, Vni: vni, Ip: lbIP, LbUnderlay: lbUnderlay, Ports: pp})
	return err
}
func (d dpAdapter) DelLoadBalancer(ctx context.Context, id string) error {
	_, err := d.c.DelLoadBalancer(ctx, &dpv1.DelLoadBalancerRequest{Id: id})
	return err
}
func (d dpAdapter) AddLbBackend(ctx context.Context, id, backendUnderlay, backendOverlayIP string, backendVni uint32) error {
	_, err := d.c.AddLbBackend(ctx, &dpv1.AddLbBackendRequest{
		Id:               id,
		BackendUnderlay:  backendUnderlay,
		BackendOverlayIp: backendOverlayIP,
		BackendVni:       backendVni,
	})
	return err
}
func (d dpAdapter) DelLbBackend(ctx context.Context, id, backendUnderlay, backendOverlayIP string) error {
	_, err := d.c.DelLbBackend(ctx, &dpv1.DelLbBackendRequest{
		Id: id, BackendUnderlay: backendUnderlay, BackendOverlayIp: backendOverlayIP,
	})
	return err
}
func (d dpAdapter) ConfigureQoS(ctx context.Context, interfaceID string, egressMbps, publicMbps, ingressMbps uint32) error {
	_, err := d.c.ConfigureQoS(ctx, &dpv1.ConfigureQoSRequest{
		InterfaceId: interfaceID, EgressMbps: egressMbps, PublicMbps: publicMbps, IngressMbps: ingressMbps,
	})
	return err
}
func (d dpAdapter) ListInterfaces(ctx context.Context) ([]LocalInterface, string, error) {
	resp, err := d.c.ListInterfaces(ctx, &dpv1.ListInterfacesRequest{})
	if err != nil {
		return nil, "", err
	}
	out := make([]LocalInterface, 0, len(resp.GetInterfaces()))
	for _, i := range resp.GetInterfaces() {
		ips := make([]string, 0, 2)
		if i.GetIpv4() != "" {
			ips = append(ips, i.GetIpv4())
		}
		if i.GetIpv6() != "" {
			ips = append(ips, i.GetIpv6())
		}
		out = append(out, LocalInterface{
			InterfaceID: i.GetInterfaceId(), Vni: i.GetVni(), OverlayIPs: ips, Underlay: i.GetUnderlayRoute(),
		})
	}
	return out, resp.GetInstanceId(), nil
}

// refreshLocalHosts re-reads the attached interfaces and, for every host prefix whose interface
// LEFT since the last read (its VM moved away), re-asserts the bus route held for it — the fallback
// described at localHosts. An interface that arrived needs nothing here: flowplane now holds its key
// and keeps whatever mesh route was there in its shadow (the resync moves that off this node's own
// VTEP, see nexthopFor). A failed read keeps the previous view. Run goroutine only.
//
// It reports whether the dataplane may have restarted since the last read — the same read carries
// its instance id — so the caller can re-send what a restart loses (see dpInstance). The first read
// is not a restart: nothing has been programmed into an earlier instance by this agent.
func (b *Bus) refreshLocalHosts(ctx context.Context) bool {
	ifaces, instance, err := b.dp.ListInterfaces(ctx)
	if err != nil {
		log.Printf("ListInterfaces (local host prefixes): %v — keeping the previous view", err)
		b.dpUnreachable = true
		return false
	}
	restarted := b.dpUnreachable || (b.dpSeen && instance != b.dpInstance)
	b.dpInstance, b.dpSeen, b.dpUnreachable = instance, true, false
	next := map[uint32]map[string]bool{}
	own := map[string]bool{b.underlay: true}
	for _, iface := range ifaces {
		if iface.Underlay != "" {
			own[iface.Underlay] = true
		}
		if iface.Vni == 0 {
			continue
		}
		for _, ip := range iface.OverlayIPs {
			prefix, err := hostPrefix(ip)
			if err != nil {
				continue
			}
			if next[iface.Vni] == nil {
				next[iface.Vni] = map[string]bool{}
			}
			next[iface.Vni][prefix] = true
		}
	}
	prev := b.localHosts
	b.localHosts, b.ownUnderlays = next, own
	for vni, prefixes := range prev {
		for prefix := range prefixes {
			if !next[vni][prefix] {
				b.releaseLocalHost(ctx, vni, prefix)
			}
		}
	}
	return restarted
}

// releaseLocalHost re-asserts what the bus holds for a key whose local interface just left: the own
// route if one is learned, else a peer import or public default (own routes win, as in apply). This
// node may have announced the /32 too (mid-move): its own withdraw is on its way to the reflector,
// so its VTEP is dropped from the held set here — a route to itself for a guest it no longer has is
// a loop — and with no other nexthop left, nothing is programmed. It is NOT marked seen: it may come
// from what an earlier session learned, so a replay in progress must still be able to prune it.
func (b *Bus) releaseLocalHost(ctx context.Context, vni uint32, prefix string) {
	if r, ok := b.learnedOwn[vni][prefix]; ok {
		r.nexthops = slices.DeleteFunc(slices.Clone(r.nexthops), func(nh string) bool { return b.ownUnderlays[nh] })
		b.learnedOwn[vni][prefix] = r
	}
	_, _ = b.syncKey(ctx, vni, prefix, true)
}

// nexthopFor picks the nexthop to program for (vni, prefix) from a route's sorted set. Any key but
// a local guest's host prefix gets the first, as it always has — for an E/W LB address a self
// nexthop is right, since flowplane delivers it locally. A local host key gets the first nexthop
// that is not this node instead, so flowplane's shadow never holds X->self for a guest that is
// here; ok is false when only this node is left, or nothing at all.
func (b *Bus) nexthopFor(vni uint32, prefix string, nexthops []string) (string, bool) {
	if !b.localHosts[vni][prefix] {
		if len(nexthops) == 0 {
			return "", false
		}
		return nexthops[0], true
	}
	nh := b.foreignNexthop(nexthops)
	return nh, nh != ""
}

// foreignNexthop is the first of nexthops that is not one of this node's VTEPs, or "".
func (b *Bus) foreignNexthop(nexthops []string) string {
	for _, nh := range nexthops {
		if !b.ownUnderlays[nh] {
			return nh
		}
	}
	return ""
}

func (b *Bus) setLearnedOwn(vni uint32, prefix string, r ownRoute) {
	if b.learnedOwn[vni] == nil {
		b.learnedOwn[vni] = map[string]ownRoute{}
	}
	b.learnedOwn[vni][prefix] = r
}

func (b *Bus) delLearnedOwn(vni uint32, prefix string) {
	if m := b.learnedOwn[vni]; m != nil {
		delete(m, prefix)
		if len(m) == 0 {
			delete(b.learnedOwn, vni)
		}
	}
}
