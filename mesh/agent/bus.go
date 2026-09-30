// Package agent is the per-node control plane: a route-bus client that announces
// local endpoint routes, subscribes by VNI, and drives the local flowplane datapath
// as remote routes arrive.
package agent

import (
	"context"
	"io"
	"log"
	"net"
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
	// node-local dataplane state, not central config).
	ListInterfaces(ctx context.Context) ([]LocalInterface, error)
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
	// PEER-IMPORT path (see Bus.applyPeer), which builds AddRoute calls directly, not via Route.
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
	// Touched only from the Run goroutine (handleServerMsg), like installed/origin — no lock.
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

	// --- global (NAT + public) snapshot tracking, the EndOfGlobal counterpart to installed/seen.
	// Touched only from the Run goroutine (handleServerMsg), like installed/origin — no lock.
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

	// Peering import bookkeeping (VPC peering). peerImports is set each reconcile (localVNI -> imports).
	// origin tags every installed (vni, prefix) as "own" (locally-originated / direct route) or "peer"
	// (imported from a peer VNI) so LOCAL routes always take precedence over imports and an own-route
	// withdraw can restore a previously-shadowed peer import. learnedPeer keeps the raw learned peer
	// routes (peerVNI -> prefix -> nexthop) so a restore has a nexthop to reinstall.
	peerImports map[uint32][]PeerImport      // localVNI -> imports (set each reconcile; nil-safe)
	origin      map[uint32]map[string]string // vni -> prefix -> "own" | "peer"
	learnedPeer map[uint32]map[string]string // peerVNI -> prefix -> nexthop (raw learned peer routes)

	// installed[vni] is the set of directly-installed (non public-VNI) route prefixes this Bus has
	// programmed on the dataplane. It PERSISTS across reconnects (the dataplane outlives a session)
	// so prune-on-EndOfRIB can remove routes that vanished from the RIB while we were disconnected.
	installed map[uint32]map[string]bool
	// seen[vni] is the set of prefixes (re)learned in the CURRENT session's snapshot; reset at each
	// session open. On EndOfRIB(vni) any installed[vni] prefix not in seen[vni] is stale → withdrawn.
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
	// learnedOwn[vni][prefix] is the bus route last learned for (vni, prefix) on its own table,
	// kept only for that fallback. A WITHDRAW or the EndOfRIB prune forgets it, so the fallback
	// never reinstates a route the bus has withdrawn.
	learnedOwn map[uint32]map[string]ownRoute

	// reconcileEvery is how often Run recomputes the desired announcement set and pushes deltas onto
	// the live stream. Tests override it for fast convergence.
	reconcileEvery time.Duration
}

// natEntry is one learned neighbor-NAT block, keyed exactly as the dataplane programs it so a
// prune can withdraw it verbatim.
type natEntry struct {
	natIP            string
	portMin, portMax uint32
	vni              uint32
}

// ownRoute is one learned own-table bus route: its whole nexthop set, since the one apply
// programs (the first) can be this node's own VTEP.
type ownRoute struct {
	nexthops []string
	external bool
}

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
		installed:       map[uint32]map[string]bool{},
		seen:            map[uint32]map[string]bool{},
		rxRoutes:        map[uint32]uint32{},
		localHosts:      map[uint32]map[string]bool{},
		ownUnderlays:    map[string]bool{},
		learnedOwn:      map[uint32]map[string]ownRoute{},
		peerImports:     map[uint32][]PeerImport{},
		origin:          map[uint32]map[string]string{},
		learnedPeer:     map[uint32]map[string]string{},
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
	// disconnected (installed[] persists across sessions; the dataplane still holds those routes).
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
func (b *Bus) reconcileStep(ctx context.Context, stream rbv1.RouteBus_SessionClient, reconcile func(context.Context) (DesiredState, error), applied *DesiredState) error {
	desired, err := reconcile(ctx)
	if err != nil {
		log.Printf("reconcile: %v", err)
		return nil
	}
	b.mu.Lock()
	prevEgress := b.egressVNIs
	b.egressVNIs = append(b.egressVNIs[:0:0], desired.EgressVNIs...)
	b.setPeerImportsLocked(desired.PeeringImports)
	b.mu.Unlock()
	b.syncEgressImports(ctx, prevEgress, desired.EgressVNIs)
	b.refreshLocalHosts(ctx)
	b.noteSubscribed(desired.Subs)
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

// syncEgressImports installs the already-learned public-VNI defaults into egress VNIs that just
// appeared, and withdraws them from ones that just went away.
//
// Without this the import is EVENT-DRIVEN ONLY: Bus.apply imports a public-VNI route into whatever
// egressVNIs happened to hold at the instant that RouteUpdate arrived. But the normal ordering is
// the other way round — an agent learns the edge's defaults once at session open, and a VNI becomes
// egress-needing LATER, when someone creates the LoadBalancer or NATGateway that makes a local NIC
// an LB backend or a SNAT source. Nothing re-imported for that VNI, so its guests had no route off
// the node: an LB backend's DSR reply reached the guest and then died with nowhere to go, and only
// an agent restart (which replays the whole snapshot AFTER the first reconcile has set egressVNIs)
// ever fixed it. That is a steady-state cluster's ONLY ordering, so N/S from intent alone could
// never work without this.
//
// Runs on the Run goroutine, like apply — no locking beyond the learnedPublic snapshot.
func (b *Bus) syncEgressImports(ctx context.Context, prev, next []uint32) {
	prevSet, nextSet := vniSet(prev), vniSet(next)
	b.mu.Lock()
	learned := make(map[string]string, len(b.learnedPublic))
	for prefix, nh := range b.learnedPublic {
		learned[prefix] = nh
	}
	b.mu.Unlock()

	for vni := range nextSet {
		if prevSet[vni] {
			continue // already importing; apply keeps it current
		}
		for prefix, nh := range learned {
			// deliveryVNI = PublicVNI mirrors Bus.apply's import arm exactly (the dataplane reads a
			// delivery_vni of 0 as "use the key vni"); external=true so SNAT sources follow it.
			if err := b.dp.AddRoute(ctx, vni, prefix, nh, true, PublicVNI); err != nil {
				log.Printf("egress import AddRoute vni=%d %s -> %s: %v", vni, prefix, nh, err)
				continue
			}
			log.Printf("imported public default %s -> %s into newly-egress vni=%d", prefix, nh, vni)
		}
	}
	for vni := range prevSet {
		if nextSet[vni] {
			continue
		}
		for prefix := range learned {
			if err := b.dp.WithdrawRoute(ctx, vni, prefix); err != nil {
				log.Printf("egress unimport WithdrawRoute vni=%d %s: %v", vni, prefix, err)
			}
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

// pruneVNI removes any directly-installed route in vni that was NOT (re)seen in this session's
// snapshot — i.e. a route that left the RIB (peer withdrew, or its owner disconnected) while this
// node was disconnected, and would otherwise linger on the dataplane as a stale blackhole/misroute.
func (b *Bus) pruneVNI(ctx context.Context, vni uint32, want uint32) {
	// A lossy replay must not prune: an older reflector dropped snapshot records on overflow, and
	// withdrawing a live route is strictly worse than keeping a stale one. Same guard as pruneGlobal.
	if got := b.rxRoutes[vni]; got != want {
		log.Printf("EndOfRIB(vni=%d): snapshot incomplete (got %d routes, reflector sent %d) — skipping prune; will retry on the next resync",
			vni, got, want)
		return
	}
	inst := b.installed[vni]
	seen := b.seen[vni]
	// A route the reflector no longer has must not be re-asserted when a local interface leaves.
	for prefix := range b.learnedOwn[vni] {
		if !seen[prefix] {
			b.delLearnedOwn(vni, prefix)
		}
	}
	for prefix := range inst {
		if seen[prefix] {
			continue
		}
		if err := b.dp.WithdrawRoute(ctx, vni, prefix); err != nil {
			log.Printf("prune WithdrawRoute vni=%d %s: %v", vni, prefix, err)
			continue
		}
		delete(inst, prefix)
	}
	if len(inst) == 0 {
		delete(b.installed, vni)
	}
}

// markInstalled / markSeen / markWithdrawn maintain the directly-installed route set used by
// prune-on-EndOfRIB. Called only from the Run goroutine (apply), so no locking.
func (b *Bus) markInstalled(vni uint32, prefix string) {
	if b.installed[vni] == nil {
		b.installed[vni] = map[string]bool{}
	}
	b.installed[vni][prefix] = true
	if b.seen[vni] == nil {
		b.seen[vni] = map[string]bool{}
	}
	b.seen[vni][prefix] = true
}

func (b *Bus) markWithdrawn(vni uint32, prefix string) {
	if m := b.installed[vni]; m != nil {
		delete(m, prefix)
	}
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

func (b *Bus) apply(ctx context.Context, ru *rbv1.RouteUpdate) {
	nh := ""
	if len(ru.Nexthops) > 0 {
		nh = ru.Nexthops[0] // ECMP set carried; v1 programs the primary
	}
	if ru.Vni == PublicVNI {
		// Public-VNI routes are aggregation records: record them and IMPORT into each local egress VNI
		// (a tenant node has no VNI-0 table). External=true so SNAT sources follow it; LB-address replies
		// miss SNAT and stay public.
		b.mu.Lock()
		switch ru.Op {
		case rbv1.RouteOp_ROUTE_OP_ADD:
			b.learnedPublic[ru.Prefix] = nh
		case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
			delete(b.learnedPublic, ru.Prefix)
		}
		evs := append([]uint32(nil), b.egressVNIs...)
		b.mu.Unlock()
		for _, vni := range evs {
			switch ru.Op {
			case rbv1.RouteOp_ROUTE_OP_ADD:
				// deliveryVNI = ru.Vni here is PublicVNI (0): there is no real VPC to deliver into at
				// VNI 0, and the dataplane treats delivery_vni=0 as "default to the key vni" — so this
				// naturally preserves the original behavior (delivery == the local egress vni), while
				// keeping this import structurally identical to a peer import (key != origin vni).
				if err := b.dp.AddRoute(ctx, vni, ru.Prefix, nh, true, ru.Vni); err != nil {
					log.Printf("import AddRoute vni=%d %s -> %s: %v", vni, ru.Prefix, nh, err)
				}
			case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
				if err := b.dp.WithdrawRoute(ctx, vni, ru.Prefix); err != nil {
					log.Printf("import WithdrawRoute vni=%d %s: %v", vni, ru.Prefix, err)
				}
			}
		}
		return
	}
	// A non-public RouteUpdate on ru.Vni is BOTH an own/direct route for ru.Vni's OWN table AND, if any
	// LOCAL vni imports ru.Vni (VPC peering), a peer route to import into those importers' tables. These
	// are ADDITIVE (they target different tables), not mutually exclusive — a node that hosts guests in
	// two peered VPCs sees ru.Vni be its own table *and* a peer VNI at once. So install the own route
	// into ru.Vni's table first, then (if ru.Vni is imported) import it into the importer tables.
	switch ru.Op {
	case rbv1.RouteOp_ROUTE_OP_ADD:
		b.setLearnedOwn(ru.Vni, ru.Prefix, ownRoute{nexthops: append([]string(nil), ru.Nexthops...), external: ru.External})
		// Own table install: delivery vni == the route's own vni (key and delivery match).
		if err := b.dp.AddRoute(ctx, ru.Vni, ru.Prefix, nh, ru.External, ru.Vni); err != nil {
			log.Printf("AddRoute vni=%d %s -> %s external=%t: %v", ru.Vni, ru.Prefix, nh, ru.External, err)
			// Still attempt the peer import below: it targets other tables and must not be skipped.
		} else {
			b.markInstalled(ru.Vni, ru.Prefix)
			// Tag as own; if a peer import currently held this (vni, prefix) the AddRoute above overwrote
			// it in the dataplane (one value per key), so flipping the tag to "own" completes the eviction.
			b.setOrigin(ru.Vni, ru.Prefix, "own")
		}
		// Additionally import into any LOCAL vni that imports ru.Vni. applyPeer targets the IMPORTER
		// tables (never ru.Vni's own table), so there is no self-conflict with the own install above.
		if importers := b.importersOf(ru.Vni); len(importers) > 0 {
			b.applyPeer(ctx, ru, nh, importers)
		}
	case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
		b.delLearnedOwn(ru.Vni, ru.Prefix)
		if err := b.dp.WithdrawRoute(ctx, ru.Vni, ru.Prefix); err != nil {
			log.Printf("WithdrawRoute vni=%d %s: %v", ru.Vni, ru.Prefix, err)
		} else {
			b.markWithdrawn(ru.Vni, ru.Prefix)
			// The own route is gone: restore a shadowed peer import for this (vni, prefix) if one exists,
			// else clear the tag entirely.
			b.clearOrigin(ru.Vni, ru.Prefix)
			b.restoreImport(ctx, ru.Vni, ru.Prefix)
		}
		// Withdraw from importer tables too: applyPeer clears its own learnedPeer bookkeeping and only
		// touches importer tables tagged "peer", so the own withdraw/restore above is unaffected.
		if importers := b.importersOf(ru.Vni); len(importers) > 0 {
			b.applyPeer(ctx, ru, nh, importers)
		}
	}
}

// applyPeer handles the peer-import side of a RouteUpdate whose VNI is imported by some LOCAL vni: it
// records the raw learned peer route (for later restore) and, for each LOCAL vni importing that peer
// VNI whose import prefixes contain the route, installs it into the importer's local table UNLESS a
// local (own) route already holds that exact key. Local routes always win. This runs IN ADDITION to
// the own install into ru.Vni's own table (see apply): the two target different tables, so a VNI that
// is both a local table and a peer VNI (co-resident peered VPCs) gets both without conflict.
func (b *Bus) applyPeer(ctx context.Context, ru *rbv1.RouteUpdate, nh string, importers []importer) {
	switch ru.Op {
	case rbv1.RouteOp_ROUTE_OP_ADD:
		b.setLearnedPeer(ru.Vni, ru.Prefix, nh)
		for _, im := range importers {
			if !prefixInCIDRs(ru.Prefix, im.prefixes) {
				continue
			}
			if b.origin[im.localVNI][ru.Prefix] == "own" {
				continue // local route wins; do not shadow it
			}
			// Peer import: key = im.localVNI (the importer's table), but delivery must be stamped
			// with ru.Vni (the peer's own/origin vni) so the datapath encaps toward the peer VPC —
			// this is the load-bearing case for delivery_vni.
			if err := b.dp.AddRoute(ctx, im.localVNI, ru.Prefix, nh, false, ru.Vni); err != nil {
				log.Printf("peer import AddRoute vni=%d %s -> %s: %v", im.localVNI, ru.Prefix, nh, err)
				continue
			}
			b.setOrigin(im.localVNI, ru.Prefix, "peer")
			b.markInstalled(im.localVNI, ru.Prefix)
		}
	case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
		b.delLearnedPeer(ru.Vni, ru.Prefix)
		for _, im := range importers {
			if !prefixInCIDRs(ru.Prefix, im.prefixes) {
				continue
			}
			if b.origin[im.localVNI][ru.Prefix] != "peer" {
				continue // an own route (or nothing) holds this key; leave it
			}
			if err := b.dp.WithdrawRoute(ctx, im.localVNI, ru.Prefix); err != nil {
				log.Printf("peer import WithdrawRoute vni=%d %s: %v", im.localVNI, ru.Prefix, err)
				continue
			}
			b.clearOrigin(im.localVNI, ru.Prefix)
			b.markWithdrawn(im.localVNI, ru.Prefix)
		}
	}
}

// restoreImport reinstalls a peer import that was shadowed by a now-withdrawn own route on (vni,
// prefix): for each active import on this local vni whose prefixes contain the route and for which a
// learned peer route still exists, AddRoute it back and re-tag as "peer".
func (b *Bus) restoreImport(ctx context.Context, localVNI uint32, prefix string) {
	for _, im := range b.peerImports[localVNI] {
		if !prefixInCIDRs(prefix, im.ImportPrefixes) {
			continue
		}
		nh, ok := b.learnedPeer[im.PeerVNI][prefix]
		if !ok {
			continue
		}
		// Restore mirrors applyPeer: key = localVNI, delivery = im.PeerVNI (the peer's origin vni).
		if err := b.dp.AddRoute(ctx, localVNI, prefix, nh, false, im.PeerVNI); err != nil {
			log.Printf("peer import restore AddRoute vni=%d %s -> %s: %v", localVNI, prefix, nh, err)
			return
		}
		b.setOrigin(localVNI, prefix, "peer")
		b.markInstalled(localVNI, prefix)
		return
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

// origin / learnedPeer bookkeeping. Called only from the apply (Run) goroutine, so no locking.
func (b *Bus) setOrigin(vni uint32, prefix, kind string) {
	if b.origin[vni] == nil {
		b.origin[vni] = map[string]string{}
	}
	b.origin[vni][prefix] = kind
}

func (b *Bus) clearOrigin(vni uint32, prefix string) {
	if m := b.origin[vni]; m != nil {
		delete(m, prefix)
		if len(m) == 0 {
			delete(b.origin, vni)
		}
	}
}

func (b *Bus) setLearnedPeer(peerVNI uint32, prefix, nh string) {
	if b.learnedPeer[peerVNI] == nil {
		b.learnedPeer[peerVNI] = map[string]string{}
	}
	b.learnedPeer[peerVNI][prefix] = nh
}

func (b *Bus) delLearnedPeer(peerVNI uint32, prefix string) {
	if m := b.learnedPeer[peerVNI]; m != nil {
		delete(m, prefix)
		if len(m) == 0 {
			delete(b.learnedPeer, peerVNI)
		}
	}
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
func (d dpAdapter) ListInterfaces(ctx context.Context) ([]LocalInterface, error) {
	resp, err := d.c.ListInterfaces(ctx, &dpv1.ListInterfacesRequest{})
	if err != nil {
		return nil, err
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
	return out, nil
}

// refreshLocalHosts re-reads the attached interfaces and, for every host prefix whose interface
// LEFT since the last read (its VM moved away), re-asserts the bus route held for it — the fallback
// described at localHosts. An interface that arrived needs nothing: flowplane now holds its key and
// keeps whatever mesh route was there in its shadow. A failed read keeps the previous view. Run
// goroutine only, like installed.
func (b *Bus) refreshLocalHosts(ctx context.Context) {
	ifaces, err := b.dp.ListInterfaces(ctx)
	if err != nil {
		log.Printf("ListInterfaces (local host prefixes): %v — keeping the previous view", err)
		return
	}
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
}

// releaseLocalHost re-asserts what the bus holds for a key whose local interface just left: the own
// route if one is learned, else a peer import (own routes win, as in apply). The nexthop is the first
// one in the held set that is not this node — this node may have announced the /32 too (mid-move),
// and a route to itself for a guest it no longer has is a loop; with no other nexthop left, nothing
// is programmed. It is recorded as installed but NOT as seen: it may come from what an earlier
// session learned, so a replay in progress must still be able to prune it.
func (b *Bus) releaseLocalHost(ctx context.Context, vni uint32, prefix string) {
	r, ok := b.learnedOwn[vni][prefix]
	if !ok {
		b.restoreImport(ctx, vni, prefix)
		return
	}
	nh := ""
	for _, cand := range r.nexthops {
		if !b.ownUnderlays[cand] {
			nh = cand
			break
		}
	}
	if nh == "" {
		return
	}
	if err := b.dp.AddRoute(ctx, vni, prefix, nh, r.external, vni); err != nil {
		log.Printf("AddRoute vni=%d %s -> %s (local interface left): %v", vni, prefix, nh, err)
		return
	}
	if b.installed[vni] == nil {
		b.installed[vni] = map[string]bool{}
	}
	b.installed[vni][prefix] = true
	b.setOrigin(vni, prefix, "own")
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
