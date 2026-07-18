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
	rbv1 "github.com/trevex/ectobase/netplane/gen/routebusv1"
)

// Dataplane is the subset of flowplane the agent drives. dpAdapter wraps the real
// DataplaneNode gRPC client; tests supply a fake.
type Dataplane interface {
	AddRoute(ctx context.Context, vni uint32, prefix, nexthop string, external bool) error
	WithdrawRoute(ctx context.Context, vni uint32, prefix string) error
	// AddNatSource programs LOCAL egress SNAT: (vni, sourceIP) is SNATed onto
	// natIP:[portMin,portMax). Delete-then-add, so re-calling is idempotent.
	AddNatSource(ctx context.Context, vni uint32, sourceIP, natIP string, portMin, portMax uint32) error
	// AddNeighborNat installs a return-route for a NAT block OWNED BY ANOTHER node:
	// a return landing here for natIp:[min,max) re-routes to ownerUnderlay.
	AddNeighborNat(ctx context.Context, natIp string, min, max uint32, ownerUnderlay string, vni uint32) error
	WithdrawNeighborNat(ctx context.Context, natIp string, min, max uint32, vni uint32) error
	// AddFwRule programs a single per-interface firewall rule (ingress or egress).
	AddFwRule(ctx context.Context, interfaceID, ruleID string, r FwRule) error
	// DelFwRule removes a per-interface firewall rule by id.
	DelFwRule(ctx context.Context, interfaceID, ruleID string) error
	// AddLbVip registers a load balancer VIP (id == VIP). vni is the WAN/public VNI (0 at the edge);
	// lbUnderlay is the edge's own anycast underlay (unused-but-required for vni==0).
	AddLbVip(ctx context.Context, id string, vni uint32, vip, lbUnderlay string, ports []LbPort) error
	// DelLbVip removes a registered LB VIP by id.
	DelLbVip(ctx context.Context, id string) error
	// AddLbBackend appends a backend underlay /128 to a registered LB VIP.
	AddLbBackend(ctx context.Context, id, backendUnderlay string) error
	// DelLbBackend removes a backend underlay /128 from a registered LB VIP.
	DelLbBackend(ctx context.Context, id, backendUnderlay string) error
	// ConfigureQoS sets the per-interface QoS lanes: egressMbps is EDT-shaped, publicMbps and
	// ingressMbps are policed. All 0 = unlimited (clears). Idempotent.
	ConfigureQoS(ctx context.Context, interfaceID string, egressMbps, publicMbps, ingressMbps uint32) error
}

// FwRule is one compiled firewall rule the agent installs on the dataplane.
type FwRule struct {
	SrcCIDR    string // empty = any
	DstCIDR    string // empty = any
	Proto      uint32 // 6=TCP, 17=UDP, 1=ICMP; 0 = any
	DstPortMin uint32
	DstPortMax uint32
	Allow      bool // true = accept, false = drop
	Egress     bool // true = egress rule, false = ingress
}

// LbPort is one LB service tuple for AddLbVip. Proto is the IP protocol number (6=TCP, 17=UDP).
type LbPort struct {
	Port  uint32
	Proto uint32
}

// Route is a local overlay route this node announces.
type Route struct {
	Vni      uint32
	Prefix   string // CIDR, e.g. "10.0.0.5/32"
	Nexthop  string // this node's underlay IPv6
	External bool   // if set, matching source traffic egress-SNATs (e.g. an external default route)
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
	// records. A later task reads it to pin the WAN return path to a specific edge.
	learnedEdge map[string]string

	egressVNIs    []uint32          // local VNIs that import the public default(s); set each reconcile
	learnedPublic map[string]string // public-VNI prefix -> nexthop (recorded, imported into egressVNIs)

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

	// reconcileEvery is how often Run recomputes the desired announcement set and pushes deltas onto
	// the live stream. Tests override it for fast convergence.
	reconcileEvery time.Duration
}

// defaultReconcileEvery bounds how stale this node's fabric-wide announcements can get after a CRD
// change while the bus session stays up (the K8s watch would make this event-driven; the ticker is
// the simple, robust floor).
const defaultReconcileEvery = 5 * time.Second

func NewBus(nodeID, underlay string, dp Dataplane, isEdge bool) *Bus {
	return &Bus{
		nodeID: nodeID, underlay: underlay, dp: dp, isEdge: isEdge,
		learnedEdge: map[string]string{}, learnedPublic: map[string]string{},
		installed:      map[uint32]map[string]bool{},
		seen:           map[uint32]map[string]bool{},
		peerImports:    map[uint32][]PeerImport{},
		origin:         map[uint32]map[string]string{},
		learnedPeer:    map[uint32]map[string]string{},
		reconcileEvery: defaultReconcileEvery,
	}
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
	if err := stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_Hello{
		Hello: &rbv1.Hello{NodeId: b.nodeID, UnderlayIpv6: b.underlay},
	}}); err != nil {
		return err
	}
	// New session: the reflector will replay each subscribed VNI's snapshot then send EndOfRIB. Reset
	// the per-session "seen" set so prune-on-EndOfRIB removes routes that left the RIB while we were
	// disconnected (installed[] persists across sessions; the dataplane still holds those routes).
	b.seen = map[uint32]map[string]bool{}

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
	b.egressVNIs = append(b.egressVNIs[:0:0], desired.EgressVNIs...)
	b.setPeerImportsLocked(desired.PeeringImports)
	b.mu.Unlock()
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

// handleServerMsg applies one inbound server message to the local dataplane.
func (b *Bus) handleServerMsg(ctx context.Context, msg *rbv1.ServerMsg) {
	if ru := msg.GetRouteUpdate(); ru != nil {
		b.apply(ctx, ru)
	}
	if nu := msg.GetNatUpdate(); nu != nil {
		b.applyNat(ctx, nu)
	}
	if pu := msg.GetPublicUpdate(); pu != nil {
		b.applyPublic(ctx, pu.GetPrefix(), pu.GetOp())
	}
	if eor := msg.GetEndOfRib(); eor != nil {
		b.pruneVNI(ctx, eor.GetVni())
	}
	// KeepAlive: no-op. Global NAT/public records have no EoR marker; they re-converge via the
	// owner's steady-state withdraw + the reflector's DropOrigin on disconnect.
}

// pruneVNI removes any directly-installed route in vni that was NOT (re)seen in this session's
// snapshot — i.e. a route that left the RIB (peer withdrew, or its owner disconnected) while this
// node was disconnected, and would otherwise linger on the dataplane as a stale blackhole/misroute.
func (b *Bus) pruneVNI(ctx context.Context, vni uint32) {
	inst := b.installed[vni]
	seen := b.seen[vni]
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
		if err := stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_WithdrawPublic{WithdrawPublic: &rbv1.PublicPrefix{
			Kind: p.Kind, Prefix: p.Prefix, OwnerUnderlay: p.OwnerUnderlay, Vni: p.Vni, PortMin: p.PortMin, PortMax: p.PortMax,
		}}}); err != nil {
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
	return stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_AnnouncePublic{AnnouncePublic: &rbv1.PublicPrefix{
		Kind: pp.Kind, Prefix: pp.Prefix, OwnerUnderlay: pp.OwnerUnderlay,
		Vni: pp.Vni, PortMin: pp.PortMin, PortMax: pp.PortMax,
	}}})
}

// applyNat programs a learned NAT block. Blocks OWNED BY THIS node are skipped:
// its local SNAT is already programmed by the reconciler via AddNatSource. For a
// block owned by a peer, install a neighbor-nat return-route so a return that
// lands here re-routes to the owner.
func (b *Bus) applyNat(ctx context.Context, nu *rbv1.NatUpdate) {
	if nu.OwnerUnderlay == b.underlay {
		return
	}
	switch nu.Op {
	case rbv1.RouteOp_ROUTE_OP_ADD:
		if err := b.dp.AddNeighborNat(ctx, nu.NatIp, nu.PortMin, nu.PortMax, nu.OwnerUnderlay, nu.Vni); err != nil {
			log.Printf("AddNeighborNat %s:[%d,%d) -> %s vni=%d: %v", nu.NatIp, nu.PortMin, nu.PortMax, nu.OwnerUnderlay, nu.Vni, err)
		}
	case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
		if err := b.dp.WithdrawNeighborNat(ctx, nu.NatIp, nu.PortMin, nu.PortMax, nu.Vni); err != nil {
			log.Printf("WithdrawNeighborNat %s:[%d,%d) vni=%d: %v", nu.NatIp, nu.PortMin, nu.PortMax, nu.Vni, err)
		}
	}
}

func (b *Bus) apply(ctx context.Context, ru *rbv1.RouteUpdate) {
	nh := ""
	if len(ru.Nexthops) > 0 {
		nh = ru.Nexthops[0] // ECMP set carried; v1 programs the primary
	}
	if ru.Vni == PublicVNI {
		// Public-VNI routes are aggregation records: record them and IMPORT into each local egress VNI
		// (a tenant node has no VNI-0 table). External=true so SNAT sources follow it; LB-VIP replies
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
				if err := b.dp.AddRoute(ctx, vni, ru.Prefix, nh, true); err != nil {
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
		if err := b.dp.AddRoute(ctx, ru.Vni, ru.Prefix, nh, ru.External); err != nil {
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
			if err := b.dp.AddRoute(ctx, im.localVNI, ru.Prefix, nh, false); err != nil {
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
		if err := b.dp.AddRoute(ctx, localVNI, prefix, nh, false); err != nil {
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

func (d dpAdapter) AddRoute(ctx context.Context, vni uint32, prefix, nexthop string, external bool) error {
	_, err := d.c.AddRoute(ctx, &dpv1.AddRouteRequest{Vni: vni, Prefix: prefix, NexthopUnderlay: nexthop, External: external})
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
func (d dpAdapter) AddFwRule(ctx context.Context, interfaceID, ruleID string, r FwRule) error {
	_, err := d.c.AddFwRule(ctx, &dpv1.AddFwRuleRequest{
		InterfaceId: interfaceID, RuleId: ruleID,
		SrcCidr: r.SrcCIDR, DstCidr: r.DstCIDR, Proto: r.Proto,
		DstPortMin: r.DstPortMin, DstPortMax: r.DstPortMax,
		Allow: r.Allow, Egress: r.Egress,
	})
	return err
}
func (d dpAdapter) DelFwRule(ctx context.Context, interfaceID, ruleID string) error {
	_, err := d.c.DelFwRule(ctx, &dpv1.DelFwRuleRequest{InterfaceId: interfaceID, RuleId: ruleID})
	return err
}
func (d dpAdapter) AddLbVip(ctx context.Context, id string, vni uint32, vip, lbUnderlay string, ports []LbPort) error {
	pp := make([]*dpv1.PortProto, 0, len(ports))
	for _, p := range ports {
		pp = append(pp, &dpv1.PortProto{Port: p.Port, Proto: p.Proto})
	}
	_, err := d.c.AddLbVip(ctx, &dpv1.AddLbVipRequest{Id: id, Vni: vni, Vip: vip, LbUnderlay: lbUnderlay, Ports: pp})
	return err
}
func (d dpAdapter) DelLbVip(ctx context.Context, id string) error {
	_, err := d.c.DelLbVip(ctx, &dpv1.DelLbVipRequest{Id: id})
	return err
}
func (d dpAdapter) AddLbBackend(ctx context.Context, id, backendUnderlay string) error {
	_, err := d.c.AddLbBackend(ctx, &dpv1.AddLbBackendRequest{Id: id, BackendUnderlay: backendUnderlay})
	return err
}
func (d dpAdapter) DelLbBackend(ctx context.Context, id, backendUnderlay string) error {
	_, err := d.c.DelLbBackend(ctx, &dpv1.DelLbBackendRequest{Id: id, BackendUnderlay: backendUnderlay})
	return err
}
func (d dpAdapter) ConfigureQoS(ctx context.Context, interfaceID string, egressMbps, publicMbps, ingressMbps uint32) error {
	_, err := d.c.ConfigureQoS(ctx, &dpv1.ConfigureQoSRequest{
		InterfaceId: interfaceID, EgressMbps: egressMbps, PublicMbps: publicMbps, IngressMbps: ingressMbps,
	})
	return err
}
