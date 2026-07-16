// Package agent is the per-node control plane: a route-bus client that announces
// local endpoint routes, subscribes by VNI, and drives the local xdp-dp datapath
// as remote routes arrive.
package agent

import (
	"context"
	"io"
	"log"
	"sync"
	"time"

	dpv1 "github.com/trevex/xdp-dp/cni/gen/dataplanev1"
	rbv1 "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
	"google.golang.org/grpc"
)

// Dataplane is the subset of xdp-dp the agent drives. dpAdapter wraps the real
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
		b.applyPublic(pu.GetPrefix(), pu.GetOp())
	}
	// EndOfRIB / KeepAlive: v1 no-op (learner-side prune-on-EoR is a follow-up).
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
	switch ru.Op {
	case rbv1.RouteOp_ROUTE_OP_ADD:
		if err := b.dp.AddRoute(ctx, ru.Vni, ru.Prefix, nh, ru.External); err != nil {
			log.Printf("AddRoute vni=%d %s -> %s external=%t: %v", ru.Vni, ru.Prefix, nh, ru.External, err)
		}
	case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
		if err := b.dp.WithdrawRoute(ctx, ru.Vni, ru.Prefix); err != nil {
			log.Printf("WithdrawRoute vni=%d %s: %v", ru.Vni, ru.Prefix, err)
		}
	}
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

var _ = grpc.WaitForReady // keep grpc import if unused after edits; remove if the linter objects
