// Package agent is the per-node control plane: a route-bus client that announces
// local endpoint routes, subscribes by VNI, and drives the local xdp-dp datapath
// as remote routes arrive.
package agent

import (
	"context"
	"io"
	"log"
	"sync"

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

	mu sync.Mutex
	// learnedEdge maps an edge's anycast datapath /128 (address only) to its
	// UNIQUE control-plane loopback, learned from EDGE_UNDERLAY PublicPrefix
	// records. A later task reads it to pin the WAN return path to a specific edge.
	learnedEdge map[string]string
}

func NewBus(nodeID, underlay string, dp Dataplane) *Bus {
	return &Bus{nodeID: nodeID, underlay: underlay, dp: dp, learnedEdge: map[string]string{}}
}

// Run opens a Session, sends Hello + the initial subscriptions + announcements,
// then pumps RouteUpdates into the dataplane until ctx is done or the stream errors.
func (b *Bus) Run(ctx context.Context, cc rbv1.RouteBusClient, subVNIs []uint32, announce []Route, announceNat []NatBlock, announcePublic []PublicPrefix) error {
	stream, err := cc.Session(ctx)
	if err != nil {
		return err
	}
	if err := stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_Hello{
		Hello: &rbv1.Hello{NodeId: b.nodeID, UnderlayIpv6: b.underlay},
	}}); err != nil {
		return err
	}
	for _, v := range subVNIs {
		if err := stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_Subscribe{
			Subscribe: &rbv1.Subscribe{Vni: v},
		}}); err != nil {
			return err
		}
	}
	for _, r := range announce {
		if err := b.announce(stream, r); err != nil {
			return err
		}
	}
	for _, blk := range announceNat {
		if err := b.AnnounceNat(stream, blk); err != nil {
			return err
		}
	}
	for _, pp := range announcePublic {
		if err := b.AnnouncePublic(stream, pp); err != nil {
			return err
		}
	}
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if ru := msg.GetRouteUpdate(); ru != nil {
			b.apply(ctx, ru)
		}
		if nu := msg.GetNatUpdate(); nu != nil {
			b.applyNat(ctx, nu)
		}
		if pu := msg.GetPublicUpdate(); pu != nil {
			b.applyPublic(pu.GetPrefix(), pu.GetOp())
		}
		// EndOfRIB / KeepAlive: v1 no-op (prune-on-EoR is a follow-up).
	}
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
	_, err := d.c.AddLbVip(ctx, &dpv1.AddLbVipRequest{Id: id, Vni: vni, VipIpv4: vip, LbUnderlay: lbUnderlay, Ports: pp})
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
