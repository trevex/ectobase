// Package agent is the per-node control plane: a route-bus client that announces
// local endpoint routes, subscribes by VNI, and drives the local xdp-dp datapath
// as remote routes arrive.
package agent

import (
	"context"
	"io"
	"log"

	dpv1 "github.com/trevex/xdp-dp/cni/gen/dataplanev1"
	rbv1 "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
	"google.golang.org/grpc"
)

// Dataplane is the subset of xdp-dp the agent drives. dpAdapter wraps the real
// DataplaneNode gRPC client; tests supply a fake.
type Dataplane interface {
	AddRoute(ctx context.Context, vni uint32, prefix, nexthop string, external bool) error
	WithdrawRoute(ctx context.Context, vni uint32, prefix string) error
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
}

func NewBus(nodeID, underlay string, dp Dataplane) *Bus {
	return &Bus{nodeID: nodeID, underlay: underlay, dp: dp}
}

// Run opens a Session, sends Hello + the initial subscriptions + announcements,
// then pumps RouteUpdates into the dataplane until ctx is done or the stream errors.
func (b *Bus) Run(ctx context.Context, cc rbv1.RouteBusClient, subVNIs []uint32, announce []Route) error {
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
		// EndOfRIB / KeepAlive: v1 no-op (prune-on-EoR is a follow-up).
	}
}

func (b *Bus) announce(stream rbv1.RouteBus_SessionClient, r Route) error {
	return stream.Send(&rbv1.ClientMsg{Msg: &rbv1.ClientMsg_Announce{Announce: &rbv1.Announce{
		Vni: r.Vni, Prefix: r.Prefix, NexthopUnderlay: r.Nexthop, External: r.External,
	}}})
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

var _ = grpc.WaitForReady // keep grpc import if unused after edits; remove if the linter objects
