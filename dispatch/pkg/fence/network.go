// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package fence provides the dispatch-side storage + network fence actuators that back
// the failover PrefixFencer seam.
package fence

import (
	"context"
	"fmt"

	"github.com/trevex/ectobase/dispatch/pkg/failover"
	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// NetworkFencer is the network half of Tier-2 fencing: it withdraws a lost pool's
// overlay routes by calling the reflector's RouteBusAdmin SetFence/ClearFence. It is also
// failover's RouteHolder, asking the same reflector what a fenced /64 still announces.
type NetworkFencer struct {
	admin pb.RouteBusAdminClient
}

// NewNetworkFencer wraps a RouteBusAdmin client.
func NewNetworkFencer(admin pb.RouteBusAdminClient) *NetworkFencer {
	return &NetworkFencer{admin: admin}
}

// Fence blocks the /64 at the reflector (idempotent). nil == the fence is set.
func (f *NetworkFencer) Fence(ctx context.Context, prefix string) error {
	if _, err := f.admin.SetFence(ctx, &pb.FenceRequest{Prefix: prefix}); err != nil {
		return fmt.Errorf("reflector SetFence %s: %w", prefix, err)
	}
	return nil
}

// Release clears the /64 block at the reflector.
func (f *NetworkFencer) Release(ctx context.Context, prefix string) error {
	if _, err := f.admin.ClearFence(ctx, &pb.FenceRequest{Prefix: prefix}); err != nil {
		return fmt.Errorf("reflector ClearFence %s: %w", prefix, err)
	}
	return nil
}

// AnnouncedFrom asks the reflector who still announces any of keys from inside prefix,
// fenced or not. Every error is returned — an older reflector without the RPC answers
// Unimplemented — and failover holds the release on it. A held key the reply names no
// holder for is still returned, with the origin left empty.
func (f *NetworkFencer) AnnouncedFrom(ctx context.Context, prefix string, keys []failover.RouteKey) ([]failover.RouteHolding, error) {
	req := &pb.AnnouncedFromRequest{Prefix: prefix, Keys: make([]*pb.RouteKey, 0, len(keys))}
	for _, k := range keys {
		req.Keys = append(req.Keys, &pb.RouteKey{Vni: k.VNI, Prefix: k.Prefix})
	}
	rep, err := f.admin.AnnouncedFrom(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("reflector AnnouncedFrom %s: %w", prefix, err)
	}
	held := make([]failover.RouteHolding, 0, len(rep.GetHoldings()))
	named := map[failover.RouteKey]bool{}
	for _, h := range rep.GetHoldings() {
		k := failover.RouteKey{VNI: h.GetKey().GetVni(), Prefix: h.GetKey().GetPrefix()}
		named[k] = true
		held = append(held, failover.RouteHolding{Key: k, Origin: h.GetOrigin(), Nexthop: h.GetNexthop()})
	}
	for _, pk := range rep.GetKeys() {
		if k := (failover.RouteKey{VNI: pk.GetVni(), Prefix: pk.GetPrefix()}); !named[k] {
			held = append(held, failover.RouteHolding{Key: k})
		}
	}
	return held, nil
}
