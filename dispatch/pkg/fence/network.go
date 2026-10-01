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

// AnnouncedFrom asks the reflector which of keys are still announced from inside prefix,
// fenced or not. Every error is returned — an older reflector without the RPC answers
// Unimplemented — and failover holds the release on it.
func (f *NetworkFencer) AnnouncedFrom(ctx context.Context, prefix string, keys []failover.RouteKey) ([]failover.RouteKey, error) {
	req := &pb.AnnouncedFromRequest{Prefix: prefix, Keys: make([]*pb.RouteKey, 0, len(keys))}
	for _, k := range keys {
		req.Keys = append(req.Keys, &pb.RouteKey{Vni: k.VNI, Prefix: k.Prefix})
	}
	rep, err := f.admin.AnnouncedFrom(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("reflector AnnouncedFrom %s: %w", prefix, err)
	}
	held := make([]failover.RouteKey, 0, len(rep.GetKeys()))
	for _, k := range rep.GetKeys() {
		held = append(held, failover.RouteKey{VNI: k.GetVni(), Prefix: k.GetPrefix()})
	}
	return held, nil
}
