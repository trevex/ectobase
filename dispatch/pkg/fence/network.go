// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package fence provides the dispatch-side storage + network fence actuators that back
// the failover PrefixFencer seam.
package fence

import (
	"context"
	"fmt"

	pb "github.com/trevex/ectobase/netplane/gen/routebusv1"
)

// NetworkFencer is the network half of Tier-2 fencing: it withdraws a lost pool's
// overlay routes by calling the reflector's RouteBusAdmin SetFence/ClearFence.
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
