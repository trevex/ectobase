// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"context"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// AdminServer implements RouteBusAdmin over a RIB: central sets/clears per-/64 route
// fences to hide a lost pool's overlay routes (the network half of Tier-2 fencing).
type AdminServer struct {
	pb.UnimplementedRouteBusAdminServer
	rib *RIB
}

// NewAdminServer wraps the RIB with the admin fence API.
func NewAdminServer(rib *RIB) *AdminServer { return &AdminServer{rib: rib} }

// SetFence hides every nexthop inside a node /64 from subscribers — routes already
// announced and any announced while the fence stands. The RIB keeps them stored.
func (a *AdminServer) SetFence(_ context.Context, req *pb.FenceRequest) (*pb.FenceReply, error) {
	if _, _, err := net.ParseCIDR(req.GetPrefix()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid fence prefix %q: %v", req.GetPrefix(), err)
	}
	a.rib.SetFence(req.GetPrefix())
	return &pb.FenceReply{}, nil
}

// ClearFence releases a /64: the RIB re-advertises the routes it was hiding from what it
// stores. Owning agents do not re-announce them — on a live session they never resend a
// route they already sent.
func (a *AdminServer) ClearFence(_ context.Context, req *pb.FenceRequest) (*pb.FenceReply, error) {
	if _, _, err := net.ParseCIDR(req.GetPrefix()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid fence prefix %q: %v", req.GetPrefix(), err)
	}
	a.rib.ClearFence(req.GetPrefix())
	return &pb.FenceReply{}, nil
}

// AnnouncedFrom reports which of the asked keys are still announced from inside a prefix, fenced
// or not — what failover waits on before it calls ClearFence (see RIB.AnnouncedFrom).
func (a *AdminServer) AnnouncedFrom(_ context.Context, req *pb.AnnouncedFromRequest) (*pb.AnnouncedFromReply, error) {
	held, err := a.rib.AnnouncedFrom(req.GetPrefix(), req.GetKeys())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid prefix %q: %v", req.GetPrefix(), err)
	}
	return &pb.AnnouncedFromReply{Keys: held}, nil
}
