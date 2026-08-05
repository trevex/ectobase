// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"context"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/trevex/ectobase/netplane/gen/routebusv1"
)

// AdminServer implements RouteBusAdmin over a RIB: central sets/clears per-/64 route
// fences to suppress a lost pool's overlay routes (the network half of Tier-2 fencing).
//
// TODO(authz): admin RPCs are higher-privilege than the RouteBus Session service and
// should be gated by per-RPC authz (a separate cert/SPIFFE ID or an interceptor); they
// currently inherit only the server's transport mTLS.
type AdminServer struct {
	pb.UnimplementedRouteBusAdminServer
	rib *RIB
}

// NewAdminServer wraps the RIB with the admin fence API.
func NewAdminServer(rib *RIB) *AdminServer { return &AdminServer{rib: rib} }

// SetFence blocks a node /64: rejects future announces from and withdraws existing
// routes whose nexthop is inside it.
func (a *AdminServer) SetFence(_ context.Context, req *pb.FenceRequest) (*pb.FenceReply, error) {
	if _, _, err := net.ParseCIDR(req.GetPrefix()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid fence prefix %q: %v", req.GetPrefix(), err)
	}
	a.rib.SetFence(req.GetPrefix())
	return &pb.FenceReply{}, nil
}

// ClearFence removes a /64 block; owning agents restore their routes on next resync.
func (a *AdminServer) ClearFence(_ context.Context, req *pb.FenceRequest) (*pb.FenceReply, error) {
	if _, _, err := net.ParseCIDR(req.GetPrefix()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid fence prefix %q: %v", req.GetPrefix(), err)
	}
	a.rib.ClearFence(req.GetPrefix())
	return &pb.FenceReply{}, nil
}
