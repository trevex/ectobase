// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// RequireClientCN returns a unary interceptor that rejects any RPC whose verified
// client-certificate CommonName is not allowedCN. It gates the admin (fence) API to
// the hub-controller identity only, so an agent that holds a valid route-bus session
// cert still cannot drive fencing (a route-withdraw DoS).
//
// If allowedCN is empty the interceptor is a no-op — mTLS-off dev mode, where the
// admin service is expected to be isolated by its listen address instead.
func RequireClientCN(allowedCN string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if allowedCN == "" {
			return handler(ctx, req)
		}
		cn, ok := peerCN(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "admin RPC requires a verified client certificate")
		}
		if cn != allowedCN {
			return nil, status.Errorf(codes.PermissionDenied, "admin RPC not permitted for client identity %q", cn)
		}
		return handler(ctx, req)
	}
}

// peerCN extracts the CommonName of the verified client certificate from the peer's
// mTLS state, or ok=false when the connection is not mutually authenticated.
func peerCN(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", false
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", false
	}
	return tlsInfo.State.VerifiedChains[0][0].Subject.CommonName, true
}
