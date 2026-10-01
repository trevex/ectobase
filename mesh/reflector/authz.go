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
// client-certificate CommonName is not allowedCN, or whose certificate the root did not issue
// directly. It gates the admin (fence) API to the dispatch-controller identity only, so an agent
// that holds a valid route-bus session cert still cannot drive fencing (a route-withdraw DoS).
//
// The CN alone names nobody: every pool holds an intermediate under the same root, and an
// intermediate's name constraints bind SANs, not the subject CN, so a pool can mint a valid leaf
// with CN=dispatch-controller. The dispatch-controller's certificate is issued by the root
// ClusterIssuer itself, so its verified chain is exactly leaf -> root; a leaf below any
// intermediate is refused.
//
// If allowedCN is empty the interceptor is a no-op — mTLS-off dev mode, where the
// admin service is expected to be isolated by its listen address instead.
func RequireClientCN(allowedCN string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if allowedCN == "" {
			return handler(ctx, req)
		}
		cn, rootIssued, ok := peerCN(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "admin RPC requires a verified client certificate")
		}
		if cn != allowedCN || !rootIssued {
			return nil, status.Errorf(codes.PermissionDenied, "admin RPC not permitted for client identity %q (root-issued: %v)", cn, rootIssued)
		}
		return handler(ctx, req)
	}
}

// peerCN extracts the CommonName of the verified client certificate from the peer's mTLS state,
// and whether the root issued it directly (some verified chain is exactly leaf -> root). ok is
// false when the connection is not mutually authenticated.
func peerCN(ctx context.Context) (cn string, rootIssued, ok bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", false, false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", false, false
	}
	chains := tlsInfo.State.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return "", false, false
	}
	for _, c := range chains {
		if len(c) == 2 {
			rootIssued = true
		}
	}
	return chains[0][0].Subject.CommonName, rootIssued, true
}
