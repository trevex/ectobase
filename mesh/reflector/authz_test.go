// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func peerCtx(cn string) context.Context {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{cert}},
		}},
	})
}

func TestRequireClientCN(t *testing.T) {
	info := &grpc.UnaryServerInfo{}
	called := false
	h := func(context.Context, any) (any, error) { called = true; return "ok", nil }

	cases := []struct {
		name      string
		allowedCN string
		ctx       context.Context
		wantCode  codes.Code
		wantCall  bool
	}{
		{"empty allowedCN is a no-op", "", context.Background(), codes.OK, true},
		{"no client cert is rejected", "dispatch-controller", context.Background(), codes.Unauthenticated, false},
		{"wrong CN is rejected", "dispatch-controller", peerCtx("agent"), codes.PermissionDenied, false},
		{"matching CN passes", "dispatch-controller", peerCtx("dispatch-controller"), codes.OK, true},
	}
	for _, tc := range cases {
		called = false
		_, err := RequireClientCN(tc.allowedCN)(tc.ctx, nil, info, h)
		if status.Code(err) != tc.wantCode {
			t.Errorf("%s: got code %v want %v (err=%v)", tc.name, status.Code(err), tc.wantCode, err)
		}
		if called != tc.wantCall {
			t.Errorf("%s: handler called=%v want %v", tc.name, called, tc.wantCall)
		}
	}
}
