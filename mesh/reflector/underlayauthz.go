// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"context"
	"net"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// peerCertIPs returns the verified client certificate's IP SANs and whether the connection is
// mutually authenticated. For the route-bus PKI each agent leaf carries exactly its node's
// underlay /128 as an IP SAN, so these are the underlays the session is cryptographically
// entitled to speak for.
func peerCertIPs(ctx context.Context) ([]net.IP, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, false
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nil, false
	}
	return tlsInfo.State.VerifiedChains[0][0].IPAddresses, true
}

// underlayGuard captures a session's permitted underlays (its cert IP SANs) and whether to
// enforce. When the session is not mutually authenticated (mTLS off / dev mode) enforcement is
// disabled and every announcement is allowed, matching the reflector's mTLS-optional posture.
type underlayGuard struct {
	allowed []net.IP
	enforce bool
}

func newUnderlayGuard(ctx context.Context) underlayGuard {
	ips, mtls := peerCertIPs(ctx)
	return underlayGuard{allowed: ips, enforce: mtls}
}

// underlayMask is the node prefix length: a node owns a /64 and its endpoints get /128s inside
// it, so an announced nexthop is permitted when it shares a /64 with one of the session cert's
// IP SANs (the node's own underlay). Exact-/128 would reject the per-endpoint nexthops.
var underlayMask = net.CIDRMask(64, 128)

// permits reports whether the session may announce a route whose nexthop (or NAT/public owner)
// underlay is the given address. Enforces "a node may only speak for its own /64": the underlay
// must fall in the same /64 as one of the session cert's IP SANs.
func (g underlayGuard) permits(underlay string) bool {
	if !g.enforce {
		return true
	}
	ip := net.ParseIP(underlay)
	if ip == nil {
		return false
	}
	target := ip.Mask(underlayMask)
	for _, a := range g.allowed {
		if a.Mask(underlayMask).Equal(target) {
			return true
		}
	}
	return false
}
