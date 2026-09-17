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

// permits reports whether the session may announce a route whose nexthop (or NAT/public owner)
// underlay is the given address. Enforces "a node may only speak for addresses it holds a cert
// for": the underlay must be EXACTLY one of the session cert's IP SANs.
//
// This is an exact match, not a prefix match, because under the node-VTEP scheme a node has one
// underlay address and every announce it makes carries it — route nexthops, NAT-block owners and
// LB_IP owners all resolve to that single VTEP. (It was a /64 prefix match while each endpoint
// got its own underlay /128 carved from the node's /64; Geneve retired that, since the VNI rides
// the tunnel header and local delivery demuxes on (vni, overlay ip) via INTERFACES. The node's
// /64 is still the FENCE coordinate — see StampNodePrefix — just not an announce-authz unit.)
//
// The prefix match was not merely redundant, it was unsound: nodes in a cluster SHARE one underlay
// /64 and take /128s inside it (test/lab/internal/config/derive.go — the /64 is keyed on the
// CLUSTER hash), so a /64 match let any node announce a peer node's VTEP as a nexthop and draw its
// traffic. Keep this exact.
//
// A speaker that legitimately announces an owner different from its datapath address — the WAN
// edge, whose EDGE_UNDERLAY record pairs its anycast underlay with its control loopback — must
// carry both addresses as IP SANs on its leaf.
func (g underlayGuard) permits(underlay string) bool {
	if !g.enforce {
		return true
	}
	ip := net.ParseIP(underlay)
	if ip == nil {
		return false
	}
	for _, a := range g.allowed {
		if a.Equal(ip) {
			return true
		}
	}
	return false
}
