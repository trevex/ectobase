// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"slices"
	"testing"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestUnderlayGuard_Permits(t *testing.T) {
	own := net.ParseIP("fd00:cafe:1914::1")

	// mTLS off: enforcement disabled, everything allowed.
	off := underlayGuard{enforce: false}
	if !off.permits("fd00:cafe:9999::1") {
		t.Error("mTLS off must permit any underlay (dev mode)")
	}

	// mTLS on: only the exact SAN is permitted. Under the node-VTEP scheme a node announces
	// exactly one underlay — its VTEP — so anything else is someone else's address.
	on := underlayGuard{allowed: []net.IP{own}, enforce: true}
	if !on.permits("fd00:cafe:1914::1") {
		t.Error("own underlay must be permitted")
	}
	// The load-bearing tightening. Nodes in a cluster SHARE an underlay /64 and take /128s
	// inside it, so under the old /64 match this address was a PEER NODE's VTEP and announcing
	// it drew that node's traffic. The /64 match existed for per-endpoint underlay /128s that
	// Geneve retired; a node now has one VTEP and announces only that.
	if on.permits("fd00:cafe:1914::5") {
		t.Error("a peer node's VTEP in the shared cluster /64 must be rejected")
	}
	if on.permits("fd00:cafe:1aa7::1") {
		t.Error("another node's underlay must be rejected")
	}
	if on.permits("fd00:cafe:1914:1::1") {
		t.Error("a different /64 must be rejected")
	}
	if on.permits("not-an-ip") {
		t.Error("unparseable underlay must be rejected")
	}
	if on.permits("") {
		t.Error("empty underlay must be rejected")
	}

	// A speaker with several SANs may speak for each of them, and only them. This is how the WAN
	// edge announces EDGE_UNDERLAY, whose owner (its control loopback) differs from the anycast
	// underlay the record carries.
	loop := net.ParseIP("fd00:ffff::e1")
	multi := underlayGuard{allowed: []net.IP{own, loop}, enforce: true}
	if !multi.permits("fd00:cafe:1914::1") || !multi.permits("fd00:ffff::e1") {
		t.Error("each SAN must be permitted")
	}
	if multi.permits("fd00:ffff::e2") {
		t.Error("a peer edge's loopback must be rejected")
	}

	// mTLS on but no SANs (shouldn't happen for a valid leaf): reject.
	empty := underlayGuard{allowed: nil, enforce: true}
	if empty.permits("fd00:cafe:1914::1") {
		t.Error("no cert SANs => reject")
	}
}

// fakeSession drives Server.Session in-process with a chosen peer context, so a test can present a
// verified client certificate with IP SANs (bufconn + insecure creds cannot). Recv reports each
// call on polled before blocking: once a test sees the poll that follows a message, the server has
// finished handling that message.
type fakeSession struct {
	grpc.ServerStream
	ctx    context.Context
	in     chan *pb.ClientMsg
	polled chan struct{}
}

func (f *fakeSession) Context() context.Context { return f.ctx }
func (f *fakeSession) Send(*pb.ServerMsg) error { return nil }
func (f *fakeSession) Recv() (*pb.ClientMsg, error) {
	f.polled <- struct{}{}
	m, ok := <-f.in
	if !ok {
		return nil, io.EOF
	}
	return m, nil
}

// sanCtx is a mutually authenticated peer whose leaf carries the given IP SANs.
func sanCtx(ips ...string) context.Context {
	cert := &x509.Certificate{}
	for _, ip := range ips {
		cert.IPAddresses = append(cert.IPAddresses, net.ParseIP(ip))
	}
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{cert}},
		}},
	})
}

// overSession opens a session as nodeA with the given cert SANs, sends one message, and calls
// inspect on the RIB while the session is still up (closing it fast-withdraws whatever it
// announced).
func overSession(t *testing.T, sans []string, msg *pb.ClientMsg, inspect func(*RIB)) {
	t.Helper()
	rib := NewRIB()
	f := &fakeSession{ctx: sanCtx(sans...), in: make(chan *pb.ClientMsg), polled: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- NewServer(rib).Session(f) }()

	<-f.polled
	f.in <- &pb.ClientMsg{Msg: &pb.ClientMsg_Hello{Hello: &pb.Hello{NodeId: "nodeA"}}}
	<-f.polled
	f.in <- msg
	<-f.polled // the message has been handled
	inspect(rib)

	close(f.in)
	if err := <-done; err != nil {
		t.Fatalf("session: %v", err)
	}
}

// announceOverSession sends one Announce over overSession and returns what the RIB advertises
// for its prefix.
func announceOverSession(t *testing.T, sans []string, a *pb.Announce) (got []string) {
	t.Helper()
	overSession(t, sans, &pb.ClientMsg{Msg: &pb.ClientMsg_Announce{Announce: a}}, func(rib *RIB) {
		got = rib.Advertised(a.Vni, a.Prefix)
	})
	return got
}

func TestSessionAnnounceAuthorizesEveryNexthop(t *testing.T) {
	const own, peerVTEP = "fd00:cafe:1914::1", "fd00:cafe:1914::5"

	// An extra nexthop that is another node's VTEP would put that node into the route's nexthop
	// set and steer traffic to it. The whole Announce is rejected: nothing reaches the RIB.
	if got := announceOverSession(t, []string{own}, &pb.Announce{
		Vni: 100, Prefix: "10.0.0.1/32", NexthopUnderlay: own, ExtraNexthops: []string{peerVTEP},
	}); len(got) != 0 {
		t.Errorf("extra nexthop outside the cert: RIB advertises %v, want nothing", got)
	}

	// Extra nexthops that are all the session's own SANs are accepted (duplicates collapse).
	const second = "fd00:ffff::e1"
	got := announceOverSession(t, []string{own, second}, &pb.Announce{
		Vni: 100, Prefix: "10.0.0.2/32", NexthopUnderlay: own, ExtraNexthops: []string{second, own},
	})
	if want := []string{own, second}; !slices.Equal(got, want) {
		t.Errorf("extra nexthops within the cert: RIB advertises %v, want %v", got, want)
	}

	// The primary nexthop is still checked.
	if got := announceOverSession(t, []string{own}, &pb.Announce{
		Vni: 100, Prefix: "10.0.0.3/32", NexthopUnderlay: peerVTEP,
	}); len(got) != 0 {
		t.Errorf("primary nexthop outside the cert: RIB advertises %v, want nothing", got)
	}
}

func TestSessionEdgeUnderlayAuthorizesTheAnycastAddress(t *testing.T) {
	const anycast, loop, peerVTEP = "fd00:db8:0:9::e", "fd00:ffff::e1", "fd00:cafe:1914::5"
	stored := func(sans []string, prefix string) (n int) {
		overSession(t, sans, &pb.ClientMsg{Msg: &pb.ClientMsg_AnnouncePublic{AnnouncePublic: &pb.PublicPrefix{
			Kind: pb.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY, Prefix: prefix, OwnerUnderlay: loop,
		}}}, func(rib *RIB) {
			rib.mu.Lock()
			n = len(rib.public)
			rib.mu.Unlock()
		})
		return n
	}

	// The record's prefix IS an underlay address: agents map it to the owner loopback to pin the
	// WAN return path. A leaf that holds only the loopback must not claim someone else's address.
	if n := stored([]string{loop}, peerVTEP+"/128"); n != 0 {
		t.Errorf("EDGE_UNDERLAY for an address outside the cert: %d records stored, want 0", n)
	}
	// Not a single address: there is nothing for the cert to cover.
	if n := stored([]string{anycast, loop}, "fd00:db8:0:9::/64"); n != 0 {
		t.Errorf("EDGE_UNDERLAY for a /64: %d records stored, want 0", n)
	}
	// The edge's leaf carries both its anycast underlay and its loopback (routebus.EdgeIdentity).
	if n := stored([]string{anycast, loop}, anycast+"/128"); n != 1 {
		t.Errorf("EDGE_UNDERLAY within the cert: %d records stored, want 1", n)
	}
}
