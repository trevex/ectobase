// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"net"
	"testing"
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
