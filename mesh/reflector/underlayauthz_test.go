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

	// mTLS on: any /128 in the cert SAN's /64 is permitted (the node's own endpoints), other
	// /64s rejected.
	on := underlayGuard{allowed: []net.IP{own}, enforce: true}
	if !on.permits("fd00:cafe:1914::1") {
		t.Error("own underlay must be permitted")
	}
	if !on.permits("fd00:cafe:1914::5") {
		t.Error("an endpoint /128 in the node's own /64 must be permitted")
	}
	if on.permits("fd00:cafe:1aa7::1") {
		t.Error("another node's /64 must be rejected")
	}
	if on.permits("fd00:cafe:1914:1::1") {
		t.Error("a different /64 (even nearby) must be rejected")
	}
	if on.permits("not-an-ip") {
		t.Error("unparseable underlay must be rejected")
	}
	if on.permits("") {
		t.Error("empty underlay must be rejected")
	}

	// mTLS on but no SANs (shouldn't happen for a valid leaf): reject.
	empty := underlayGuard{allowed: nil, enforce: true}
	if empty.permits("fd00:cafe:1914::1") {
		t.Error("no cert SANs => reject")
	}
}
