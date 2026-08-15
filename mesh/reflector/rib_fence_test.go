// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import "testing"

func TestRIB_Fence_RejectsAnnounceFromFencedNexthop(t *testing.T) {
	r := NewRIB()
	r.SetFence("2001:db8:0:1::/64")
	// Announce a route whose nexthop is inside the fenced /64 -> must be dropped.
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	if r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("fenced-nexthop route must not be stored")
	}
	// A route from an unfenced nexthop is accepted.
	r.Announce("nodeB", 100, "10.0.0.6/32", []string{"2001:db8:0:2::b"}, false)
	if !r.HasRoute(100, "10.0.0.6/32") {
		t.Fatalf("unfenced route must be stored")
	}
}

func TestRIB_SetFence_WithdrawsExistingMatching(t *testing.T) {
	r := NewRIB()
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	if !r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("precondition: route stored")
	}
	r.SetFence("2001:db8:0:1::/64")
	if r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("SetFence must withdraw existing routes with a fenced nexthop")
	}
	r.ClearFence("2001:db8:0:1::/64")
	// After clear, a re-announce is accepted again.
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	if !r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("ClearFence must re-allow announces")
	}
}
