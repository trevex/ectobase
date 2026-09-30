// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"testing"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// A fence is a filter on what the RIB advertises, not a deletion of what it stores. Every test here
// models the real agent: it announces a route ONCE per session and never re-sends it (bus.go
// reconcileStep only sends diffDesired(applied, desired), and applied resets only on a new session),
// so nothing but the RIB itself can bring a fenced route back.

const (
	fencedNet = "2001:db8:0:1::/64"
	fencedNH  = "2001:db8:0:1::a" // inside fencedNet
	healthyNH = "2001:db8:0:2::b" // outside it
)

// lastUpdateFor returns the last RouteUpdate the sink saw for prefix, or nil.
func lastUpdateFor(f *fakeSink, prefix string) *pb.RouteUpdate {
	var last *pb.RouteUpdate
	for _, u := range updates(f) {
		if u.Prefix == prefix {
			last = u
		}
	}
	return last
}

// snapshotOf subscribes a brand-new sink to vni and returns the replay's routes by prefix.
func snapshotOf(r *RIB, vni uint32) map[string][]string {
	s := &fakeSink{id: "fresh-subscriber"}
	r.Subscribe(vni, s)
	out := map[string][]string{}
	for _, u := range updates(s) {
		out[u.Prefix] = u.Nexthops
	}
	return out
}

func wantAdd(t *testing.T, f *fakeSink, prefix string, nexthops ...string) {
	t.Helper()
	u := lastUpdateFor(f, prefix)
	if u == nil || u.Op != pb.RouteOp_ROUTE_OP_ADD || !equalStrs(u.Nexthops, nexthops) {
		t.Fatalf("want last update for %s = ADD %v, got %+v", prefix, nexthops, u)
	}
}

func wantWithdraw(t *testing.T, f *fakeSink, prefix string) {
	t.Helper()
	if u := lastUpdateFor(f, prefix); u == nil || u.Op != pb.RouteOp_ROUTE_OP_WITHDRAW {
		t.Fatalf("want last update for %s = WITHDRAW, got %+v", prefix, u)
	}
}

func TestRIB_Fence_HidesAnnounceFromFencedNexthop(t *testing.T) {
	r := NewRIB()
	r.SetFence(fencedNet)
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{fencedNH}, false)
	if r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("a fenced-nexthop route must not be advertised")
	}
	r.Announce("nodeB", 100, "10.0.0.6/32", []string{healthyNH}, false)
	if !r.HasRoute(100, "10.0.0.6/32") {
		t.Fatalf("an unfenced route must be advertised")
	}
}

// The live defect: SetFence used to delete the route, and ClearFence waited for a re-announce the
// agent never makes, so every route the recovered pool had stayed gone fabric-wide until its
// mesh-agent restarted.
func TestRIB_ClearFence_RestoresRouteWithoutReannounce(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{fencedNH}, false)

	r.SetFence(fencedNet)
	wantWithdraw(t, sub, "10.0.0.5/32")
	if _, ok := snapshotOf(r, 100)["10.0.0.5/32"]; ok {
		t.Fatalf("a fenced route must be absent from a new subscriber's snapshot")
	}

	r.ClearFence(fencedNet)
	wantAdd(t, sub, "10.0.0.5/32", fencedNH)
	if got := snapshotOf(r, 100)["10.0.0.5/32"]; !equalStrs(got, []string{fencedNH}) {
		t.Fatalf("a released route must be back in snapshots, got %v", got)
	}
	if !r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("a released route must be advertised again")
	}
}

// The external flag is part of what was stored, so the route comes back as it was announced.
func TestRIB_ClearFence_RestoresExternalFlag(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(0, sub)
	r.Announce("edge1", 0, "0.0.0.0/0", []string{fencedNH}, true)
	r.SetFence(fencedNet)
	r.ClearFence(fencedNet)
	if u := lastUpdateFor(sub, "0.0.0.0/0"); u == nil || u.Op != pb.RouteOp_ROUTE_OP_ADD || !u.External {
		t.Fatalf("want the restored route re-advertised as external, got %+v", u)
	}
}

func TestRIB_AnnounceDuringFence_AdvertisedOnClear(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)
	r.SetFence(fencedNet)

	r.Announce("nodeA", 100, "10.0.0.5/32", []string{fencedNH}, false)
	if u := lastUpdateFor(sub, "10.0.0.5/32"); u != nil {
		t.Fatalf("an announce behind a fence must not reach subscribers, got %+v", u)
	}
	if _, ok := snapshotOf(r, 100)["10.0.0.5/32"]; ok {
		t.Fatalf("an announce behind a fence must be absent from snapshots")
	}

	r.ClearFence(fencedNet)
	wantAdd(t, sub, "10.0.0.5/32", fencedNH)
	if !r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("the route announced during the fence must be advertised once it clears")
	}
}

// The failed-over VM: its interface on the recovered pool is gone, so that pool's agent withdraws
// the route while the fence still hides it. Releasing the fence must not bring it back.
func TestRIB_WithdrawDuringFence_StaysGoneAfterClear(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{fencedNH}, false)
	r.SetFence(fencedNet)
	n := len(updates(sub))

	r.Withdraw("nodeA", 100, "10.0.0.5/32")
	if got := len(updates(sub)); got != n {
		t.Fatalf("withdrawing a route the fence already hides must not fan out again, got %d more", got-n)
	}
	r.ClearFence(fencedNet)
	if got := len(updates(sub)); got != n {
		t.Fatalf("a route withdrawn during the fence must not come back, got %+v", updates(sub)[n:])
	}
	if r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("a route withdrawn during the fence must not be advertised after it clears")
	}
}

// A session that ends during the fence takes its hidden routes with it.
func TestRIB_OriginDroppedDuringFence_StaysGoneAfterClear(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{fencedNH}, false)
	r.SetFence(fencedNet)
	r.dropOrigin("nodeA")
	r.ClearFence(fencedNet)
	wantWithdraw(t, sub, "10.0.0.5/32")
	if r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("a dropped origin's route must not be advertised after the fence clears")
	}
}

// An anycast key announced from a fenced and a healthy nexthop keeps being advertised on the healthy
// one alone; the fence does not take the healthy origin's route down with it.
func TestRIB_Fence_MultiOriginKeepsHealthyNexthop(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeC"}
	r.Subscribe(100, sub)
	r.Announce("nodeA", 100, "0.0.0.0/0", []string{fencedNH}, true)
	r.Announce("nodeB", 100, "0.0.0.0/0", []string{healthyNH}, true)
	wantAdd(t, sub, "0.0.0.0/0", fencedNH, healthyNH)

	r.SetFence(fencedNet)
	wantAdd(t, sub, "0.0.0.0/0", healthyNH)
	if got := snapshotOf(r, 100)["0.0.0.0/0"]; !equalStrs(got, []string{healthyNH}) {
		t.Fatalf("the snapshot must carry only the healthy nexthop, got %v", got)
	}

	r.ClearFence(fencedNet)
	wantAdd(t, sub, "0.0.0.0/0", fencedNH, healthyNH)
	if got := snapshotOf(r, 100)["0.0.0.0/0"]; !equalStrs(got, []string{fencedNH, healthyNH}) {
		t.Fatalf("the snapshot must carry both nexthops again, got %v", got)
	}
}

// Failover: the lost pool (fenced) still holds the VM's /32 and the target pool announces the same
// /32 once the VM runs there. Only the target is advertised while the fence stands.
func TestRIB_Fence_FailoverTargetAdvertisedSourceHidden(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeC"}
	r.Subscribe(100, sub)
	r.Announce("source", 100, "10.0.0.5/32", []string{fencedNH}, false)
	r.SetFence(fencedNet)
	wantWithdraw(t, sub, "10.0.0.5/32")

	r.Announce("target", 100, "10.0.0.5/32", []string{healthyNH}, false)
	wantAdd(t, sub, "10.0.0.5/32", healthyNH)
	if got := snapshotOf(r, 100)["10.0.0.5/32"]; !equalStrs(got, []string{healthyNH}) {
		t.Fatalf("only the target may be advertised during the fence, got %v", got)
	}

	// The recovered source's agent withdraws the VM it no longer runs, then the fence is released:
	// the target alone stays advertised, and subscribers see no churn.
	n := len(updates(sub))
	r.Withdraw("source", 100, "10.0.0.5/32")
	r.ClearFence(fencedNet)
	if got := len(updates(sub)); got != n {
		t.Fatalf("want no fanout for the failed-over /32, got %+v", updates(sub)[n:])
	}
	if got := snapshotOf(r, 100)["10.0.0.5/32"]; !equalStrs(got, []string{healthyNH}) {
		t.Fatalf("want the target alone after the release, got %v", got)
	}
}

func TestRIB_Fence_IdempotentAndQuietWhenNothingChanges(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{fencedNH}, false)
	r.Announce("nodeB", 100, "10.0.0.6/32", []string{healthyNH}, false)
	n := len(updates(sub))

	r.SetFence(fencedNet)
	if got := len(updates(sub)); got != n+1 {
		t.Fatalf("want exactly one WITHDRAW for the fenced route, got %+v", updates(sub)[n:])
	}
	r.SetFence(fencedNet)
	if got := len(updates(sub)); got != n+1 {
		t.Fatalf("a repeated SetFence must not fan out, got %+v", updates(sub)[n+1:])
	}
	r.SetFence("2001:db8:0:9::/64") // covers no nexthop
	if got := len(updates(sub)); got != n+1 {
		t.Fatalf("a fence over no nexthop must not fan out, got %+v", updates(sub)[n+1:])
	}

	r.ClearFence(fencedNet)
	if got := len(updates(sub)); got != n+2 {
		t.Fatalf("want exactly one ADD for the released route, got %+v", updates(sub)[n+1:])
	}
	r.ClearFence(fencedNet)
	r.ClearFence("2001:db8:0:9::/64")
	if got := len(updates(sub)); got != n+2 {
		t.Fatalf("a repeated or empty ClearFence must not fan out, got %+v", updates(sub)[n+2:])
	}
}

// Two overlapping fences hide a nexthop until BOTH are released.
func TestRIB_Fence_OverlappingFencesReleaseTogether(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{fencedNH}, false)
	r.SetFence(fencedNet)
	r.SetFence("2001:db8::/48")
	n := len(updates(sub))

	r.ClearFence(fencedNet)
	if got := len(updates(sub)); got != n || r.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("the /48 fence still covers the nexthop: want it hidden and no fanout, got %+v", updates(sub)[n:])
	}
	r.ClearFence("2001:db8::/48")
	wantAdd(t, sub, "10.0.0.5/32", fencedNH)
}

// A fence is keyed by the network it covers, not by how the caller spelled it: a /64 set with a
// host part or leading zeros is released by its canonical spelling, and setting it twice under two
// spellings is still one fence.
func TestRIB_Fence_KeyIsTheNetworkNotItsSpelling(t *testing.T) {
	r := NewRIB()
	sub := &fakeSink{id: "nodeB"}
	r.Subscribe(100, sub)
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{fencedNH}, false)

	r.SetFence("2001:db8:0:1::a/64")
	r.SetFence("2001:0db8:0000:0001::/64")
	r.ClearFence(fencedNet)
	wantAdd(t, sub, "10.0.0.5/32", fencedNH)
	if !r.HasRoute(100, "10.0.0.5/32") {
		t.Fatal("clearing the /64 under its canonical spelling must release it however it was set")
	}
}

// updatesFor returns the RouteUpdates the sink saw for prefix.
func updatesFor(f *fakeSink, prefix string) []*pb.RouteUpdate {
	var out []*pb.RouteUpdate
	for _, u := range updates(f) {
		if u.Prefix == prefix {
			out = append(out, u)
		}
	}
	return out
}

// A fence is about how OTHER nodes reach a node's routes; the origin knows its own. It must not be
// sent its own key on a fence change: the agent installs any tenant-VNI ADD as a mesh route, and on
// its own guest's /32 that overwrites the key holding the guest's local self-route.
func TestRIB_Fence_OriginIsNotSentItsOwnKey(t *testing.T) {
	r := NewRIB()
	origin := &fakeSink{id: "nodeA"}
	other := &fakeSink{id: "nodeB"}
	r.Subscribe(100, origin)
	r.Subscribe(100, other)
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{fencedNH}, false)

	r.SetFence(fencedNet)
	if got := updatesFor(origin, "10.0.0.5/32"); len(got) != 0 {
		t.Fatalf("the origin must not be sent a WITHDRAW for its own key on SetFence, got %+v", got)
	}
	wantWithdraw(t, other, "10.0.0.5/32")

	r.ClearFence(fencedNet)
	if got := updatesFor(origin, "10.0.0.5/32"); len(got) != 0 {
		t.Fatalf("the origin must not be sent an ADD for its own key on ClearFence, got %+v", got)
	}
	wantAdd(t, other, "10.0.0.5/32", fencedNH)
}

// Every origin of a multi-origin key is spared the fence change, the healthy one included; the
// rest of the fabric sees the reduced set, then the restored one.
func TestRIB_Fence_NoOriginOfAMultiOriginKeyIsSentTheChange(t *testing.T) {
	r := NewRIB()
	fenced := &fakeSink{id: "nodeA"}
	healthy := &fakeSink{id: "nodeB"}
	other := &fakeSink{id: "nodeC"}
	for _, s := range []*fakeSink{fenced, healthy, other} {
		r.Subscribe(100, s)
	}
	r.Announce("nodeA", 100, "0.0.0.0/0", []string{fencedNH}, true)
	r.Announce("nodeB", 100, "0.0.0.0/0", []string{healthyNH}, true)
	nFenced, nHealthy := len(updatesFor(fenced, "0.0.0.0/0")), len(updatesFor(healthy, "0.0.0.0/0"))

	r.SetFence(fencedNet)
	wantAdd(t, other, "0.0.0.0/0", healthyNH)
	r.ClearFence(fencedNet)
	wantAdd(t, other, "0.0.0.0/0", fencedNH, healthyNH)

	if got := updatesFor(fenced, "0.0.0.0/0")[nFenced:]; len(got) != 0 {
		t.Fatalf("the fenced origin must not be sent the fence change for its key, got %+v", got)
	}
	if got := updatesFor(healthy, "0.0.0.0/0")[nHealthy:]; len(got) != 0 {
		t.Fatalf("the healthy origin must not be sent the fence change for its key, got %+v", got)
	}
}
