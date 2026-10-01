// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"testing"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// AnnouncedFrom is what failover asks before it releases a fenced /64: of the addresses it moved
// off that pool, which does the pool still announce? It answers from what the RIB stores, so the
// fence that hides those routes must not hide them from the question too.

func key(vni uint32, prefix string) *pb.RouteKey { return &pb.RouteKey{Vni: vni, Prefix: prefix} }

func announcedFrom(t *testing.T, r *RIB, within string, keys ...*pb.RouteKey) map[string]bool {
	t.Helper()
	held, err := r.AnnouncedFrom(within, keys)
	if err != nil {
		t.Fatalf("AnnouncedFrom(%s): %v", within, err)
	}
	out := map[string]bool{}
	for _, k := range held {
		out[k.Prefix] = true
	}
	return out
}

func TestRIB_AnnouncedFrom_UnfencedAndFenced(t *testing.T) {
	r := NewRIB()
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{fencedNH}, false)
	r.Announce("nodeB", 100, "10.0.0.6/32", []string{healthyNH}, false)

	got := announcedFrom(t, r, fencedNet, key(100, "10.0.0.5/32"), key(100, "10.0.0.6/32"))
	if !got["10.0.0.5/32"] || got["10.0.0.6/32"] || len(got) != 1 {
		t.Fatalf("unfenced: want only 10.0.0.5/32 held inside %s, got %v", fencedNet, got)
	}

	// The fence hides the route from subscribers; the question is about what ClearFence would
	// bring back, so the answer must not change.
	r.SetFence(fencedNet)
	got = announcedFrom(t, r, fencedNet, key(100, "10.0.0.5/32"), key(100, "10.0.0.6/32"))
	if !got["10.0.0.5/32"] || len(got) != 1 {
		t.Fatalf("fenced: a hidden route is still stored and must be reported, got %v", got)
	}
}

// The failover case itself: the moved VM's /32 is announced by the stale source AND the pool it
// now runs on. Only the source's nexthop is inside the fenced /64, and that alone counts.
func TestRIB_AnnouncedFrom_MultiOrigin(t *testing.T) {
	r := NewRIB()
	r.SetFence(fencedNet)
	r.Announce("target", 100, "10.0.0.5/32", []string{healthyNH}, false)
	r.Announce("source", 100, "10.0.0.5/32", []string{fencedNH}, false)
	if got := announcedFrom(t, r, fencedNet, key(100, "10.0.0.5/32")); !got["10.0.0.5/32"] {
		t.Fatalf("a key the fenced source still announces must be reported despite another origin, got %v", got)
	}
	// Asked about the target's /64 instead, the same key is held from there too.
	if got := announcedFrom(t, r, "2001:db8:0:2::/64", key(100, "10.0.0.5/32")); !got["10.0.0.5/32"] {
		t.Fatalf("the target's own announcement must count inside its /64, got %v", got)
	}

	r.Withdraw("source", 100, "10.0.0.5/32")
	if got := announcedFrom(t, r, fencedNet, key(100, "10.0.0.5/32")); len(got) != 0 {
		t.Fatalf("after the source withdraws, only the target holds the key: want nothing inside %s, got %v", fencedNet, got)
	}
}

func TestRIB_AnnouncedFrom_AfterWithdrawAndSessionDrop(t *testing.T) {
	r := NewRIB()
	r.Announce("nodeA", 100, "10.0.0.5/32", []string{fencedNH}, false)
	r.Announce("nodeA", 100, "10.0.0.7/32", []string{fencedNH}, false)
	r.SetFence(fencedNet)

	r.Withdraw("nodeA", 100, "10.0.0.5/32")
	got := announcedFrom(t, r, fencedNet, key(100, "10.0.0.5/32"), key(100, "10.0.0.7/32"))
	if got["10.0.0.5/32"] || !got["10.0.0.7/32"] {
		t.Fatalf("a withdrawn key must not be reported, the other must; got %v", got)
	}

	// A session ending withdraws everything its node announced.
	r.dropOrigin("nodeA")
	if got := announcedFrom(t, r, fencedNet, key(100, "10.0.0.7/32")); len(got) != 0 {
		t.Fatalf("a dropped origin holds nothing, got %v", got)
	}
}

// A key is a (vni, prefix): the same address in another VPC is a different route, and an address
// that is not asked about is not reported however it is announced (a pool's LB anycast addresses).
func TestRIB_AnnouncedFrom_TargetedByVNIAndKey(t *testing.T) {
	r := NewRIB()
	r.Announce("nodeA", 200, "10.0.0.5/32", []string{fencedNH}, false)
	r.Announce("nodeA", 100, "10.9.9.9/32", []string{fencedNH}, false) // e.g. an E/W LB address
	got := announcedFrom(t, r, fencedNet, key(100, "10.0.0.5/32"))
	if len(got) != 0 {
		t.Fatalf("only the asked (vni, prefix) may be reported, got %v", got)
	}
}

// The agent builds its host prefix from the address string flowplane reports, which is canonical;
// the caller's comes from the IPAM's status and need not be. A spelling must not hide a held key.
func TestRIB_AnnouncedFrom_MatchesCanonicalSpelling(t *testing.T) {
	r := NewRIB()
	r.Announce("nodeA", 100, "fd00::5/128", []string{fencedNH}, false)
	held, err := r.AnnouncedFrom(fencedNet, []*pb.RouteKey{key(100, "fd00:0:0:0::5/128")})
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held[0].Prefix != "fd00:0:0:0::5/128" {
		t.Fatalf("want the key reported as asked, got %v", held)
	}
}

func TestRIB_AnnouncedFrom_RejectsInvalidPrefix(t *testing.T) {
	if _, err := NewRIB().AnnouncedFrom("not-a-cidr", nil); err == nil {
		t.Fatal("AnnouncedFrom must reject an invalid prefix")
	}
}
