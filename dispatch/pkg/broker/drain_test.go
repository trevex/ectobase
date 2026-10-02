// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"testing"

	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

func TestDrainStatus_MarksEmptyNodesDrained(t *testing.T) {
	fenced := []string{"2001:db8:0:1::/64", "2001:db8:0:2::/64"}
	// Nodes still running a stale VMI keyed by /64. Node 1 is empty, node 2 still busy.
	busy := map[string]bool{"2001:db8:0:2::/64": true}
	got := DrainStatus(fenced, busy, false)
	m := map[string]bool{}
	for _, d := range got {
		m[d.Prefix] = d.Drained
	}
	if !m["2001:db8:0:1::/64"] {
		t.Fatalf("empty /64 must be drained")
	}
	if m["2001:db8:0:2::/64"] {
		t.Fatalf("busy /64 must NOT be drained")
	}
	_ = platformv1.NodeDrainStatus{}
}

func drainMap(fenced []string, busy map[string]bool, unplaced bool) map[string]bool {
	m := map[string]bool{}
	for _, d := range DrainStatus(fenced, busy, unplaced) {
		m[d.Prefix] = d.Drained
	}
	return m
}

// A pool that declares spec.underlayPrefix is fenced as ONE aggregate, while busy is keyed by the
// node /64s VMs run on. The aggregate never equals a /64, so it must be busy by containment: any
// busy /64 inside it holds it, in either family.
func TestDrainStatus_AggregateIsBusyWhenAnyNodeInsideIs(t *testing.T) {
	for name, tc := range map[string]struct {
		aggregate, busy string
		drained         bool
	}{
		"v6 busy /64 inside":      {"2001:db8::/48", "2001:db8:0:7::/64", false},
		"v6 busy /64 outside":     {"2001:db8::/48", "2001:db9:0:7::/64", true},
		"v6 spelled differently":  {"2001:0db8::/48", "2001:db8:0:7::/64", false},
		"v4 busy /24 inside":      {"10.20.0.0/16", "10.20.3.0/24", false},
		"v4 busy /24 outside":     {"10.20.0.0/16", "10.21.3.0/24", true},
		"other family never hits": {"2001:db8::/48", "10.20.3.0/24", true},
	} {
		t.Run(name, func(t *testing.T) {
			got := drainMap([]string{tc.aggregate}, map[string]bool{tc.busy: true}, false)
			if got[tc.aggregate] != tc.drained {
				t.Fatalf("aggregate %s with %s busy: drained=%v, want %v", tc.aggregate, tc.busy, got[tc.aggregate], tc.drained)
			}
		})
	}
}

// The /64-per-node case is unchanged: a busy /64 holds the fenced /64 it equals, and only that one.
func TestDrainStatus_EqualPrefixUnchanged(t *testing.T) {
	got := drainMap([]string{"2001:db8:0:1::/64"}, map[string]bool{"2001:db8:0:1::/64": true}, false)
	if got["2001:db8:0:1::/64"] {
		t.Fatal("a busy /64 equal to the fenced prefix must not be drained")
	}
	if got := drainMap([]string{"2001:db8:0:2::/64"}, map[string]bool{"2001:db8:0:1::/64": true}, false); !got["2001:db8:0:2::/64"] {
		t.Fatal("a busy /64 must not hold a different fenced /64")
	}
	// A busy prefix WIDER than the fenced one overlaps it, so it holds it too (fail closed).
	if got := drainMap([]string{"2001:db8:0:1::/64"}, map[string]bool{"2001:db8::/48": true}, false); got["2001:db8:0:1::/64"] {
		t.Fatal("a busy prefix covering the fenced one must hold it")
	}
	// An unparseable busy key can still match by equality.
	got = drainMap([]string{"not-a-prefix"}, map[string]bool{"not-a-prefix": true}, false)
	if got["not-a-prefix"] {
		t.Fatal("equality must hold even for a key that does not parse")
	}
}

// A VM on a node whose /64 is unknown (no agent annotation yet) may be inside ANY fenced prefix,
// the aggregate above all, so it holds every one.
func TestDrainStatus_UnplacedVMHoldsEveryFence(t *testing.T) {
	got := drainMap([]string{"2001:db8::/48", "2001:db8:0:1::/64"}, nil, true)
	for p, drained := range got {
		if drained {
			t.Fatalf("%s drained while a VM runs on a node with no known prefix", p)
		}
	}
}
