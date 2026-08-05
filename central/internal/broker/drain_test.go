// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"testing"

	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

func TestDrainStatus_MarksEmptyNodesDrained(t *testing.T) {
	fenced := []string{"2001:db8:0:1::/64", "2001:db8:0:2::/64"}
	// Nodes still running a stale VMI keyed by /64. Node 1 is empty, node 2 still busy.
	busy := map[string]bool{"2001:db8:0:2::/64": true}
	got := DrainStatus(fenced, busy)
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
