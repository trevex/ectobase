// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import "testing"

func TestClusterPoolStatus_FenceFields(t *testing.T) {
	s := ClusterPoolStatus{
		NodePrefixes:   []string{"2001:db8:0:1::/64"},
		FencedPrefixes: []string{"2001:db8:0:1::/64"},
		NodeDrain:      []NodeDrainStatus{{Prefix: "2001:db8:0:1::/64", Drained: true}},
	}
	if s.NodePrefixes[0] != "2001:db8:0:1::/64" || !s.NodeDrain[0].Drained {
		t.Fatalf("fence fields not wired: %+v", s)
	}
}
