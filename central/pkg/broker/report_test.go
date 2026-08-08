// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import "testing"

func TestNodePrefixesFromNodes(t *testing.T) {
	nodes := []NodeFact{
		{Name: "n1", Prefix: "2001:db8:0:1::/64"},
		{Name: "n2", Prefix: "2001:db8:0:2::/64"},
		{Name: "n3", Prefix: ""}, // no prefix yet -> skipped
	}
	got := NodePrefixesFromNodes(nodes)
	if len(got) != 2 || got[0] != "2001:db8:0:1::/64" || got[1] != "2001:db8:0:2::/64" {
		t.Fatalf("unexpected prefixes: %v", got)
	}
}

func TestPlacementForVM(t *testing.T) {
	nodes := []NodeFact{{Name: "n1", Prefix: "2001:db8:0:1::/64"}}
	pl := PlacementForVM("poolA", "n1", nodes)
	if pl == nil || pl.NodePrefix != "2001:db8:0:1::/64" || pl.ClusterName != "poolA" {
		t.Fatalf("unexpected placement: %+v", pl)
	}
	if PlacementForVM("poolA", "unknown", nodes) != nil {
		t.Fatalf("unknown node must yield nil placement")
	}
}
