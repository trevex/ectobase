// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import netv1 "github.com/trevex/ectobase/api/v1alpha1"

// NodeFact is a node's fence-relevant identity: its name and its /64 underlay prefix.
type NodeFact struct {
	Name   string
	Prefix string
}

// NodePrefixesFromNodes returns the /64 underlay prefixes of the given nodes (skipping
// nodes with no assigned prefix), preserving order. This is the pool fence coordinate
// the broker stamps into ClusterPool.Status.NodePrefixes.
func NodePrefixesFromNodes(nodes []NodeFact) []string {
	var out []string
	for _, n := range nodes {
		if n.Prefix == "" {
			continue
		}
		out = append(out, n.Prefix)
	}
	return out
}

// PlacementForVM builds a VMPlacement for a VM running on nodeName in pool, resolving
// the node's /64 from nodes. Returns nil if the node is unknown (nothing to report yet).
func PlacementForVM(pool, nodeName string, nodes []NodeFact) *netv1.VMPlacement {
	for _, n := range nodes {
		if n.Name == nodeName {
			return &netv1.VMPlacement{ClusterName: pool, NodeName: nodeName, NodePrefix: n.Prefix}
		}
	}
	return nil
}
