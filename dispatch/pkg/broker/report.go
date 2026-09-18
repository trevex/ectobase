// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// NodeFact is a node's fence-relevant identity: its name and its /64 underlay prefix.
type NodeFact struct {
	Name   string
	Prefix string
}

// NodePrefixesFromNodes returns the DISTINCT /64 underlay prefixes of the given nodes (skipping
// nodes with no assigned prefix), in first-seen order. This is the pool fence coordinate the broker
// stamps into ClusterPool.Status.NodePrefixes.
//
// Deduplicated because it is semantically a SET of fence coordinates, not a per-node list: every
// node stamps its own underlay masked to a /64, so in the usual single-/64-per-cluster topology all
// of them report the same prefix and the raw list is that one coordinate repeated once per node.
// Central reads "how many distinct coordinates" to decide whether its fence coverage is provably
// complete (see failover.fenceCoverage), so the duplicates were actively misleading there as well
// as noise in the status.
func NodePrefixesFromNodes(nodes []NodeFact) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range nodes {
		if n.Prefix == "" || seen[n.Prefix] {
			continue
		}
		seen[n.Prefix] = true
		out = append(out, n.Prefix)
	}
	return out
}

// PlacementForVM builds a VMPlacement for a VM running on nodeName in pool, resolving
// the node's /64 from nodes. Returns nil if the node is unknown (nothing to report yet).
func PlacementForVM(pool, nodeName string, nodes []NodeFact) *computev1.VMPlacement {
	for _, n := range nodes {
		if n.Name == nodeName {
			return &computev1.VMPlacement{ClusterName: pool, NodeName: nodeName, NodePrefix: n.Prefix}
		}
	}
	return nil
}

// DrainStatus computes per-/64 drain confirmation for the fenced prefixes: a /64 is
// Drained unless it still hosts a stale VMI (busy[prefix]==true). The broker reports
// this upward after GC-reconciling the rebound CompiledVMs; central releases a fence
// only for Drained /64s.
func DrainStatus(fenced []string, busy map[string]bool) []platformv1.NodeDrainStatus {
	out := make([]platformv1.NodeDrainStatus, 0, len(fenced))
	for _, p := range fenced {
		out = append(out, platformv1.NodeDrainStatus{Prefix: p, Drained: !busy[p]})
	}
	return out
}
