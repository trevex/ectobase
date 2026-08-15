// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// NodeUnderlayPrefixAnnotation is set by the mesh agent on its own Node with that
// node's /64 underlay prefix — the Tier-2 fence coordinate (the CIDR the Ceph
// NetworkFence blocklists and whose nexthops the reflector route-fence suppresses).
// The broker reads it to populate ClusterPool.Status.NodePrefixes.
const NodeUnderlayPrefixAnnotation = "net.ectobase.dev/underlay-prefix"
