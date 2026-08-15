// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
)

// underlayPrefix returns the /64 network of a node's underlay IPv6 address (the Tier-2
// fence coordinate), or "" if the input is not a genuine IPv6 address (a v4 or v4-mapped
// hostIP, or garbage) — such a node is simply not fence-eligible.
func underlayPrefix(underlay string) string {
	addr, err := netip.ParseAddr(underlay)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return ""
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

// StampNodePrefix stamps this node's /64 underlay prefix (NodeUnderlayPrefixAnnotation)
// onto its own Node so the Tier-2 broker reads the correct fence coordinate. Best-effort
// and idempotent: a non-IPv6 underlay is skipped (nil), an already-correct annotation is a
// no-op, and a not-yet-registered Node returns an error the caller logs and retries next tick.
func (r *Reconciler) StampNodePrefix(ctx context.Context) error {
	prefix := underlayPrefix(r.underlay)
	if prefix == "" {
		return nil // not a v6 underlay -> not fence-eligible
	}
	var node corev1.Node
	if err := r.client.Get(ctx, client.ObjectKey{Name: r.nodeID}, &node); err != nil {
		return fmt.Errorf("get node %s: %w", r.nodeID, err)
	}
	if node.Annotations[netv1.NodeUnderlayPrefixAnnotation] == prefix {
		return nil // already stamped
	}
	patch := client.MergeFrom(node.DeepCopy())
	if node.Annotations == nil {
		node.Annotations = map[string]string{}
	}
	node.Annotations[netv1.NodeUnderlayPrefixAnnotation] = prefix
	return r.client.Patch(ctx, &node, patch)
}
