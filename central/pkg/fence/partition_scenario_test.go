// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package fence

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/trevex/ectobase/netplane/reflector"
)

// A partitioned pool's node keeps a live route + holds the RBD; central fences the
// whole /64. Assert BOTH cuts land: the route is suppressed AND storage confirms fenced.
func TestPartition_WholePoolFence_CutsBothBackends(t *testing.T) {
	const prefix = "2001:db8:0:1::/64"

	// Network: the partitioned node re-announced a sticky route (local Tier-1). Fence it.
	rib := reflector.NewRIB()
	rib.Announce("stale-node", 100, "10.0.0.9/32", []string{"2001:db8:0:1::9"}, false)
	rib.SetFence(prefix)
	if rib.HasRoute(100, "10.0.0.9/32") {
		t.Fatalf("network fence must suppress the partitioned node's route")
	}
	// A further re-announce from the fenced /64 is rejected (no dual-IP).
	rib.Announce("stale-node", 100, "10.0.0.9/32", []string{"2001:db8:0:1::9"}, false)
	if rib.HasRoute(100, "10.0.0.9/32") {
		t.Fatalf("network fence must reject re-announces from the fenced /64")
	}

	// Storage: the NetworkFence CR reports Succeeded -> storage cut confirmed.
	nf := &unstructured.Unstructured{}
	nf.SetGroupVersionKind(schema.GroupVersionKind{Group: NetworkFenceGVR.Group, Version: NetworkFenceGVR.Version, Kind: "NetworkFence"})
	nf.SetName(fenceName(prefix))
	_ = unstructured.SetNestedField(nf.Object, "Succeeded", "status", "result")
	c := fake.NewClientBuilder().WithObjects(nf).Build()
	sf := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "s", Namespace: "ceph"})
	if err := sf.Fence(context.Background(), prefix); err != nil {
		t.Fatalf("storage fence must confirm active: %v", err)
	}
}
