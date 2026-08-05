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
)

// A NetworkFence whose status the fake pre-populates as Succeeded confirms active.
func TestStorageFencer_FenceCreatesAndConfirms(t *testing.T) {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(schema.GroupVersionKind{Group: NetworkFenceGVR.Group, Version: NetworkFenceGVR.Version, Kind: "NetworkFence"})
	existing.SetName("ectobase-2001-db8-0-1----64")
	_ = unstructured.SetNestedField(existing.Object, "Succeeded", "status", "result")

	c := fake.NewClientBuilder().WithObjects(existing).Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})

	if err := f.Fence(context.Background(), "2001:db8:0:1::/64"); err != nil {
		t.Fatalf("Fence: %v", err)
	}
}

func TestStorageFencer_FencePendingReturnsError(t *testing.T) {
	c := fake.NewClientBuilder().Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
	// No CR yet: Fence creates it, but status isn't Succeeded -> not active -> error (fail-safe).
	if err := f.Fence(context.Background(), "2001:db8:0:1::/64"); err == nil {
		t.Fatalf("Fence must error until the NetworkFence reports Succeeded")
	}
}
