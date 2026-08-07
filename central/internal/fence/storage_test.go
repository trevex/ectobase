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

func fenceCR(name, state, result string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: NetworkFenceGVR.Group, Version: NetworkFenceGVR.Version, Kind: "NetworkFence"})
	u.SetName(name)
	_ = unstructured.SetNestedField(u.Object, state, "spec", "fenceState")
	if result != "" {
		_ = unstructured.SetNestedField(u.Object, result, "status", "result")
	}
	return u
}

// Release must NOT delete a Fenced CR outright (that leaves the ceph blocklist): it
// transitions Fenced->Unfenced (so csi-addons un-blocklists) and returns an error to
// await confirmation. The CR must survive, now Unfenced.
func TestStorageFencer_ReleaseTransitionsToUnfenced(t *testing.T) {
	const name = "ectobase-2001-db8-0-1----64"
	cur := fenceCR(name, "Fenced", "Succeeded")
	c := fake.NewClientBuilder().WithObjects(cur).Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})

	if err := f.Release(context.Background(), "2001:db8:0:1::/64"); err == nil {
		t.Fatalf("Release must error while the Unfenced transition is in flight")
	}
	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(cur.GroupVersionKind())
	if err := c.Get(context.Background(), client.ObjectKey{Name: name}, got); err != nil {
		t.Fatalf("CR must survive the transition (not be deleted): %v", err)
	}
	if s, _, _ := unstructured.NestedString(got.Object, "spec", "fenceState"); s != "Unfenced" {
		t.Fatalf("fenceState=%q, want Unfenced (so csi-addons runs blocklist rm)", s)
	}
}

// Once the CR is observed Unfenced AND reports Succeeded (csi-addons ran blocklist rm),
// Release deletes it and returns nil.
func TestStorageFencer_ReleaseDeletesAfterUnfenced(t *testing.T) {
	const name = "ectobase-2001-db8-0-1----64"
	cur := fenceCR(name, "Unfenced", "Succeeded")
	c := fake.NewClientBuilder().WithObjects(cur).Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})

	if err := f.Release(context.Background(), "2001:db8:0:1::/64"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(cur.GroupVersionKind())
	if err := c.Get(context.Background(), client.ObjectKey{Name: name}, got); err == nil {
		t.Fatalf("CR must be deleted after a confirmed un-fence")
	}
}

// A missing CR means the fence is already released.
func TestStorageFencer_ReleaseMissingIsNil(t *testing.T) {
	c := fake.NewClientBuilder().Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
	if err := f.Release(context.Background(), "2001:db8:0:1::/64"); err != nil {
		t.Fatalf("Release of a missing NetworkFence must be nil, got %v", err)
	}
}
