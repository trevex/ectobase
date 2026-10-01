// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package fence

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// A Fenced NetworkFence whose fence op csi-addons reports Succeeded confirms active.
func TestStorageFencer_FenceCreatesAndConfirms(t *testing.T) {
	existing := fenceCR("ectobase-2001-db8-0-1----64", "Fenced", "Succeeded")
	_ = unstructured.SetNestedField(existing.Object, fenceSucceededMsg, "status", "message")

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

// fencedCR is what csi-addons leaves after a successful fence op.
func fencedCR(name string) *unstructured.Unstructured {
	u := fenceCR(name, "Fenced", "Succeeded")
	_ = unstructured.SetNestedField(u.Object, fenceSucceededMsg, "status", "message")
	return u
}

func getCR(t *testing.T, c client.Client, name string) (*unstructured.Unstructured, bool) {
	t.Helper()
	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(schema.GroupVersionKind{Group: NetworkFenceGVR.Group, Version: NetworkFenceGVR.Version, Kind: "NetworkFence"})
	if err := c.Get(context.Background(), client.ObjectKey{Name: name}, got); err != nil {
		return nil, false
	}
	return got, true
}

// A release in flight leaves the CR Unfenced, its status reporting the UNFENCE op Succeeded. If the
// pool is lost again before the release finishes, the next Fence must not take that status as
// proof of a fence: it would let failover rebind the pool's VMs while csi-addons is running
// `ceph osd blocklist rm` for the nodes still holding them. Fence replaces the CR instead, so the
// only Succeeded it can see is one csi-addons wrote for the new Fenced op.
func TestStorageFencer_FenceOnAnUnfencedCRRefencesBeforeConfirming(t *testing.T) {
	const name, prefix = "ectobase-2001-db8-0-1----64", "2001:db8:0:1::/64"
	unfenced := fenceCR(name, "Unfenced", "Succeeded")
	_ = unstructured.SetNestedField(unfenced.Object, "unfencing operation successful", "status", "message")
	c := fake.NewClientBuilder().WithObjects(unfenced).Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})

	if err := f.Fence(context.Background(), prefix); err == nil {
		t.Fatal("an Unfenced CR's Succeeded is the unfence op's: Fence must not confirm on it")
	}
	if err := f.Fence(context.Background(), prefix); err == nil {
		t.Fatal("the replacement Fenced CR has no result yet: Fence must not confirm")
	}
	cur, ok := getCR(t, c, name)
	if !ok {
		t.Fatal("Fence must leave a Fenced CR in place")
	}
	if s, _, _ := unstructured.NestedString(cur.Object, "spec", "fenceState"); s != "Fenced" {
		t.Fatalf("fenceState=%q, want Fenced", s)
	}
	if r, _, _ := unstructured.NestedString(cur.Object, "status", "result"); r != "" {
		t.Fatalf("the replacement must start with no result, got %q", r)
	}

	// csi-addons runs the fence op and reports it.
	_ = unstructured.SetNestedField(cur.Object, "Succeeded", "status", "result")
	_ = unstructured.SetNestedField(cur.Object, fenceSucceededMsg, "status", "message")
	if err := c.Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	if err := f.Fence(context.Background(), prefix); err != nil {
		t.Fatalf("a fresh Succeeded for the fence op confirms: %v", err)
	}
}

// Even on a Fenced CR, a result that reports the unfence op is not a fence.
func TestStorageFencer_FenceIgnoresAnUnfenceResult(t *testing.T) {
	const name = "ectobase-2001-db8-0-1----64"
	cr := fenceCR(name, "Fenced", "Succeeded")
	_ = unstructured.SetNestedField(cr.Object, "unfencing operation successful", "status", "message")
	c := fake.NewClientBuilder().WithObjects(cr).Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
	if err := f.Fence(context.Background(), "2001:db8:0:1::/64"); err == nil {
		t.Fatal("a Succeeded for the unfence op must not confirm a fence")
	}
}

// A CR on its way out is no fence, whatever its status says.
func TestStorageFencer_FenceOnADeletingCRWaits(t *testing.T) {
	const name = "ectobase-2001-db8-0-1----64"
	cr := fencedCR(name)
	now := metav1.Now()
	cr.SetDeletionTimestamp(&now)
	cr.SetFinalizers([]string{"csiaddons.openshift.io/network-fence"})
	c := fake.NewClientBuilder().WithObjects(cr).Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
	if err := f.Fence(context.Background(), "2001:db8:0:1::/64"); err == nil {
		t.Fatal("a NetworkFence being deleted must not confirm a fence")
	}
}
