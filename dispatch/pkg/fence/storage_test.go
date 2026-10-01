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

	if err := f.Fence(context.Background(), testPool, "2001:db8:0:1::/64"); err != nil {
		t.Fatalf("Fence: %v", err)
	}
}

func TestStorageFencer_FencePendingReturnsError(t *testing.T) {
	c := fake.NewClientBuilder().Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
	// No CR yet: Fence creates it, but status isn't Succeeded -> not active -> error (fail-safe).
	if err := f.Fence(context.Background(), testPool, "2001:db8:0:1::/64"); err == nil {
		t.Fatalf("Fence must error until the NetworkFence reports Succeeded")
	}
}

// testPool is the pool the CRs in these tests were fenced for.
const testPool = "k02"

// fenceCR is a NetworkFence the dispatch fenced for testPool.
func fenceCR(name, state, result string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: NetworkFenceGVR.Group, Version: NetworkFenceGVR.Version, Kind: "NetworkFence"})
	u.SetName(name)
	u.SetLabels(map[string]string{FencedForPoolLabel: testPool})
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

	if err := f.Release(context.Background(), testPool, "2001:db8:0:1::/64"); err == nil {
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

// Once the CR is observed Unfenced AND csi-addons reports the UNFENCE op Succeeded (it ran
// blocklist rm), Release deletes it and returns nil.
func TestStorageFencer_ReleaseDeletesAfterUnfenced(t *testing.T) {
	const name = "ectobase-2001-db8-0-1----64"
	cur := unfencedCR(name)
	c := fake.NewClientBuilder().WithObjects(cur).Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})

	if err := f.Release(context.Background(), testPool, "2001:db8:0:1::/64"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, ok := getCR(t, c, name); ok {
		t.Fatalf("CR must be deleted after a confirmed un-fence")
	}
}

// Right after Release flips a CR to Unfenced its status still reports the FENCE op Succeeded.
// A pass that lands before csi-addons runs the unfence must not delete the CR: csi-addons'
// delete only drops its finalizer, so the unfence would never run and the multi-year blocklist
// entry would be stranded with nothing left tracking it.
func TestStorageFencer_ReleaseKeepsAnUnfencedCRUntilTheUnfenceIsReported(t *testing.T) {
	const name = "ectobase-2001-db8-0-1----64"
	for what, cr := range map[string]*unstructured.Unstructured{
		"fence op's result still standing": func() *unstructured.Unstructured {
			u := fenceCR(name, "Unfenced", "Succeeded")
			_ = unstructured.SetNestedField(u.Object, fenceSucceededMsg, "status", "message")
			return u
		}(),
		"no message": fenceCR(name, "Unfenced", "Succeeded"),
		"unfence failed": func() *unstructured.Unstructured {
			u := fenceCR(name, "Unfenced", "Failed")
			_ = unstructured.SetNestedField(u.Object, "rpc error", "status", "message")
			return u
		}(),
	} {
		t.Run(what, func(t *testing.T) {
			c := fake.NewClientBuilder().WithObjects(cr).Build()
			f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
			if err := f.Release(context.Background(), testPool, "2001:db8:0:1::/64"); err == nil {
				t.Fatal("Release must not report released before the unfence op is reported")
			}
			if _, ok := getCR(t, c, name); !ok {
				t.Fatal("the CR must survive until its unfence is reported")
			}
		})
	}
}

// The status messages are csi-addons' exported FenceOperationSuccessfulMessage and
// UnFenceOperationSuccessfulMessage (v0.9.0+). They are the only thing telling the two ops apart,
// so a change upstream must fail here, not in a fence that confirms the wrong op.
func TestCSIAddonsOperationMessagesArePinned(t *testing.T) {
	if fenceSucceededMsg != "fencing operation successful" {
		t.Fatalf("fence message drifted: %q", fenceSucceededMsg)
	}
	if unfenceSucceededMsg != "unfencing operation successful" {
		t.Fatalf("unfence message drifted: %q", unfenceSucceededMsg)
	}
}

// A missing CR means the fence is already released.
func TestStorageFencer_ReleaseMissingIsNil(t *testing.T) {
	c := fake.NewClientBuilder().Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
	if err := f.Release(context.Background(), testPool, "2001:db8:0:1::/64"); err != nil {
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

// unfencedCR is what csi-addons leaves after a successful unfence op.
func unfencedCR(name string) *unstructured.Unstructured {
	u := fenceCR(name, "Unfenced", "Succeeded")
	_ = unstructured.SetNestedField(u.Object, unfenceSucceededMsg, "status", "message")
	return u
}

// A release in flight leaves the CR Unfenced. If the pool is lost again before that release
// finishes, Fence must re-fence — but deleting the CR before its unfence ran would strand the
// blocklist entry (csi-addons' delete only drops its finalizer, and a later Release would find
// nothing and call it released), and flipping it back in place would let the fence op's old
// Succeeded confirm a fence that is being removed. So Fence waits, touching nothing, until the
// unfence is reported; the barrier stays blocked meanwhile.
func TestStorageFencer_FenceOnAnUnfencedCRWaitsForTheUnfence(t *testing.T) {
	const name, prefix = "ectobase-2001-db8-0-1----64", "2001:db8:0:1::/64"
	for what, cr := range map[string]*unstructured.Unstructured{
		"no result yet": fenceCR(name, "Unfenced", ""),
		"fence op's result still standing": func() *unstructured.Unstructured {
			u := fenceCR(name, "Unfenced", "Succeeded")
			_ = unstructured.SetNestedField(u.Object, fenceSucceededMsg, "status", "message")
			return u
		}(),
	} {
		t.Run(what, func(t *testing.T) {
			c := fake.NewClientBuilder().WithObjects(cr).Build()
			before, _ := getCR(t, c, name)
			f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
			if err := f.Fence(context.Background(), testPool, prefix); err == nil {
				t.Fatal("Fence must not confirm on a CR whose unfence has not been reported")
			}
			after, ok := getCR(t, c, name)
			if !ok {
				t.Fatal("Fence must not delete a CR whose unfence has not been reported")
			}
			if after.GetResourceVersion() != before.GetResourceVersion() {
				t.Fatal("Fence must not patch a CR whose unfence has not been reported")
			}
		})
	}
}

// Once the unfence is reported, the old CR is spent: Fence deletes it and creates a fresh Fenced
// one, whose only possible Succeeded is a fence op's.
func TestStorageFencer_FenceReplacesAnUnfencedCROnceTheUnfenceIsReported(t *testing.T) {
	const name, prefix = "ectobase-2001-db8-0-1----64", "2001:db8:0:1::/64"
	c := fake.NewClientBuilder().WithObjects(unfencedCR(name)).Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})

	if err := f.Fence(context.Background(), testPool, prefix); err == nil {
		t.Fatal("an Unfenced CR's Succeeded is the unfence op's: Fence must not confirm on it")
	}
	if _, ok := getCR(t, c, name); ok {
		t.Fatal("a CR whose unfence is reported must be deleted to make way for a fresh fence")
	}
	if err := f.Fence(context.Background(), testPool, prefix); err == nil {
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
	if err := f.Fence(context.Background(), testPool, prefix); err != nil {
		t.Fatalf("a fresh Succeeded for the fence op confirms: %v", err)
	}
}

// Even on a Fenced CR, a result that reports the unfence op is not a fence.
func TestStorageFencer_FenceIgnoresAnUnfenceResult(t *testing.T) {
	const name = "ectobase-2001-db8-0-1----64"
	cr := fenceCR(name, "Fenced", "Succeeded")
	_ = unstructured.SetNestedField(cr.Object, unfenceSucceededMsg, "status", "message")
	c := fake.NewClientBuilder().WithObjects(cr).Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
	if err := f.Fence(context.Background(), testPool, "2001:db8:0:1::/64"); err == nil {
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
	if err := f.Fence(context.Background(), testPool, "2001:db8:0:1::/64"); err == nil {
		t.Fatal("a NetworkFence being deleted must not confirm a fence")
	}
}

func mustGetCR(t *testing.T, c client.Client, name string) *unstructured.Unstructured {
	t.Helper()
	u, ok := getCR(t, c, name)
	if !ok {
		t.Fatalf("NetworkFence %s is gone", name)
	}
	return u
}

// The fence records the pool it was set for, on the CR itself: the dispatch host cluster, which no
// broker can write.
func TestStorageFencer_FenceRecordsThePool(t *testing.T) {
	c := fake.NewClientBuilder().Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
	_ = f.Fence(context.Background(), "k03", "2001:db8:0:1::/64") // created, not yet confirmed
	if got := mustGetCR(t, c, "ectobase-2001-db8-0-1----64").GetLabels()[FencedForPoolLabel]; got != "k03" {
		t.Fatalf("%s = %q, want k03", FencedForPoolLabel, got)
	}
	if pool, found, err := f.FencedFor(context.Background(), "2001:db8:0:1::/64"); err != nil || !found || pool != "k03" {
		t.Fatalf("FencedFor = %q %v %v, want k03", pool, found, err)
	}
	if _, found, err := f.FencedFor(context.Background(), "2001:db8:0:9::/64"); err != nil || found {
		t.Fatalf("FencedFor of an absent fence = found %v, err %v", found, err)
	}
}

// A pool's status names the prefix to release and its broker writes that status. Release refuses,
// and leaves untouched, a CR held for another pool or carrying no label at all.
func TestStorageFencer_ReleaseRefusesAFenceThatIsNotThePools(t *testing.T) {
	const name = "ectobase-2001-db8-0-1----64"
	for owner, labels := range map[string]map[string]string{
		"another pool": {FencedForPoolLabel: "k03"},
		"no label":     nil,
	} {
		t.Run(owner, func(t *testing.T) {
			cr := fenceCR(name, "Fenced", "Succeeded")
			cr.SetLabels(labels)
			c := fake.NewClientBuilder().WithObjects(cr).Build()
			f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
			if err := f.Release(context.Background(), testPool, "2001:db8:0:1::/64"); err == nil {
				t.Fatal("released a fence that is not this pool's")
			}
			if s, _, _ := unstructured.NestedString(mustGetCR(t, c, name).Object, "spec", "fenceState"); s != "Fenced" {
				t.Fatalf("fenceState = %q, want it left Fenced", s)
			}
		})
	}
}

// Nor may one pool's Fence take over, or replace, a CR held for another.
func TestStorageFencer_FenceLeavesAnotherPoolsFenceAlone(t *testing.T) {
	const name = "ectobase-2001-db8-0-1----64"
	cr := unfencedCR(name) // spent, which Fence would otherwise delete and recreate
	cr.SetLabels(map[string]string{FencedForPoolLabel: "k03"})
	c := fake.NewClientBuilder().WithObjects(cr).Build()
	f := NewStorageFencer(c, "rbd.csi.ceph.com", "", client.ObjectKey{Name: "csi-rbd-secret", Namespace: "ceph"})
	if err := f.Fence(context.Background(), testPool, "2001:db8:0:1::/64"); err == nil {
		t.Fatal("fenced over another pool's NetworkFence")
	}
	if got := mustGetCR(t, c, name).GetLabels()[FencedForPoolLabel]; got != "k03" {
		t.Fatalf("the CR changed hands: %q", got)
	}
}
