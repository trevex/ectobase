// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package failover

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// A pool's status.fencedPrefixes and status.nodeDrain are written by its own broker. Whose fence a
// prefix is comes only from the dispatch's record (the NetworkFence label), so a compromised pool
// cannot have another pool's fence lifted by listing it as its own and drained.

const otherNet = "2001:db9::/48" // pool B's fence

// drainedReporting is reachable pool A whose status lists prefixes as fenced and drained.
func drainedReporting(prefixes ...string) *platformv1.ClusterPool {
	pool := readyPoolObj("A")
	pool.Status.FencedPrefixes = prefixes
	for _, p := range prefixes {
		pool.Status.NodeDrain = append(pool.Status.NodeDrain, platformv1.NodeDrainStatus{Prefix: p, Drained: true})
	}
	return pool
}

func reconcileOwners(t *testing.T, pool *platformv1.ClusterPool, storage *fenceRecord, network PrefixFencer) *platformv1.ClusterPool {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(pool, readyPoolObj("B")).WithStatusSubresource(pool).Build()
	r := &Reconciler{Client: c, StorageFencer: storage, NetworkFencer: network, Routes: &fakeRoutes{}, FailoverThreshold: time.Minute}
	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &platformv1.ClusterPool{}
	_ = c.Get(context.Background(), key("A"), got)
	return got
}

func TestReleaseDrained_AnotherPoolsFenceIsNeverReleased(t *testing.T) {
	storageCalls, network := &releaseCountingFencer{}, &releaseCountingFencer{}
	storage := asStorage(storageCalls, "A", sourceNet)
	storage.owner[otherNet] = "B"
	got := reconcileOwners(t, drainedReporting(sourceNet, otherNet), storage, network)

	for _, released := range [][]string{storageCalls.released, network.released} {
		if slices.Contains(released, otherNet) {
			t.Fatalf("pool B's fence was released on pool A's report: %v", released)
		}
	}
	if storage.owner[otherNet] != "B" {
		t.Fatalf("pool B's fence record was touched: %v", storage.owner)
	}
	// Its own drained fence is released as usual, at both backends.
	if !slices.Contains(storageCalls.released, sourceNet) || !slices.Contains(network.released, sourceNet) {
		t.Fatalf("pool A's own drained fence must still be released; storage=%v network=%v", storageCalls.released, network.released)
	}
	if len(got.Status.FencedPrefixes) != 0 {
		t.Fatalf("both entries must leave A's status (one released, one not A's), got %v", got.Status.FencedPrefixes)
	}
}

// A fence with no record of its pool (a NetworkFence without the label) is no pool's to release.
func TestReleaseDrained_AnUnrecordedFenceIsNotReleased(t *testing.T) {
	storageCalls, network := &releaseCountingFencer{}, &releaseCountingFencer{}
	storage := asStorage(storageCalls, "A")
	storage.owner[sourceNet] = ""
	got := reconcileOwners(t, drainedReporting(sourceNet), storage, network)
	if len(storageCalls.released)+len(network.released) != 0 {
		t.Fatalf("an unlabelled fence was released; storage=%v network=%v", storageCalls.released, network.released)
	}
	if _, ok := storage.owner[sourceNet]; !ok {
		t.Fatal("the unlabelled fence was removed")
	}
	if len(got.Status.FencedPrefixes) != 0 {
		t.Fatalf("the entry must be dropped from status, got %v", got.Status.FencedPrefixes)
	}
}

// When the record cannot be read, nothing is released and nothing is forgotten.
func TestReleaseDrained_AnUnreadableRecordHoldsTheFence(t *testing.T) {
	storageCalls, network := &releaseCountingFencer{}, &releaseCountingFencer{}
	storage := &unreadableRecord{fenceRecord: asStorage(storageCalls, "A", sourceNet)}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(drainedReporting(sourceNet), readyPoolObj("B")).
		WithStatusSubresource(&platformv1.ClusterPool{}).Build()
	r := &Reconciler{Client: c, StorageFencer: storage, NetworkFencer: network, Routes: &fakeRoutes{}, FailoverThreshold: time.Minute}
	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &platformv1.ClusterPool{}
	_ = c.Get(context.Background(), key("A"), got)
	if len(storageCalls.released)+len(network.released) != 0 || !stillFenced(got) {
		t.Fatalf("an unverifiable fence must be held and kept; released storage=%v network=%v fenced=%v",
			storageCalls.released, network.released, got.Status.FencedPrefixes)
	}
}

type unreadableRecord struct{ *fenceRecord }

func (unreadableRecord) FencedFor(context.Context, string) (string, bool, error) {
	return "", false, errors.New("apiserver unavailable")
}

// The operator moved spec.underlayPrefix while the old prefix was fenced: that fence is still
// recorded for this pool, and it is released as before.
func TestReleaseDrained_ReleasesTheOldPrefixAfterAnUnderlayPrefixChange(t *testing.T) {
	storageCalls, network := &releaseCountingFencer{}, &releaseCountingFencer{}
	pool := drainedReporting(sourceNet)
	pool.Spec.UnderlayPrefix = "2001:db8:1::/48" // changed after sourceNet was fenced
	got := reconcileOwners(t, pool, asStorage(storageCalls, "A", sourceNet), network)
	if !slices.Contains(storageCalls.released, sourceNet) || !slices.Contains(network.released, sourceNet) || stillFenced(got) {
		t.Fatalf("the old prefix's fence must be released; storage=%v network=%v fenced=%v",
			storageCalls.released, network.released, got.Status.FencedPrefixes)
	}
}

// The reflector fence goes first and the storage fence, which holds the record, last: a storage
// release still in flight keeps the entry and the record for the next pass.
func TestReleaseDrained_TheRecordOutlivesTheReflectorFence(t *testing.T) {
	network := &releaseCountingFencer{}
	storage := asStorage(releaseErrFencer{}, "A", sourceNet)
	got := reconcileOwners(t, drainedReporting(sourceNet), storage, network)
	if !slices.Contains(network.released, sourceNet) {
		t.Fatalf("the reflector fence must be lifted first, got %v", network.released)
	}
	if storage.owner[sourceNet] != "A" || !stillFenced(got) {
		t.Fatalf("with the storage release unconfirmed, the record and the entry must stay; owner=%v fenced=%v",
			storage.owner, got.Status.FencedPrefixes)
	}
}
