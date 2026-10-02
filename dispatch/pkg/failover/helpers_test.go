// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package failover

import (
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/dispatch/pkg/clusterpool"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := computev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := platformv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// readyPoolObj is a reachable pool: Ready, with a lease its broker just renewed.
func readyPoolObj(name string) *platformv1.ClusterPool {
	now := metav1.NewMicroTime(time.Now())
	return &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: platformv1.ClusterPoolStatus{
		Phase: clusterpool.PhaseReady,
		Lease: &platformv1.ClusterPoolLease{RenewTime: &now},
	}}
}

func req(name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}
}
func key(name string) client.ObjectKey { return types.NamespacedName{Name: name} }

// fenceRecord is the StorageFencer seam over a test PrefixFencer. It keeps the ownership record the
// real NetworkFence's fenced-for-pool label keeps: Fence records the pool, Release refuses a prefix
// recorded for another pool and forgets one it released, FencedFor reads the record.
type fenceRecord struct {
	PrefixFencer
	owner map[string]string
}

// asStorage wraps f, with held already fenced for pool (as an earlier pass would have).
func asStorage(f PrefixFencer, pool string, held ...string) *fenceRecord {
	r := &fenceRecord{PrefixFencer: f, owner: map[string]string{}}
	for _, p := range held {
		r.owner[p] = pool
	}
	return r
}

func (r *fenceRecord) Fence(ctx context.Context, pool, prefix string) error {
	if o, ok := r.owner[prefix]; ok && o != pool {
		return fmt.Errorf("fence on %s is held for pool %s", prefix, o)
	}
	r.owner[prefix] = pool
	return r.PrefixFencer.Fence(ctx, prefix)
}

func (r *fenceRecord) Release(ctx context.Context, pool, prefix string) error {
	o, ok := r.owner[prefix]
	if !ok {
		return nil
	}
	if o != pool {
		return fmt.Errorf("fence on %s is held for pool %s, not %s", prefix, o, pool)
	}
	if err := r.PrefixFencer.Release(ctx, prefix); err != nil {
		return err
	}
	delete(r.owner, prefix)
	return nil
}

func (r *fenceRecord) FencedFor(_ context.Context, prefix string) (string, bool, error) {
	o, ok := r.owner[prefix]
	return o, ok, nil
}
