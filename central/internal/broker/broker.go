// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

// Broker is the per-cluster set-reconcile engine: it makes the downstream set of
// CompiledNICs exactly match the central objects bound to ClusterName (spec.clusterName).
type Broker struct {
	Central     client.Client
	Downstream  client.Client
	ClusterName string
}

// key identifies a namespaced CompiledNIC as "namespace/name".
func key(o *netv1.CompiledNIC) string { return o.Namespace + "/" + o.Name }

// SyncOnce is a declarative set-reconcile: desired = central CompiledNICs with
// spec.clusterName==ClusterName; make downstream match (create/update/delete).
// Idempotent and restart-safe (no in-memory diff; derived from live sets each call).
func (b *Broker) SyncOnce(ctx context.Context) error {
	// Fetch desired set from central, filtered by clusterName field index.
	desired := &netv1.CompiledNICList{}
	if err := b.Central.List(ctx, desired, client.MatchingFields{"spec.clusterName": b.ClusterName}); err != nil {
		return fmt.Errorf("list central: %w", err)
	}
	want := make(map[string]netv1.CompiledNIC, len(desired.Items))
	for _, o := range desired.Items {
		want[key(&o)] = o
	}

	// Fetch current set from downstream.
	have := &netv1.CompiledNICList{}
	if err := b.Downstream.List(ctx, have); err != nil {
		return fmt.Errorf("list downstream: %w", err)
	}

	// Reconcile existing downstream objects: update drifted, delete extras.
	haveKeys := make(map[string]bool, len(have.Items))
	for i := range have.Items {
		cur := &have.Items[i]
		haveKeys[key(cur)] = true
		w, ok := want[key(cur)]
		if !ok {
			// Not in desired set — GC it.
			if err := b.Downstream.Delete(ctx, cur); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("gc %s: %w", key(cur), err)
			}
			continue
		}
		// In desired set — update if spec has drifted. Spec has slices, so use a
		// semantic deep-equal (NOT ==, which does not compile on struct-with-slice).
		if !equality.Semantic.DeepEqual(cur.Spec, w.Spec) {
			cur.Spec = w.Spec
			if err := b.Downstream.Update(ctx, cur); err != nil {
				return fmt.Errorf("update %s: %w", key(cur), err)
			}
		}
	}

	// Create objects present in desired but absent from downstream.
	for k, w := range want {
		if haveKeys[k] {
			continue
		}
		local := &netv1.CompiledNIC{}
		local.Namespace = w.Namespace
		local.Name = w.Name
		local.Spec = w.Spec
		if err := b.Downstream.Create(ctx, local); err != nil {
			return fmt.Errorf("create %s: %w", k, err)
		}
	}
	return nil
}
