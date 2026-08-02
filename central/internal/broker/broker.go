// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

// Broker is the per-cluster set-reconcile engine: it makes the downstream
// set of CompiledWorkloads exactly match the central objects bound to ClusterName.
type Broker struct {
	Central     client.Client
	Downstream  client.Client
	ClusterName string
}

// SyncOnce is a declarative set-reconcile: desired = central objects with
// spec.clusterName==ClusterName; make downstream match (create/update/delete).
// Idempotent and restart-safe (no in-memory diff; derived from live sets each call).
func (b *Broker) SyncOnce(ctx context.Context) error {
	// Fetch desired set from central, filtered by clusterName field index.
	desired := &v1alpha1.CompiledWorkloadList{}
	if err := b.Central.List(ctx, desired, client.MatchingFields{"spec.clusterName": b.ClusterName}); err != nil {
		return fmt.Errorf("list central: %w", err)
	}
	want := make(map[string]v1alpha1.CompiledWorkload, len(desired.Items))
	for _, o := range desired.Items {
		want[o.Name] = o
	}

	// Fetch current set from downstream.
	have := &v1alpha1.CompiledWorkloadList{}
	if err := b.Downstream.List(ctx, have); err != nil {
		return fmt.Errorf("list downstream: %w", err)
	}

	// Reconcile existing downstream objects: update drifted, delete extras.
	haveNames := make(map[string]bool, len(have.Items))
	for i := range have.Items {
		cur := &have.Items[i]
		haveNames[cur.Name] = true
		w, ok := want[cur.Name]
		if !ok {
			// Not in desired set — GC it.
			if err := b.Downstream.Delete(ctx, cur); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("gc %s: %w", cur.Name, err)
			}
			continue
		}
		// In desired set — update if spec has drifted.
		if cur.Spec != w.Spec {
			cur.Spec = w.Spec
			if err := b.Downstream.Update(ctx, cur); err != nil {
				return fmt.Errorf("update %s: %w", cur.Name, err)
			}
		}
	}

	// Create objects present in desired but absent from downstream.
	for name, w := range want {
		if haveNames[name] {
			continue
		}
		local := &v1alpha1.CompiledWorkload{}
		local.Name = name
		local.Spec = w.Spec
		if err := b.Downstream.Create(ctx, local); err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
	}
	return nil
}
