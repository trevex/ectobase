// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package clusterpool holds the central ClusterPool reconciler. This is the
// minimal foundation the Phase 2 scheduler/failover controllers build on: it
// proves a controller-runtime manager can watch, cache, and status-patch
// ClusterPool objects served by the aggregated apiserver (not a CRD). For now
// the reconciler only initializes a freshly created pool's lifecycle phase to
// "Pending"; the scheduler will later transition it through Ready/Failed.
package clusterpool

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

// PhasePending is the initial lifecycle phase assigned to a new ClusterPool.
const PhasePending = "Pending"

// Reconciler drives ClusterPool lifecycle. Today it only seeds the initial
// phase; later phases (scheduling, failover) hang off the same watch.
type Reconciler struct {
	Client client.Client
}

// Reconcile initializes an unphased ClusterPool to Phase=Pending. It is a
// no-op once a phase is set, so re-reconciles (from cache resyncs or later
// status writes) are idempotent and don't fight a scheduler that has advanced
// the phase.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pool v1alpha1.ClusterPool
	if err := r.Client.Get(ctx, req.NamespacedName, &pool); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if pool.Status.Phase != "" {
		return ctrl.Result{}, nil
	}

	pool.Status.Phase = PhasePending
	if err := r.Client.Status().Update(ctx, &pool); err != nil {
		return ctrl.Result{}, fmt.Errorf("update clusterpool status: %w", err)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler on the manager, watching ClusterPool.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ClusterPool{}).
		Complete(r)
}
