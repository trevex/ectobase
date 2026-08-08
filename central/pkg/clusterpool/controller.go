// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package clusterpool holds the central ClusterPool reconciler. It derives the
// pool's lifecycle phase from broker lease freshness: a fresh RenewTime yields
// Ready, a stale one yields Unknown, and no lease yields Pending. A Ready
// condition mirrors the phase. The reconciler requeues on HealthStale so
// staleness is detected even without an incoming event.
package clusterpool

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

// PhasePending is the initial lifecycle phase assigned to a new ClusterPool.
const PhasePending = "Pending"

// Reconciler drives ClusterPool lifecycle: derives Phase from broker lease
// freshness, sets a Ready condition, and requeues periodically so staleness is
// detected without an event.
type Reconciler struct {
	Client      client.Client
	HealthStale time.Duration
}

// Reconcile derives the ClusterPool phase from broker lease freshness, sets a
// Ready condition, and requeues after HealthStale so expired leases are
// detected without an explicit watch event.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pool v1alpha1.ClusterPool
	if err := r.Client.Get(ctx, req.NamespacedName, &pool); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	phase := phaseFromLease(time.Now(), pool.Status.Lease, r.HealthStale)
	cond := metav1.Condition{Type: "Ready", ObservedGeneration: pool.Generation}
	switch phase {
	case PhaseReady:
		cond.Status, cond.Reason, cond.Message = metav1.ConditionTrue, "LeaseFresh", "broker lease renewed within the staleness threshold"
	case PhaseUnknown:
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, "LeaseExpired", "broker lease not renewed within the staleness threshold"
	default:
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, "NoLease", "no broker has reported a lease for this pool"
	}

	changed := pool.Status.Phase != phase
	if changed {
		pool.Status.Phase = phase
	}
	if meta.SetStatusCondition(&pool.Status.Conditions, cond) {
		changed = true
	}
	if changed {
		if err := r.Client.Status().Update(ctx, &pool); err != nil {
			return ctrl.Result{}, fmt.Errorf("update clusterpool status: %w", err)
		}
	}
	return ctrl.Result{RequeueAfter: r.HealthStale}, nil
}

// SetupWithManager registers the reconciler on the manager, watching ClusterPool.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ClusterPool{}).
		Complete(r)
}
