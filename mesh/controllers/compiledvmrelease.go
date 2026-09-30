// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
)

// CompiledVMReleaseReconciler completes the handover of a retired CompiledVM twin: once the pool it
// was compiled for has reported release (status.released — written by that pool's broker, or by
// failover after fencing a lost pool), it drops the finalizer that held the twin on the dispatch.
//
// It keys on the TWIN, not the source VM, because a VM that is being deleted has already released
// its own finalizer by the time its pool gets round to letting go.
type CompiledVMReleaseReconciler struct{ Client client.Client }

func (r *CompiledVMReleaseReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var twin compiledv1.CompiledVM
	if err := r.Client.Get(ctx, req.NamespacedName, &twin); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if twin.DeletionTimestamp.IsZero() || !twin.Status.Released {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, releaseFinalizer(ctx, r.Client, &twin, finalizerSourceReleased)
}

func (r *CompiledVMReleaseReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("compiledvmrelease").
		For(&compiledv1.CompiledVM{}).
		Complete(r)
}
