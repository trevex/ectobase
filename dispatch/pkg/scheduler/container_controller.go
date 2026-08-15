// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package scheduler

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// ContainerReconciler binds unbound Containers to a ClusterPool. It mirrors the VM
// scheduler.Reconciler: the DISPATCH picks the pool (spec.clusterName); the node is
// chosen later on the pool cluster by kube-scheduler. Container has no PoolSelector.
type ContainerReconciler struct{ Client client.Client }

func (r *ContainerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var container computev1.Container
	if err := r.Client.Get(ctx, req.NamespacedName, &container); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if container.Spec.ClusterName != "" {
		return ctrl.Result{}, nil // already bound
	}
	var pools platformv1.ClusterPoolList
	if err := r.Client.List(ctx, &pools); err != nil {
		return ctrl.Result{}, fmt.Errorf("list pools: %w", err)
	}
	// allocatedByPool is a read-then-write snapshot: it's safe against over-commit
	// only because this controller runs with a single reconcile worker
	// (MaxConcurrentReconciles=1), so binds are serialized — same correctness reason
	// as the VM scheduler. Capacity counts BOTH VMs and Containers per pool.
	allocated, err := allocatedByPool(ctx, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Container has no PoolSelector field, so pass nil.
	pool, _, ok := ScheduleWorkload(container.Spec.Resources.Requests, nil, pools.Items, allocated)
	if !ok {
		// No Ready pool fits. ContainerStatus has no Conditions field (unlike VM),
		// so we simply leave it unbound and don't hard-error; the ClusterPool watch
		// re-enqueues this Container when a pool changes (capacity may free up).
		return ctrl.Result{}, nil
	}
	container.Spec.ClusterName = pool
	if err := r.Client.Update(ctx, &container); err != nil {
		return ctrl.Result{}, fmt.Errorf("bind container: %w", err)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager watches Containers and re-enqueues all unbound Containers when
// any ClusterPool changes. MaxConcurrentReconciles=1 serializes binds (same reason
// as the VM scheduler).
func (r *ContainerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&computev1.Container{}).
		Watches(&platformv1.ClusterPool{}, handler.EnqueueRequestsFromMapFunc(r.unboundContainers)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

func (r *ContainerReconciler) unboundContainers(ctx context.Context, _ client.Object) []ctrl.Request {
	var containers computev1.ContainerList
	if err := r.Client.List(ctx, &containers); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range containers.Items {
		if containers.Items[i].Spec.ClusterName == "" {
			reqs = append(reqs, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&containers.Items[i])})
		}
	}
	return reqs
}
