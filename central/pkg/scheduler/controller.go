// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package scheduler

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// Reconciler binds unbound VirtualMachines to a ClusterPool.
type Reconciler struct{ Client client.Client }

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vm netv1.VirtualMachine
	if err := r.Client.Get(ctx, req.NamespacedName, &vm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if vm.Spec.ClusterName != "" {
		return ctrl.Result{}, nil // already bound
	}
	var pools platformv1.ClusterPoolList
	if err := r.Client.List(ctx, &pools); err != nil {
		return ctrl.Result{}, fmt.Errorf("list pools: %w", err)
	}
	// allocatedByPool is a read-then-write snapshot: it's safe against over-commit
	// only because this controller runs with a single reconcile worker (replicas:1,
	// default MaxConcurrentReconciles=1), so binds are serialized. If concurrency is
	// ever raised, the spec Update below still 409s on a racing write (optimistic
	// concurrency) — but do not bump MaxConcurrentReconciles without revisiting this.
	allocated, err := r.allocatedByPool(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	pool, reason, ok := Schedule(&vm, pools.Items, allocated)
	if !ok {
		meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "Scheduled", Status: metav1.ConditionFalse, Reason: "Unschedulable", Message: reason, ObservedGeneration: vm.Generation})
		if err := r.Client.Status().Update(ctx, &vm); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil // re-triggered when a pool changes
	}
	vm.Spec.ClusterName = pool
	if err := r.Client.Update(ctx, &vm); err != nil {
		return ctrl.Result{}, fmt.Errorf("bind vm: %w", err)
	}
	meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "Scheduled", Status: metav1.ConditionTrue, Reason: "Bound", Message: "bound to " + pool, ObservedGeneration: vm.Generation})
	if err := r.Client.Status().Update(ctx, &vm); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// allocatedByPool sums the resource Requests of every bound VM, grouped by its pool.
func (r *Reconciler) allocatedByPool(ctx context.Context) (map[string]corev1.ResourceList, error) {
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms); err != nil {
		return nil, fmt.Errorf("list vms: %w", err)
	}
	out := map[string]corev1.ResourceList{}
	for i := range vms.Items {
		v := &vms.Items[i]
		if v.Spec.ClusterName == "" {
			continue
		}
		cur := out[v.Spec.ClusterName]
		if cur == nil {
			cur = corev1.ResourceList{}
		}
		for name, q := range v.Spec.Resources.Requests {
			c := cur[name]
			c.Add(q)
			cur[name] = c
		}
		out[v.Spec.ClusterName] = cur
	}
	return out, nil
}

// SetupWithManager watches VirtualMachines and re-enqueues all unbound VMs when any ClusterPool changes.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.VirtualMachine{}).
		Watches(&platformv1.ClusterPool{}, handler.EnqueueRequestsFromMapFunc(r.unboundVMs)).
		Complete(r)
}

func (r *Reconciler) unboundVMs(ctx context.Context, _ client.Object) []ctrl.Request {
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range vms.Items {
		if vms.Items[i].Spec.ClusterName == "" {
			reqs = append(reqs, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&vms.Items[i])})
		}
	}
	return reqs
}
