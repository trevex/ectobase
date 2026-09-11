// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"reflect"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

// VMPlacementMirrorReconciler copies a CompiledVM's reported placement onto the VirtualMachine it
// was compiled from.
//
// It exists because the two halves of that write have different blast radii. A pool's broker may
// only write inside its own pool namespace — that is what per-pool RBAC scopes — so it reports
// placement onto its CompiledVM. But the VirtualMachine lives in a tenant namespace shared with
// other pools' workloads, so granting the broker that write would let any pool stamp placement on
// any pool's VM. Doing the last hop here keeps the cross-namespace write with the dispatch
// controller, which is fleet-scoped by design.
//
// Placement is observed state, so this only ever writes status, and only when it actually differs.
type VMPlacementMirrorReconciler struct {
	Client client.Client
}

func (r *VMPlacementMirrorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cvm compiledv1.CompiledVM
	if err := r.Client.Get(ctx, req.NamespacedName, &cvm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if cvm.Status.Placement == nil {
		return ctrl.Result{}, nil // nothing reported yet
	}
	// The twin does not live in its source's namespace, so the stamped back-reference is the only
	// way to find the VirtualMachine it belongs to.
	ns, name, ok := sourceOf(&cvm)
	if !ok {
		return ctrl.Result{}, nil
	}
	var vm computev1.VirtualMachine
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &vm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	want := &computev1.VMPlacement{
		ClusterName: cvm.Status.Placement.ClusterName,
		NodeName:    cvm.Status.Placement.NodeName,
		NodePrefix:  cvm.Status.Placement.NodePrefix,
	}
	if reflect.DeepEqual(vm.Status.Placement, want) {
		return ctrl.Result{}, nil // no write, no resourceVersion churn
	}
	orig := vm.DeepCopy()
	vm.Status.Placement = want
	// Merge patch, not Update: other controllers write other fields of this same status
	// subresource, and a full Update from a cached read would clobber them.
	if err := r.Client.Status().Patch(ctx, &vm, client.MergeFrom(orig)); err != nil {
		return ctrl.Result{}, fmt.Errorf("mirror placement onto virtualmachine %s/%s: %w", ns, name, err)
	}
	return ctrl.Result{}, nil
}

func (r *VMPlacementMirrorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Distinct name: CompiledVMReconciler already registers a controller rooted on
		// VirtualMachine, and controller-runtime derives the default name from the watched kind.
		Named("vmplacementmirror").
		For(&compiledv1.CompiledVM{}).
		// Also re-mirror when the VirtualMachine itself changes, so a status wipe (or a VM
		// recreated under the same name) converges without waiting for the next broker report.
		Watches(&computev1.VirtualMachine{}, handler.EnqueueRequestsFromMapFunc(r.compiledVMsForVM)).
		Complete(r)
}

// compiledVMsForVM maps a VirtualMachine back to the CompiledVMs compiled from it. It scans by
// stamp rather than computing the twin's key, because the twin's namespace depends on placement,
// which may have changed since it was written.
func (r *VMPlacementMirrorReconciler) compiledVMsForVM(ctx context.Context, obj client.Object) []ctrl.Request {
	vm, ok := obj.(*computev1.VirtualMachine)
	if !ok {
		return nil
	}
	twins, err := twinsOfSource(ctx, r.Client, &compiledv1.CompiledVMList{}, vm.Namespace, vm.Name)
	if err != nil {
		return nil
	}
	reqs := make([]ctrl.Request, 0, len(twins))
	for _, t := range twins {
		reqs = append(reqs, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(t)})
	}
	return reqs
}
