// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// CompileVolumeAttachments lowers a VirtualMachine + its referenced Volumes into one
// CompiledVolumeAttachment per VolumeRef, each cluster-bound (from placement) and
// workload-labelled. A Volume with a BootImage yields Boot=true. Pure.
func CompileVolumeAttachments(vm *computev1.VirtualMachine, volumes []storagev1.Volume, placement Placement) []compiledv1.CompiledVolumeAttachment {
	byName := map[string]*storagev1.Volume{}
	for i := range volumes {
		byName[volumes[i].Name] = &volumes[i]
	}
	var out []compiledv1.CompiledVolumeAttachment
	for _, ref := range vm.Spec.VolumeRefs {
		vol, ok := byName[ref.Name]
		if !ok {
			continue // volume not found yet; the Volume watch re-triggers
		}
		att := compiledv1.CompiledVolumeAttachment{
			TypeMeta:   metav1.TypeMeta{APIVersion: "compiled.ectobase.dev/v1alpha1", Kind: "CompiledVolumeAttachment"},
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%s", vm.Name, ref.Name), Namespace: vm.Namespace},
			Spec: compiledv1.CompiledVolumeAttachmentSpec{
				ClusterName:  placement.ClusterName,
				Size:         vol.Spec.Size,
				StorageClass: vol.Spec.StorageClass,
				BootImage:    vol.Spec.BootImage,
				Boot:         vol.Spec.BootImage != "",
			},
		}
		if placement.WorkloadID != "" {
			att.Labels = map[string]string{"workload": placement.WorkloadID}
		}
		out = append(out, att)
	}
	return out
}

// CompiledVolumeAttachmentReconciler upserts a VM's CompiledVolumeAttachments (one per
// VolumeRef) and GCs attachments for VolumeRefs that were removed.
type CompiledVolumeAttachmentReconciler struct{ Client client.Client }

func (r *CompiledVolumeAttachmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vm computev1.VirtualMachine
	if err := r.Client.Get(ctx, req.NamespacedName, &vm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	var volList storagev1.VolumeList
	if err := r.Client.List(ctx, &volList, client.InNamespace(vm.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list volumes: %w", err)
	}
	placement := Placement{ClusterName: vm.Spec.ClusterName, WorkloadID: vm.Name}
	desired := CompileVolumeAttachments(&vm, volList.Items, placement)
	want := map[string]compiledv1.CompiledVolumeAttachment{}
	for _, a := range desired {
		want[a.Name] = a
	}
	var have compiledv1.CompiledVolumeAttachmentList
	if err := r.Client.List(ctx, &have, client.InNamespace(vm.Namespace), client.MatchingLabels{"workload": vm.Name}); err != nil {
		return ctrl.Result{}, fmt.Errorf("list attachments: %w", err)
	}
	haveNames := map[string]bool{}
	for i := range have.Items {
		cur := &have.Items[i]
		haveNames[cur.Name] = true
		w, ok := want[cur.Name]
		if !ok {
			if err := r.Client.Delete(ctx, cur); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("gc attachment %s: %w", cur.Name, err)
			}
			continue
		}
		// Spec carries a resource.Quantity (Size), so compare semantically (10Gi ==
		// 10737418240) rather than reflect.DeepEqual — else equal sizes with different
		// literals would churn Updates. Also refresh the workload label defensively
		// (immutable in practice — it's vm.Name, the list key — but keeps parity with
		// the 1:1 CompiledNIC/CompiledVM compilers).
		if !equality.Semantic.DeepEqual(cur.Spec, w.Spec) || cur.Labels["workload"] != w.Labels["workload"] {
			cur.Spec = w.Spec
			if cur.Labels == nil {
				cur.Labels = map[string]string{}
			}
			cur.Labels["workload"] = w.Labels["workload"]
			if err := r.Client.Update(ctx, cur); err != nil {
				return ctrl.Result{}, fmt.Errorf("update attachment %s: %w", cur.Name, err)
			}
		}
	}
	for name, w := range want {
		if haveNames[name] {
			continue
		}
		att := w
		if err := controllerutil.SetControllerReference(&vm, &att, r.Client.Scheme()); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Client.Create(ctx, &att); err != nil {
			return ctrl.Result{}, fmt.Errorf("create attachment %s: %w", name, err)
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager watches VirtualMachines (Owns their attachments) + re-enqueues a VM
// when a referenced Volume changes.
func (r *CompiledVolumeAttachmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Distinct name: CompiledVMReconciler also For(VirtualMachine) (both default to
		// "virtualmachine" otherwise -> duplicate-controller-name panic at manager start).
		Named("compiledvolumeattachment").
		For(&computev1.VirtualMachine{}).
		Owns(&compiledv1.CompiledVolumeAttachment{}).
		// Only Volume spec changes (Size/StorageClass/BootImage) affect the compiled
		// attachment; GenerationChangedPredicate skips re-compiling on Volume status writes.
		Watches(&storagev1.Volume{}, handler.EnqueueRequestsFromMapFunc(r.vmsForVolume),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// vmsForVolume maps a Volume event to reconcile requests for VMs (same namespace) that reference it.
func (r *CompiledVolumeAttachmentReconciler) vmsForVolume(ctx context.Context, obj client.Object) []reconcile.Request {
	vol, ok := obj.(*storagev1.Volume)
	if !ok {
		return nil
	}
	var vms computev1.VirtualMachineList
	if err := r.Client.List(ctx, &vms, client.InNamespace(vol.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range vms.Items {
		for _, ref := range vms.Items[i].Spec.VolumeRefs {
			if ref.Name == vol.Name {
				reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: vms.Items[i].Namespace, Name: vms.Items[i].Name}})
				break
			}
		}
	}
	return reqs
}
