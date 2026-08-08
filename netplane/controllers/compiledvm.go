// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"reflect"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
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

// defaultRunStrategy is stamped when a VM leaves RunStrategy empty: KubeVirt
// restarts the VMI on another node on node death (Tier-1 local self-heal).
const defaultRunStrategy = "RerunOnFailure"

// CompileVM lowers a VirtualMachine into a CompiledVM: containerDisk image, compute
// resources, run strategy (defaulted), the cluster binding (from placement), and
// one resolved overlay interface (MAC + networkName) per owned NetworkInterface.
func CompileVM(vm *netv1.VirtualMachine, nics []netv1.NetworkInterface, placement Placement, networkName string) netv1.CompiledVM {
	runStrategy := vm.Spec.RunStrategy
	if runStrategy == "" {
		runStrategy = defaultRunStrategy
	}
	macByNIC := map[string]string{}
	for i := range nics {
		macByNIC[nics[i].Name] = nics[i].Spec.MAC
	}
	var ifaces []netv1.CompiledVMInterface
	for _, ref := range vm.Spec.InterfaceRefs {
		ifaces = append(ifaces, netv1.CompiledVMInterface{MAC: macByNIC[ref.Name], NetworkName: networkName})
	}
	compiled := netv1.CompiledVM{
		TypeMeta:   metav1.TypeMeta{APIVersion: "net.ectobase.dev/v1alpha1", Kind: "CompiledVM"},
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%s", vm.Namespace, vm.Name), Namespace: vm.Namespace},
		Spec: netv1.CompiledVMSpec{
			ClusterName: placement.ClusterName,
			Image:       vm.Spec.Image,
			Resources:   *vm.Spec.Resources.DeepCopy(),
			RunStrategy: runStrategy,
			Interfaces:  ifaces,
		},
	}
	if placement.WorkloadID != "" {
		compiled.Labels = map[string]string{"workload": placement.WorkloadID}
	}
	return compiled
}

// CompiledVMReconciler watches VirtualMachines and upserts their CompiledVM.
type CompiledVMReconciler struct {
	Client      client.Client
	NetworkName string // the multus NAD name for the flowplane overlay binding
}

func (r *CompiledVMReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vm netv1.VirtualMachine
	if err := r.Client.Get(ctx, req.NamespacedName, &vm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	var nicList netv1.NetworkInterfaceList
	if err := r.Client.List(ctx, &nicList, client.InNamespace(vm.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list nics: %w", err)
	}
	placement := Placement{ClusterName: vm.Spec.ClusterName, WorkloadID: vm.Name}
	compiled := CompileVM(&vm, nicList.Items, placement, r.NetworkName)
	key := types.NamespacedName{Namespace: compiled.Namespace, Name: compiled.Name}
	var existing netv1.CompiledVM
	err := r.Client.Get(ctx, key, &existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := controllerutil.SetControllerReference(&vm, &compiled, r.Client.Scheme()); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Client.Create(ctx, &compiled); err != nil {
			return ctrl.Result{}, fmt.Errorf("create compiledvm: %w", err)
		}
	case err != nil:
		return ctrl.Result{}, err
	default:
		if reflect.DeepEqual(existing.Spec, compiled.Spec) && existing.Labels["workload"] == compiled.Labels["workload"] {
			return ctrl.Result{}, nil
		}
		existing.Spec = compiled.Spec
		if existing.Labels == nil {
			existing.Labels = map[string]string{}
		}
		existing.Labels["workload"] = compiled.Labels["workload"]
		if err := r.Client.Update(ctx, &existing); err != nil {
			return ctrl.Result{}, fmt.Errorf("update compiledvm: %w", err)
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager watches VirtualMachines (Owns their CompiledVMs) and re-enqueues
// a VM when one of its NetworkInterfaces changes (MAC).
func (r *CompiledVMReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Distinct name: CompiledVolumeAttachmentReconciler also For(VirtualMachine), and
		// controller-runtime derives the name from the watched kind, so both would default to
		// "virtualmachine" and the manager rejects the duplicate.
		Named("compiledvm").
		For(&netv1.VirtualMachine{}).
		Owns(&netv1.CompiledVM{}).
		// MAC lives in NetworkInterface.spec, so a MAC change bumps generation;
		// GenerationChangedPredicate avoids recompiling every VM on unrelated NIC
		// status writes (e.g. port allocation).
		Watches(&netv1.NetworkInterface{}, handler.EnqueueRequestsFromMapFunc(r.vmsForNIC),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// vmsForNIC maps a NetworkInterface event to reconcile requests for every VM in the
// same namespace that references it.
func (r *CompiledVMReconciler) vmsForNIC(ctx context.Context, obj client.Object) []reconcile.Request {
	nic, ok := obj.(*netv1.NetworkInterface)
	if !ok {
		return nil
	}
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms, client.InNamespace(nic.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range vms.Items {
		for _, ref := range vms.Items[i].Spec.InterfaceRefs {
			if ref.Name == nic.Name {
				reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: vms.Items[i].Namespace, Name: vms.Items[i].Name}})
				break
			}
		}
	}
	return reqs
}
