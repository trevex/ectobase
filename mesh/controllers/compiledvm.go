// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"reflect"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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
func CompileVM(vm *computev1.VirtualMachine, nics []netv1.NetworkInterface, placement Placement, networkName string) compiledv1.CompiledVM {
	runStrategy := vm.Spec.RunStrategy
	if runStrategy == "" {
		runStrategy = defaultRunStrategy
	}
	macByNIC := map[string]string{}
	for i := range nics {
		macByNIC[nics[i].Name] = macOrSpec(&nics[i])
	}
	var ifaces []compiledv1.CompiledVMInterface
	for _, ref := range vm.Spec.InterfaceRefs {
		ifaces = append(ifaces, compiledv1.CompiledVMInterface{MAC: macByNIC[ref.Name], NetworkName: networkName})
	}
	compiled := compiledv1.CompiledVM{
		TypeMeta:   metav1.TypeMeta{APIVersion: "compiled.ectobase.dev/v1alpha1", Kind: "CompiledVM"},
		ObjectMeta: metav1.ObjectMeta{Name: compiledTwinName(vm.Namespace, vm.Name), Namespace: validate.PoolNamespace(placement.ClusterName)},
		Spec: compiledv1.CompiledVMSpec{
			ClusterName: placement.ClusterName,
			Image:       vm.Spec.Image,
			Resources:   *vm.Spec.Resources.DeepCopy(),
			RunStrategy: runStrategy,
			Interfaces:  ifaces,
			CloudInit:   compiledCloudInit(vm.Spec.CloudInit),
		},
	}
	if placement.WorkloadID != "" {
		compiled.Labels = map[string]string{"workload": placement.WorkloadID}
	}
	return compiled
}

// compiledCloudInit lowers the VM's cloud-init intent onto its CompiledVM (nil stays nil,
// so a VM without bootstrap produces no cloud-init disk downstream).
func compiledCloudInit(ci *computev1.CloudInit) *compiledv1.CloudInit {
	if ci == nil {
		return nil
	}
	return &compiledv1.CloudInit{UserData: ci.UserData}
}

// CompiledVMReconciler watches VirtualMachines and upserts their CompiledVM.
type CompiledVMReconciler struct {
	Client      client.Client
	NetworkName string // the multus NAD name for the flowplane overlay binding
}

func (r *CompiledVMReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vm computev1.VirtualMachine
	if err := r.Client.Get(ctx, req.NamespacedName, &vm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !vm.DeletionTimestamp.IsZero() {
		// Retired, not deleted outright: the twin stays until its pool has stopped the VM, so a
		// delete cannot race its own running VMI. The VM itself need not wait for that.
		twins, err := twinsOfSource(ctx, r.Client, &compiledv1.CompiledVMList{}, vm.Namespace, vm.Name)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("teardown compiledvm: %w", err)
		}
		for _, o := range twins {
			if twin, ok := o.(*compiledv1.CompiledVM); ok {
				if err := retireTwin(ctx, r.Client, twin); err != nil {
					return ctrl.Result{}, fmt.Errorf("teardown compiledvm %s/%s: %w", twin.Namespace, twin.Name, err)
				}
			}
		}
		return ctrl.Result{}, releaseFinalizer(ctx, r.Client, &vm, finalizerCompiledVM)
	}
	if err := ensureFinalizer(ctx, r.Client, &vm, finalizerCompiledVM); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure compiledvm finalizer: %w", err)
	}
	// No pool, no namespace to compile into — and nothing downstream could consume the twin.
	if vm.Spec.ClusterName == "" {
		return ctrl.Result{}, nil
	}
	// Break before make: retire every twin outside this pool, and compile nothing here until each
	// of them is gone.
	poolNS := validate.PoolNamespace(vm.Spec.ClusterName)
	twins, err := twinsOfSource(ctx, r.Client, &compiledv1.CompiledVMList{}, vm.Namespace, vm.Name)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list compiledvms: %w", err)
	}
	if held := awaitingRelease(poolNS, twins); len(held) > 0 {
		for _, twin := range held {
			if twin.Namespace == poolNS {
				continue // a reversed move: this pool's own twin is already on its way out
			}
			if err := retireTwin(ctx, r.Client, twin); err != nil {
				return ctrl.Result{}, fmt.Errorf("retire compiledvm %s/%s: %w", twin.Namespace, twin.Name, err)
			}
		}
		return ctrl.Result{}, r.setMoving(ctx, &vm, metav1.ConditionTrue, "WaitingForSourceRelease",
			"waiting for pool "+held[0].Spec.ClusterName+" to release the VM before it starts on "+vm.Spec.ClusterName)
	}
	var nicList netv1.NetworkInterfaceList
	if err := r.Client.List(ctx, &nicList, client.InNamespace(vm.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list nics: %w", err)
	}
	placement := Placement{ClusterName: vm.Spec.ClusterName, WorkloadID: vm.Name}
	compiled := CompileVM(&vm, nicList.Items, placement, r.NetworkName)
	key := types.NamespacedName{Namespace: compiled.Namespace, Name: compiled.Name}
	var existing compiledv1.CompiledVM
	err = r.Client.Get(ctx, key, &existing)
	switch {
	case apierrors.IsNotFound(err):
		stampSource(&compiled, vm.Namespace, vm.Name)
		controllerutil.AddFinalizer(&compiled, finalizerSourceReleased)
		if err := r.Client.Create(ctx, &compiled); err != nil {
			return ctrl.Result{}, fmt.Errorf("create compiledvm: %w", err)
		}
	case err != nil:
		return ctrl.Result{}, err
	default:
		if reflect.DeepEqual(existing.Spec, compiled.Spec) && existing.Labels["workload"] == compiled.Labels["workload"] &&
			controllerutil.ContainsFinalizer(&existing, finalizerSourceReleased) {
			return ctrl.Result{}, r.setMoving(ctx, &vm, metav1.ConditionFalse, "Moved", "running on pool "+vm.Spec.ClusterName)
		}
		// A twin compiled before the release finalizer existed gets it here, so a later move of it
		// is gated like any other.
		controllerutil.AddFinalizer(&existing, finalizerSourceReleased)
		existing.Spec = compiled.Spec
		if existing.Labels == nil {
			existing.Labels = map[string]string{}
		}
		existing.Labels["workload"] = compiled.Labels["workload"]
		if err := r.Client.Update(ctx, &existing); err != nil {
			return ctrl.Result{}, fmt.Errorf("update compiledvm: %w", err)
		}
	}
	// No prune here: the gate above already retired every twin outside this pool, and nothing
	// reaches this point while one remains.
	return ctrl.Result{}, r.setMoving(ctx, &vm, metav1.ConditionFalse, "Moved", "running on pool "+vm.Spec.ClusterName)
}

// condMoving reports a move's progress on the VirtualMachine.
const condMoving = "Moving"

// setMoving records a move's progress. A VM that never moved carries no Moving condition at all:
// the False side is written only to close one that was opened.
func (r *CompiledVMReconciler) setMoving(ctx context.Context, vm *computev1.VirtualMachine, status metav1.ConditionStatus, reason, msg string) error {
	cur := meta.FindStatusCondition(vm.Status.Conditions, condMoving)
	if status == metav1.ConditionFalse && (cur == nil || cur.Status == metav1.ConditionFalse) {
		return nil
	}
	orig := vm.DeepCopy()
	if !meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{
		Type: condMoving, Status: status, Reason: reason, Message: msg, ObservedGeneration: vm.Generation,
	}) {
		return nil
	}
	// Optimistic lock: failover and the placement mirror write this status too, and a merge patch
	// replaces the whole conditions list — a conflict is retried rather than clobbering theirs.
	return r.Client.Status().Patch(ctx, vm, client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{}))
}

// SetupWithManager watches VirtualMachines (Owns their CompiledVMs) and re-enqueues
// a VM when one of its NetworkInterfaces changes (MAC).
func (r *CompiledVMReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Distinct name: CompiledVolumeAttachmentReconciler also For(VirtualMachine), and
		// controller-runtime derives the name from the watched kind, so both would default to
		// "virtualmachine" and the manager rejects the duplicate.
		Named("compiledvm").
		For(&computev1.VirtualMachine{}).
		// Not Owns(): the twin lives in the pool namespace, and EnqueueRequestForOwner derives the
		// request from the DEPENDENT's namespace, which would enqueue a source key that does not exist.
		Watches(&compiledv1.CompiledVM{}, handler.EnqueueRequestsFromMapFunc(requestForSource)).
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
	var vms computev1.VirtualMachineList
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
