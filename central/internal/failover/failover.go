// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package failover runs Tier-2 fence-gated failover: when a ClusterPool is lost
// (Unknown beyond a conservative threshold), VMs bound to it are re-bound to a
// healthy pool — but ONLY after external storage + network fences confirm, else
// it fails safe (leaves the VM in place and records FailoverBlocked).
package failover

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	"github.com/trevex/ectobase/central/internal/clusterpool"
	"github.com/trevex/ectobase/central/internal/scheduler"
)

// Fencer externally excludes a lost instance from storage + network so a VM can
// be safely restarted elsewhere. Phase 3 ships DenyFencer (fail-safe) + tests;
// real Ceph/overlay actuators are Phase 4+.
type Fencer interface {
	FenceStorage(ctx context.Context, vm *netv1.VirtualMachine) error
	FenceNetwork(ctx context.Context, vm *netv1.VirtualMachine) error
}

// DenyFencer refuses to confirm any fence; wiring it means Tier-2 always fails safe.
type DenyFencer struct{}

func (DenyFencer) FenceStorage(context.Context, *netv1.VirtualMachine) error {
	return fmt.Errorf("no storage fence actuator configured")
}
func (DenyFencer) FenceNetwork(context.Context, *netv1.VirtualMachine) error {
	return fmt.Errorf("no network fence actuator configured")
}

// Reconciler runs Tier-2 fence-gated failover for VMs bound to a lost pool.
type Reconciler struct {
	Client            client.Client
	Fencer            Fencer
	FailoverThreshold time.Duration
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pool platformv1.ClusterPool
	if err := r.Client.Get(ctx, req.NamespacedName, &pool); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !poolLost(&pool, time.Now(), r.FailoverThreshold) {
		return ctrl.Result{RequeueAfter: r.FailoverThreshold}, nil
	}
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms); err != nil {
		return ctrl.Result{}, fmt.Errorf("list vms: %w", err)
	}
	var pools platformv1.ClusterPoolList
	if err := r.Client.List(ctx, &pools); err != nil {
		return ctrl.Result{}, fmt.Errorf("list pools: %w", err)
	}
	for i := range vms.Items {
		vm := &vms.Items[i]
		if vm.Spec.ClusterName != pool.Name {
			continue
		}
		if err := r.failoverVM(ctx, vm, pool.Name, pools.Items); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: r.FailoverThreshold}, nil
}

// failoverVM runs the fence-gated re-bind for a single VM already confirmed to be
// on a lost pool. The Spec.ClusterName write is reached ONLY if BOTH fences confirm
// AND a healthy target pool exists; every other path exits via block() (status only,
// never Spec) — the fail-safe invariant.
func (r *Reconciler) failoverVM(ctx context.Context, vm *netv1.VirtualMachine, lostPool string, pools []platformv1.ClusterPool) error {
	if err := r.Fencer.FenceStorage(ctx, vm); err != nil {
		return r.block(ctx, vm, "storage fence unconfirmed: "+err.Error())
	}
	if err := r.Fencer.FenceNetwork(ctx, vm); err != nil {
		return r.block(ctx, vm, "network fence unconfirmed: "+err.Error())
	}
	var candidates []platformv1.ClusterPool
	for _, p := range pools {
		if p.Name != lostPool {
			candidates = append(candidates, p)
		}
	}
	// nil allocated: capacity accounting across multiple VMs failing over in the
	// same pass is deferred (Phase 4). Single-VM failovers are safe; a burst onto
	// the same target may over-commit until the next reconcile re-scores.
	newPool, reason, ok := scheduler.Schedule(vm, candidates, nil)
	if !ok {
		return r.block(ctx, vm, "no pool to fail over to: "+reason)
	}
	vm.Spec.ClusterName = newPool
	if err := r.Client.Update(ctx, vm); err != nil {
		return fmt.Errorf("rebind vm: %w", err)
	}
	meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "FailoverBlocked", Status: metav1.ConditionFalse, Reason: "FailedOver", Message: "failed over to " + newPool, ObservedGeneration: vm.Generation})
	meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "Scheduled", Status: metav1.ConditionTrue, Reason: "FailedOver", Message: "bound to " + newPool, ObservedGeneration: vm.Generation})
	return r.Client.Status().Update(ctx, vm)
}

// block records a FailoverBlocked=True condition on the VM and writes ONLY status
// (never Spec) — the fail-safe exit used whenever a fence is unconfirmed or no
// target pool exists.
func (r *Reconciler) block(ctx context.Context, vm *netv1.VirtualMachine, msg string) error {
	meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "FailoverBlocked", Status: metav1.ConditionTrue, Reason: "FenceUnconfirmed", Message: msg, ObservedGeneration: vm.Generation})
	return r.Client.Status().Update(ctx, vm)
}

// poolLost reports whether pool is Unknown and its lease has been stale longer than threshold.
func poolLost(pool *platformv1.ClusterPool, now time.Time, threshold time.Duration) bool {
	if pool.Status.Phase != clusterpool.PhaseUnknown {
		return false
	}
	if pool.Status.Lease == nil || pool.Status.Lease.RenewTime == nil {
		// No timing information (unreachable via phaseFromLease, which only marks
		// Unknown when a lease exists but expired). Fail safe: without evidence of
		// how long the pool has been gone, do NOT trigger a destructive rebind.
		return false
	}
	return now.Sub(pool.Status.Lease.RenewTime.Time) > threshold
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&platformv1.ClusterPool{}).Complete(r)
}
