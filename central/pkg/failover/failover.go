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

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/central/pkg/clusterpool"
	"github.com/trevex/ectobase/central/pkg/scheduler"
)

// PrefixFencer applies/releases ONE fence backend (storage or network) for a single
// node /64. Fence must be idempotent and return nil ONLY when the fence is confirmed
// ACTIVE; Release returns nil only when the fence is confirmed removed.
type PrefixFencer interface {
	Fence(ctx context.Context, prefix string) error
	Release(ctx context.Context, prefix string) error
}

// DenyFencer refuses to confirm any fence; wiring it means Tier-2 always fails safe.
type DenyFencer struct{}

func (DenyFencer) Fence(context.Context, string) error   { return fmt.Errorf("no fence actuator configured") }
func (DenyFencer) Release(context.Context, string) error { return fmt.Errorf("no fence actuator configured") }

// Reconciler runs Tier-2 fence-gated failover for VMs bound to a lost pool.
type Reconciler struct {
	Client            client.Client
	StorageFencer     PrefixFencer
	NetworkFencer     PrefixFencer
	FailoverThreshold time.Duration
}

func (r *Reconciler) Reconcile(ctx context.Context, rq ctrl.Request) (ctrl.Result, error) {
	var pool platformv1.ClusterPool
	if err := r.Client.Get(ctx, rq.NamespacedName, &pool); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Recovery path: release fences for /64s the broker has confirmed drained.
	if err := r.releaseDrained(ctx, &pool); err != nil {
		return ctrl.Result{}, err
	}
	if !poolLost(&pool, time.Now(), r.FailoverThreshold) {
		return ctrl.Result{RequeueAfter: r.FailoverThreshold}, nil
	}
	// Whole-pool fence: every /64 must confirm BOTH fences active (barrier) before
	// any re-bind. A pool with no reported /64s cannot be safely fenced -> block.
	if len(pool.Status.NodePrefixes) == 0 {
		return ctrl.Result{RequeueAfter: r.FailoverThreshold}, r.blockPoolVMs(ctx, pool.Name, "no NodePrefixes reported; cannot fence")
	}
	// Track a /64 the moment its STORAGE fence is applied so that a later barrier
	// failure still records it in FencedPrefixes -> releaseDrained can release it on
	// recovery. Releasing a network fence that was never set is a harmless idempotent
	// no-op. The error paths persist only pool status + VM status, never Spec.
	var fenced []string
	for _, p := range pool.Status.NodePrefixes {
		if err := r.StorageFencer.Fence(ctx, p); err != nil {
			_ = r.setFencedPrefixes(ctx, &pool, fenced) // track what's already applied for later release
			return ctrl.Result{RequeueAfter: r.FailoverThreshold}, r.blockPoolVMs(ctx, pool.Name, "storage fence unconfirmed for "+p+": "+err.Error())
		}
		fenced = append(fenced, p) // storage fence applied -> track it (network Release is idempotent)
		if err := r.NetworkFencer.Fence(ctx, p); err != nil {
			_ = r.setFencedPrefixes(ctx, &pool, fenced)
			return ctrl.Result{RequeueAfter: r.FailoverThreshold}, r.blockPoolVMs(ctx, pool.Name, "network fence unconfirmed for "+p+": "+err.Error())
		}
	}
	if err := r.setFencedPrefixes(ctx, &pool, fenced); err != nil {
		return ctrl.Result{}, err
	}
	// All /64s fenced active -> schedule + sticky re-bind the whole batch.
	return ctrl.Result{RequeueAfter: r.FailoverThreshold}, r.rebindPoolVMs(ctx, pool.Name)
}

// rebindPoolVMs schedules ALL VMs on lostPool as a batch (capacity + anti-affinity
// accounted) and sticky-re-binds each that placed; VMs with no target get FailoverBlocked.
func (r *Reconciler) rebindPoolVMs(ctx context.Context, lostPool string) error {
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms); err != nil {
		return fmt.Errorf("list vms: %w", err)
	}
	var pools platformv1.ClusterPoolList
	if err := r.Client.List(ctx, &pools); err != nil {
		return fmt.Errorf("list pools: %w", err)
	}
	var candidates []platformv1.ClusterPool
	for _, p := range pools.Items {
		if p.Name != lostPool {
			candidates = append(candidates, p)
		}
	}
	var batch []*netv1.VirtualMachine
	for i := range vms.Items {
		if vms.Items[i].Spec.ClusterName == lostPool {
			batch = append(batch, &vms.Items[i])
		}
	}
	placements := scheduler.ScheduleBatch(batch, candidates)
	for i, vm := range batch {
		pl := placements[i]
		if !pl.OK {
			if err := r.block(ctx, vm, "no pool to fail over to: "+pl.Reason); err != nil {
				return err
			}
			continue
		}
		vm.Spec.ClusterName = pl.Pool
		if err := r.Client.Update(ctx, vm); err != nil {
			return fmt.Errorf("rebind vm %s: %w", vm.Name, err)
		}
		msg := "failed over to " + pl.Pool
		if pl.Violated {
			msg += " (anti-affinity violated: no non-violating pool)"
		}
		meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "FailoverBlocked", Status: metav1.ConditionFalse, Reason: "FailedOver", Message: msg, ObservedGeneration: vm.Generation})
		meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "Scheduled", Status: metav1.ConditionTrue, Reason: "FailedOver", Message: "bound to " + pl.Pool, ObservedGeneration: vm.Generation})
		if err := r.Client.Status().Update(ctx, vm); err != nil {
			return fmt.Errorf("status vm %s: %w", vm.Name, err)
		}
	}
	return nil
}

// blockPoolVMs marks every VM on lostPool FailoverBlocked (used when the pool-wide
// fence barrier is not satisfied). Writes only status, never Spec.
func (r *Reconciler) blockPoolVMs(ctx context.Context, lostPool, msg string) error {
	var vms netv1.VirtualMachineList
	if err := r.Client.List(ctx, &vms); err != nil {
		return fmt.Errorf("list vms: %w", err)
	}
	for i := range vms.Items {
		if vms.Items[i].Spec.ClusterName != lostPool {
			continue
		}
		if err := r.block(ctx, &vms.Items[i], msg); err != nil {
			return err
		}
	}
	return nil
}

// setFencedPrefixes records which /64s central has fenced (drives recovery release).
func (r *Reconciler) setFencedPrefixes(ctx context.Context, pool *platformv1.ClusterPool, fenced []string) error {
	pool.Status.FencedPrefixes = fenced
	return r.Client.Status().Update(ctx, pool)
}

// releaseDrained clears the fence (both backends) for every FencedPrefix the broker
// has reported Drained, then trims it from FencedPrefixes. Fail-safe: an un-drained
// /64 stays fenced. Returns nil when there's nothing to release.
func (r *Reconciler) releaseDrained(ctx context.Context, pool *platformv1.ClusterPool) error {
	if len(pool.Status.FencedPrefixes) == 0 {
		return nil
	}
	drained := map[string]bool{}
	for _, d := range pool.Status.NodeDrain {
		if d.Drained {
			drained[d.Prefix] = true
		}
	}
	var remain []string
	changed := false
	for _, p := range pool.Status.FencedPrefixes {
		if !drained[p] {
			remain = append(remain, p)
			continue
		}
		if err := r.StorageFencer.Release(ctx, p); err != nil {
			remain = append(remain, p) // hold the fence if release unconfirmed
			continue
		}
		if err := r.NetworkFencer.Release(ctx, p); err != nil {
			remain = append(remain, p)
			continue
		}
		changed = true
	}
	if !changed {
		return nil
	}
	pool.Status.FencedPrefixes = remain
	return r.Client.Status().Update(ctx, pool)
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
	// Distinct name: the clusterpool (pool-health) reconciler also watches ClusterPool and
	// controller-runtime derives the controller name from the watched kind, so both would default
	// to "clusterpool" and the manager rejects the duplicate ("controller with name clusterpool
	// already exists"). Name this one "failover".
	return ctrl.NewControllerManagedBy(mgr).Named("failover").For(&platformv1.ClusterPool{}).Complete(r)
}
