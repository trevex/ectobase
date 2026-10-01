// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package failover runs Tier-2 fence-gated failover: when a ClusterPool is lost
// (Unknown beyond a conservative threshold), VMs bound to it are re-bound to a
// healthy pool — but ONLY after external storage + network fences confirm, else
// it fails safe (leaves the VM in place and records FailoverBlocked).
package failover

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
	"github.com/trevex/ectobase/dispatch/pkg/clusterpool"
	"github.com/trevex/ectobase/dispatch/pkg/scheduler"
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

func (DenyFencer) Fence(context.Context, string) error {
	return fmt.Errorf("no fence actuator configured")
}
func (DenyFencer) Release(context.Context, string) error {
	return fmt.Errorf("no fence actuator configured")
}

// Reconciler runs Tier-2 fence-gated failover for VMs bound to a lost pool.
type Reconciler struct {
	Client        client.Client
	StorageFencer PrefixFencer
	NetworkFencer PrefixFencer
	// Routes gates fence release on route state (see routegate.go). nil holds every release that
	// has an address to check, as an unreachable reflector does.
	Routes            RouteHolder
	FailoverThreshold time.Duration
	// HealthStale is how fresh a pool's lease must be for its fences to be released (the
	// pool-health controller's threshold); zero means defaultHealthStale.
	HealthStale time.Duration
}

// defaultHealthStale matches the pool-health controller's lease-staleness threshold.
const defaultHealthStale = 30 * time.Second

func (r *Reconciler) Reconcile(ctx context.Context, rq ctrl.Request) (ctrl.Result, error) {
	var pool platformv1.ClusterPool
	if err := r.Client.Get(ctx, rq.NamespacedName, &pool); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Recovery path: release fences for /64s the broker has confirmed drained — only while the
	// pool is demonstrably back (see releaseDrained).
	healthStale := r.HealthStale
	if healthStale == 0 {
		healthStale = defaultHealthStale
	}
	waiting, err := r.releaseDrained(ctx, &pool, clusterpool.Reachable(&pool, time.Now(), healthStale))
	if err != nil {
		return ctrl.Result{}, err
	}
	if !poolLost(&pool, time.Now(), r.FailoverThreshold) {
		if waiting {
			return ctrl.Result{RequeueAfter: routeRecheck}, nil
		}
		return ctrl.Result{RequeueAfter: r.FailoverThreshold}, nil
	}
	// A lost pool's drain report is stale by definition: forget it before fencing, so only a
	// report its broker makes after the pool is back can release anything.
	if err := r.forgetDrain(ctx, &pool); err != nil {
		return ctrl.Result{}, err
	}
	// Whole-pool fence: every target must confirm BOTH fences active (barrier) before any re-bind.
	targets, complete, why := fenceCoverage(&pool)
	if len(targets) == 0 {
		return ctrl.Result{RequeueAfter: r.FailoverThreshold}, r.blockPoolVMs(ctx, pool.Name, why)
	}
	// Track a /64 the moment its STORAGE fence is applied so that a later barrier
	// failure still records it in FencedPrefixes -> releaseDrained can release it on
	// recovery. Releasing a network fence that was never set is a harmless idempotent
	// no-op. The error paths persist only pool status + VM status, never Spec.
	var fenced []string
	for _, p := range targets {
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
	// Everything we know about is now fenced — but fencing what we know is not the same as having
	// fenced everything that exists. Reattaching a disk while an unfenced node may still be writing
	// to it is the exact corruption this path exists to prevent, so the REBIND is what gets blocked,
	// not the fencing: containing the nodes we do know about is pure upside and happens regardless.
	if !complete {
		return ctrl.Result{RequeueAfter: r.FailoverThreshold}, r.blockPoolVMs(ctx, pool.Name, why)
	}
	// Fence coverage provably complete -> schedule + sticky re-bind the whole batch.
	// The fence is also the proof a planned move gets from a live pool's broker: nothing on this
	// pool can reach storage any more, so its retired twins are released. Every pass, not once — a
	// twin is retired only after the rebind below has been compiled. Neither waits on the other's
	// success: a release patch that fails must not hold back the rebind, nor the reverse.
	releaseErr := r.releaseFencedTwins(ctx, pool.Name)
	rebindErr := r.rebindPoolVMs(ctx, pool.Name)
	return ctrl.Result{RequeueAfter: r.FailoverThreshold}, errors.Join(releaseErr, rebindErr)
}

// rebindPoolVMs schedules ALL VMs on lostPool as a batch (capacity + anti-affinity
// accounted) and sticky-re-binds each that placed; VMs with no target get FailoverBlocked.
func (r *Reconciler) rebindPoolVMs(ctx context.Context, lostPool string) error {
	var vms computev1.VirtualMachineList
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
	var batch []*computev1.VirtualMachine
	for i := range vms.Items {
		if vms.Items[i].Spec.ClusterName == lostPool {
			batch = append(batch, &vms.Items[i])
		}
	}
	placements := scheduler.ScheduleBatch(batch, candidates)
	// Process the whole batch even if individual VMs fail: a mid-batch abort would
	// leave later VMs stranded on the lost pool. Collect errors and return them
	// aggregated so controller-runtime requeues and retries just the failures, while
	// the VMs that succeeded keep their progress.
	var errs []error
	for i, vm := range batch {
		pl := placements[i]
		if !pl.OK {
			if err := r.block(ctx, vm, "no pool to fail over to: "+pl.Reason); err != nil {
				errs = append(errs, fmt.Errorf("block vm %s: %w", vm.Name, err))
			}
			continue
		}
		vm.Spec.ClusterName = pl.Pool
		if err := r.Client.Update(ctx, vm); err != nil {
			errs = append(errs, fmt.Errorf("rebind vm %s: %w", vm.Name, err))
			continue // don't stamp "failed over" conditions on a rebind that didn't land
		}
		msg := "failed over to " + pl.Pool
		if pl.Violated {
			msg += " (anti-affinity violated: no non-violating pool)"
		}
		meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "FailoverBlocked", Status: metav1.ConditionFalse, Reason: "FailedOver", Message: msg, ObservedGeneration: vm.Generation})
		meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "Scheduled", Status: metav1.ConditionTrue, Reason: "FailedOver", Message: "bound to " + pl.Pool, ObservedGeneration: vm.Generation})
		// vm carries the fresh resourceVersion written back by the spec Update above,
		// so this status write targets the current object rather than a stale one.
		if err := r.Client.Status().Update(ctx, vm); err != nil {
			errs = append(errs, fmt.Errorf("status vm %s: %w", vm.Name, err))
		}
	}
	return errors.Join(errs...)
}

// releaseFencedTwins marks every retired CompiledVM twin on a fenced, lost pool released. Its broker
// is down and cannot say so itself; the fence makes it true regardless.
func (r *Reconciler) releaseFencedTwins(ctx context.Context, lostPool string) error {
	var twins compiledv1.CompiledVMList
	if err := r.Client.List(ctx, &twins, client.InNamespace(validate.PoolNamespace(lostPool))); err != nil {
		return fmt.Errorf("list compiledvms of %s: %w", lostPool, err)
	}
	var errs []error
	for i := range twins.Items {
		twin := &twins.Items[i]
		if twin.DeletionTimestamp.IsZero() || twin.Status.Released {
			continue
		}
		// Optimistic-locked, because the list above is cached and a twin's name is not unique over
		// time: a reversed move recreates a LIVE twin under the same name. A plain patch built from a
		// stale read of the old, retired twin would mark the new one released, and nothing resets
		// it. A conflict is collected like any error, so the pass requeues and reads again.
		orig := twin.DeepCopy()
		twin.Status.Released = true
		if err := r.Client.Status().Patch(ctx, twin,
			client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{})); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("release %s/%s: %w", twin.Namespace, twin.Name, err))
		}
	}
	return errors.Join(errs...)
}

// blockPoolVMs marks every VM on lostPool FailoverBlocked (used when the pool-wide
// fence barrier is not satisfied). Writes only status, never Spec.
func (r *Reconciler) blockPoolVMs(ctx context.Context, lostPool, msg string) error {
	var vms computev1.VirtualMachineList
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

// forgetDrain marks every NodeDrain entry not drained on a lost pool. NodeDrain is its broker's
// last report, and the broker writes it separately from the lease heartbeat, so a pool that comes
// back can be Ready on a fresh lease while NodeDrain still says Drained=true from before it was
// lost — after that loss, VMIs may well be running on those prefixes again. The broker's next
// report, computed from its live downstream on every tick, overwrites this: ReportStatus replaces
// the whole list whenever what it computes differs from what it read.
func (r *Reconciler) forgetDrain(ctx context.Context, pool *platformv1.ClusterPool) error {
	changed := false
	for i := range pool.Status.NodeDrain {
		if pool.Status.NodeDrain[i].Drained {
			pool.Status.NodeDrain[i].Drained = false
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := r.Client.Status().Update(ctx, pool); err != nil {
		return fmt.Errorf("forget drain report of lost pool %s: %w", pool.Name, err)
	}
	return nil
}

// setFencedPrefixes records which /64s central has fenced (drives recovery release). It adds to
// what is recorded and never drops anything: a prefix fenced by an earlier pass is still fenced
// when this pass fails before reaching it, and only releaseDrained, having released it, may forget
// it. Overwriting with this pass's shorter list leaked such a fence with nothing left to release it.
func (r *Reconciler) setFencedPrefixes(ctx context.Context, pool *platformv1.ClusterPool, fenced []string) error {
	for _, p := range fenced {
		if !slices.Contains(pool.Status.FencedPrefixes, p) {
			pool.Status.FencedPrefixes = append(pool.Status.FencedPrefixes, p)
		}
	}
	return r.Client.Status().Update(ctx, pool)
}

// releaseDrained clears the fence (both backends) for every FencedPrefix the broker
// has reported Drained and that no longer announces an address placed on another pool,
// then trims it from FencedPrefixes. Fail-safe: an un-drained /64 stays fenced, and so
// does one the reflector still holds such a route from, or that cannot be checked.
// waiting reports a prefix held on routes alone, which the caller rechecks soon; the
// pool's FenceReleaseBlocked condition says which and why. A failed check is not an
// error: it holds the release and lets the rest of the pass run.
//
// Nothing is released unless the pool is reachable (Ready on a fresh lease). NodeDrain is
// its broker's LAST report, and nothing clears it when the pool is lost again. With a
// release that can wait on routes indefinitely, a stale Drained=true on a pool lost again
// is reachable: a partition that also drops the pool's route-bus sessions empties the
// reflector, the route gate passes, and the release would reopen Ceph to nodes that are
// partitioned but alive — while the same pass fences and rebinds their VMs elsewhere.
func (r *Reconciler) releaseDrained(ctx context.Context, pool *platformv1.ClusterPool, reachable bool) (waiting bool, err error) {
	drained := map[string]bool{}
	for _, d := range pool.Status.NodeDrain {
		if d.Drained && reachable {
			drained[d.Prefix] = true
		}
	}
	// Only look up what is placed elsewhere when a release is actually on the table.
	var keys []RouteKey
	var owner map[RouteKey]string
	var lookupErr error
	for _, p := range pool.Status.FencedPrefixes {
		if drained[p] {
			keys, owner, lookupErr = r.placedElsewhere(ctx, pool.Name)
			break
		}
	}
	var remain, blocked []string
	reason := ""
	changed := false
	for _, p := range pool.Status.FencedPrefixes {
		if !drained[p] {
			remain = append(remain, p)
			continue
		}
		if lookupErr != nil {
			remain, blocked = append(remain, p), append(blocked, fmt.Sprintf("%s: cannot work out which addresses to check: %v", p, lookupErr))
			reason = "RouteCheckFailed"
			continue
		}
		// Before either fence lifts: a stale source still announcing a moved VM may well still be
		// running it, so storage stays fenced as long as the route does.
		if ok, why, msg := r.routesGone(ctx, p, keys, owner); !ok {
			remain, blocked = append(remain, p), append(blocked, msg)
			if reason != "RouteCheckFailed" {
				reason = why // one reason per condition; a failed check needs fixing first
			}
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
	if changed {
		pool.Status.FencedPrefixes = remain
	}
	if setReleaseBlocked(pool, reason, blocked) {
		changed = true
		if len(blocked) > 0 {
			log.FromContext(ctx).Info("holding fence release on route state", "pool", pool.Name, "reason", reason, "detail", blocked)
		}
	}
	if !changed {
		return len(blocked) > 0, nil
	}
	return len(blocked) > 0, r.Client.Status().Update(ctx, pool)
}

// setReleaseBlocked records on the pool why a drained prefix is still fenced, or — once nothing is
// held on routes, including when nothing is fenced at all — that it no longer is. A pool that
// never waited gets no condition at all. Reports whether the status changed.
func setReleaseBlocked(pool *platformv1.ClusterPool, reason string, blocked []string) bool {
	c := metav1.Condition{Type: ConditionFenceReleaseBlocked, ObservedGeneration: pool.Generation}
	switch {
	case len(blocked) > 0:
		c.Status, c.Reason, c.Message = metav1.ConditionTrue, reason, strings.Join(blocked, "; ")
	case meta.IsStatusConditionTrue(pool.Status.Conditions, ConditionFenceReleaseBlocked):
		c.Status, c.Reason, c.Message = metav1.ConditionFalse, "RoutesWithdrawn", "no fenced prefix is waiting on a route"
	default:
		return false
	}
	return meta.SetStatusCondition(&pool.Status.Conditions, c)
}

// block records a FailoverBlocked=True condition on the VM and writes ONLY status
// (never Spec) — the fail-safe exit used whenever a fence is unconfirmed or no
// target pool exists.
func (r *Reconciler) block(ctx context.Context, vm *computev1.VirtualMachine, msg string) error {
	meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "FailoverBlocked", Status: metav1.ConditionTrue, Reason: "FenceUnconfirmed", Message: msg, ObservedGeneration: vm.Generation})
	return r.Client.Status().Update(ctx, vm)
}

// fenceCoverage decides WHAT to fence for a lost pool and whether that fencing is COMPLETE — i.e.
// whether it provably covers every node that could still be writing, including nodes central never
// observed. Returns the targets, completeness, and (when incomplete or empty) the reason.
//
// The hazard: node /64s are reported BY THE BROKER, so the set central holds is frozen at whatever
// was last seen before contact was lost. A node that joined during the outage is absent from it. A
// fence coordinate derived from the entity being fenced is precisely what you cannot rely on,
// because that entity is the one you have lost contact with.
//
//   - `spec.underlayPrefix` declared — one aggregate, complete BY CONSTRUCTION: it contains every
//     node's underlay whether or not central ever saw the node. The correct coordinate, and central
//     configuration rather than reported state.
//   - not declared, reported prefixes collapse to ONE distinct /64 — complete for the same reason:
//     in the single-/64-per-cluster topology every node's identity is a /128 inside that /64, so
//     fencing it covers unobserved nodes too. Each node reports the /64 itself, so the raw list
//     repeats it per node; dedup makes "how many distinct coordinates" the real question.
//   - not declared, SEVERAL distinct /64s — the cluster spans /64s, so an unobserved node may sit
//     in one never reported. Incomplete: the caller fences what is known (containment is free) but
//     must not rebind.
//
// Callers distinguish "nothing to fence" (empty targets) from "fenced but not provably complete"
// (targets, complete=false) — the first cannot protect anything, the second protects what it can.
func fenceCoverage(pool *platformv1.ClusterPool) (targets []string, complete bool, why string) {
	if p := pool.Spec.UnderlayPrefix; p != "" {
		return []string{p}, true, ""
	}
	seen := map[string]bool{}
	var distinct []string
	for _, p := range pool.Status.NodePrefixes {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		distinct = append(distinct, p)
	}
	switch len(distinct) {
	case 0:
		return nil, false, "no NodePrefixes reported and spec.underlayPrefix unset; cannot fence anything"
	case 1:
		return distinct, true, ""
	default:
		return distinct, false, fmt.Sprintf("fenced the %d reported node /64s (%v) but coverage is not provably "+
			"complete with spec.underlayPrefix unset: the reported set is the last seen before contact was lost, "+
			"so a node that joined during the outage may sit in an unreported /64 and stay writable. Declare "+
			"spec.underlayPrefix (an aggregate containing every node underlay) to make fencing complete",
			len(distinct), distinct)
	}
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
	return ctrl.NewControllerManagedBy(mgr).Named("failover").For(&platformv1.ClusterPool{}).
		// A twin retired by a rebind should be released on the next pass, not after the
		// FailoverThreshold requeue — every VM of a lost pool waits on it.
		Watches(&compiledv1.CompiledVM{}, handler.EnqueueRequestsFromMapFunc(poolOfTwin),
			builder.WithPredicates(retiredTwin)).
		Complete(r)
}

// retiredTwin admits only twins being deleted: a live twin never needs a release, and letting every
// twin event wake failover would re-run the fence pass for each VM churn on every pool.
var retiredTwin = predicate.NewPredicateFuncs(func(o client.Object) bool {
	return o.GetDeletionTimestamp() != nil
})

// poolOfTwin maps a CompiledVM twin to the ClusterPool it was compiled for.
func poolOfTwin(_ context.Context, obj client.Object) []reconcile.Request {
	twin, ok := obj.(*compiledv1.CompiledVM)
	if !ok || twin.Spec.ClusterName == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: twin.Spec.ClusterName}}}
}
