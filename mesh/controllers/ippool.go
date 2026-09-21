// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"math"
	"net/netip"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type IPPoolReconciler struct {
	Client    client.Client
	APIReader client.Reader
}

func (r *IPPoolReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var p netv1.IPPool
	if err := r.Client.Get(ctx, req.NamespacedName, &p); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if p.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, r.Sync(ctx, &p)
}

// Sync sets IPPool.Status.State to Invalid (bad type or bad/missing CIDR), Conflict
// (prefixes overlap a sibling pool in the same namespace) or Ready, and fills Total.
//
// Overlap detection is why this is modelled on the Subnet reconciler rather than on the
// LB-specific pool reconciler this replaces: two overlapping pools hand the SAME address to
// two consumers, and the IPAllocation name collision does not catch it, because allocation
// names are pool-scoped (<pool>-<address>). Nothing below the pool can see that mistake.
func (r *IPPoolReconciler) Sync(ctx context.Context, p *netv1.IPPool) error {
	if !validIPPoolType(p.Spec.Type) {
		return r.setState(ctx, p, "Invalid", 0, 0)
	}
	v4, v6, perr := parsePoolPrefixes(p)
	if perr != nil {
		return r.setState(ctx, p, "Invalid", 0, 0)
	}

	var list netv1.IPPoolList
	if err := r.APIReader.List(ctx, &list, client.InNamespace(p.Namespace)); err != nil {
		return fmt.Errorf("list ippools: %w", err)
	}
	for i := range list.Items {
		o := &list.Items[i]
		if (o.UID != "" && o.UID == p.UID) || (o.Name == p.Name && o.Namespace == p.Namespace) {
			continue
		}
		ov4, ov6, oerr := parsePoolPrefixes(o)
		if oerr != nil {
			continue
		}
		// Overlap is symmetric, so only the lower-precedence sibling reports Conflict
		// (first writer wins); this keeps the resolution deterministic regardless of
		// which pool reconciles first.
		if (overlaps(v4, ov4) || overlaps(v6, ov6)) && ipPoolPrecedes(o, p) {
			return r.setState(ctx, p, "Conflict", 0, 0)
		}
	}
	allocated, err := r.countAllocations(ctx, p)
	if err != nil {
		return err
	}
	return r.setState(ctx, p, "Ready", poolTotal(v4, v6), allocated)
}

// countAllocations fills the Allocated convenience counter by label-listing the pool's
// IPAllocations. It is derived and reported for operators only: no allocator ever reads it
// back, because a counter cannot tell you WHICH addresses are free, and a stale one would be
// a licence to double-allocate.
func (r *IPPoolReconciler) countAllocations(ctx context.Context, p *netv1.IPPool) (int32, error) {
	var list netv1.IPAllocationList
	if err := r.APIReader.List(ctx, &list, client.InNamespace(p.Namespace),
		client.MatchingLabels{netv1.PoolLabel: p.Name}); err != nil {
		return 0, fmt.Errorf("list ipallocations for pool %s: %w", p.Name, err)
	}
	var n int32
	for i := range list.Items {
		// The label is an index, not a fact — spec.poolRef is what the object claims.
		if list.Items[i].Spec.PoolRef.Name == p.Name {
			n++
		}
	}
	return n, nil
}

// validIPPoolType mirrors the v1alpha1 kubebuilder enum. The CRD rejects anything else on
// the CRD path and IPPool.Validate does on the aggregated one, but a pool that predates a
// marker (or arrives through a client that skips both) must not silently serve addresses.
func validIPPoolType(t netv1.IPPoolType) bool {
	return t == netv1.IPPoolTypePublic || t == netv1.IPPoolTypeInternal
}

// parsePoolPrefixes returns the pool's masked prefixes, erroring when one is malformed,
// is the wrong family for its field, or when the pool offers no prefix at all.
func parsePoolPrefixes(p *netv1.IPPool) (v4, v6 *netip.Prefix, err error) {
	if p.Spec.V4Prefix != nil {
		pre, e := netip.ParsePrefix(*p.Spec.V4Prefix)
		if e != nil || !pre.Addr().Is4() {
			return nil, nil, fmt.Errorf("bad v4Prefix")
		}
		pm := pre.Masked()
		v4 = &pm
	}
	if p.Spec.V6Prefix != nil {
		pre, e := netip.ParsePrefix(*p.Spec.V6Prefix)
		if e != nil || pre.Addr().Is4() {
			return nil, nil, fmt.Errorf("bad v6Prefix")
		}
		pm := pre.Masked()
		v6 = &pm
	}
	if v4 == nil && v6 == nil {
		return nil, nil, fmt.Errorf("no prefixes")
	}
	return v4, v6, nil
}

// poolTotal is the pool's combined allocatable address count, accumulated wide and
// clamped to the int32 status field.
func poolTotal(v4, v6 *netip.Prefix) int32 {
	total := int64(totalHosts(v4)) + int64(totalHosts(v6))
	if total > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(total)
}

// ipPoolPrecedes reports whether a has precedence over b for conflict resolution: the
// earlier-created object wins, with name then UID as stable tie-breakers so the ordering
// is total and independent of list order.
func ipPoolPrecedes(a, b *netv1.IPPool) bool {
	at, bt := a.CreationTimestamp, b.CreationTimestamp
	if !at.Equal(&bt) {
		return at.Before(&bt)
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.UID < b.UID
}

func (r *IPPoolReconciler) setState(ctx context.Context, p *netv1.IPPool, state string, total, allocated int32) error {
	p.Status.State = state
	p.Status.Total = total
	p.Status.Allocated = allocated
	if err := r.Client.Status().Update(ctx, p); err != nil {
		return fmt.Errorf("update ippool status: %w", err)
	}
	return nil
}

func (r *IPPoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.IPPool{}).
		Watches(&netv1.IPPool{}, r.siblingPools()).
		// Keeps the Allocated counter roughly live. It is a display value, so a missed
		// event costs an operator a stale number until the next resync, nothing more.
		Watches(&netv1.IPAllocation{}, r.poolOfAllocation()).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// siblingPools re-enqueues the other IPPools in the namespace when one changes or is
// deleted, so a Conflict loser can recompute (and go Ready) once the winner is removed
// or repointed.
func (r *IPPoolReconciler) siblingPools() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		changed, ok := obj.(*netv1.IPPool)
		if !ok {
			return nil
		}
		var list netv1.IPPoolList
		if err := r.Client.List(ctx, &list, client.InNamespace(changed.Namespace)); err != nil {
			return nil
		}
		var reqs []reconcile.Request
		for i := range list.Items {
			o := &list.Items[i]
			if o.Name == changed.Name && o.Namespace == changed.Namespace {
				continue // skip the object itself (For() already handles it)
			}
			reqs = append(reqs, reconcile.Request{NamespacedName: keyOf(o)})
		}
		return reqs
	})
}

// poolOfAllocation enqueues the IPPool an IPAllocation names, so the Allocated counter
// follows claims and releases instead of only the resync.
func (r *IPPoolReconciler) poolOfAllocation() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		alloc, ok := obj.(*netv1.IPAllocation)
		if !ok || alloc.Spec.PoolRef.Name == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{
			Namespace: alloc.Namespace, Name: alloc.Spec.PoolRef.Name,
		}}}
	})
}
