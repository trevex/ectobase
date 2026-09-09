// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"net/netip"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"github.com/trevex/ectobase/mesh/allocator"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type LBVIPReconciler struct {
	Client    client.Client
	APIReader client.Reader
}

func (r *LBVIPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var lb netv1.LoadBalancer
	if err := r.Client.Get(ctx, req.NamespacedName, &lb); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if lb.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, r.Sync(ctx, &lb)
}

// Sync allocates or adopts a VIP for one LoadBalancer from its LBPool and writes Status.
func (r *LBVIPReconciler) Sync(ctx context.Context, lb *netv1.LoadBalancer) error {
	if lb.Status.State == "Allocated" && lb.Status.ObservedGeneration == lb.Generation && lb.Status.AllocatedVIP != "" {
		return nil
	}
	var pool netv1.LBPool
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: lb.Namespace, Name: lb.Spec.PoolRef.Name}, &pool); err != nil {
		return r.setState(ctx, lb, "Invalid", "")
	}
	if pool.Status.State != "Ready" {
		return r.setState(ctx, lb, "Pending", "")
	}

	var pinned *netip.Addr
	if lb.Spec.VIP != "" {
		a, err := netip.ParseAddr(lb.Spec.VIP)
		if err != nil {
			return r.setState(ctx, lb, "Invalid", "")
		}
		pinned = &a
	}
	prefix, err := poolPrefixFor(&pool, pinned)
	if err != nil {
		return r.setState(ctx, lb, "Invalid", "")
	}

	used, err := r.usedVIPs(ctx, lb, &pool)
	if err != nil {
		return fmt.Errorf("build vip used-set: %w", err)
	}
	resv := append(allocator.ReservedFor(prefix), parseAddrs(pool.Spec.ReservedIPs)...)

	// Prefer the LB's own current VIP when auto-allocating, so an unrelated
	// spec edit (generation bump) never silently renumbers a live VIP.
	var preferred *netip.Addr
	if a, err := netip.ParseAddr(lb.Status.AllocatedVIP); err == nil {
		preferred = &a
	}

	var vip netip.Addr
	if pinned != nil {
		if !allocator.InPrefix(prefix, *pinned) {
			return r.setState(ctx, lb, "Invalid", "")
		}
		if _, taken := used[*pinned]; taken {
			return r.setState(ctx, lb, "Invalid", "")
		}
		for _, x := range resv {
			if x == *pinned {
				return r.setState(ctx, lb, "Invalid", "")
			}
		}
		vip = *pinned
	} else if a, ok := stickyOrLowest(prefix, preferred, used, resv); ok {
		vip = a
	} else {
		return r.setState(ctx, lb, "Exhausted", "")
	}
	return r.setState(ctx, lb, "Allocated", vip.String())
}

// stickyOrLowest keeps the previously-allocated VIP if it is still valid and
// free, otherwise falls back to the lowest free address in the prefix.
func stickyOrLowest(prefix netip.Prefix, preferred *netip.Addr, used map[netip.Addr]struct{}, resv []netip.Addr) (netip.Addr, bool) {
	if preferred != nil && allocator.InPrefix(prefix, *preferred) {
		if _, taken := used[*preferred]; !taken {
			blocked := false
			for _, x := range resv {
				if x == *preferred {
					blocked = true
					break
				}
			}
			if !blocked {
				return *preferred, true
			}
		}
	}
	return allocator.LowestFree(prefix, used, resv)
}

// poolPrefixFor returns the pool prefix matching a pinned VIP's family, or the
// pool's single prefix (preferring v4) when unpinned.
func poolPrefixFor(p *netv1.LBPool, pinned *netip.Addr) (netip.Prefix, error) {
	var v4, v6 *netip.Prefix
	if p.Spec.V4Prefix != nil {
		pre, err := netip.ParsePrefix(*p.Spec.V4Prefix)
		if err == nil && pre.Addr().Is4() {
			m := pre.Masked()
			v4 = &m
		}
	}
	if p.Spec.V6Prefix != nil {
		pre, err := netip.ParsePrefix(*p.Spec.V6Prefix)
		if err == nil && !pre.Addr().Is4() {
			m := pre.Masked()
			v6 = &m
		}
	}
	if pinned != nil {
		if pinned.Is4() && v4 != nil {
			return *v4, nil
		}
		if !pinned.Is4() && v6 != nil {
			return *v6, nil
		}
		return netip.Prefix{}, fmt.Errorf("pinned VIP family not offered by pool")
	}
	if v4 != nil {
		return *v4, nil
	}
	if v6 != nil {
		return *v6, nil
	}
	return netip.Prefix{}, fmt.Errorf("pool has no valid prefix")
}

// usedVIPs returns the addresses already allocated to OTHER LoadBalancers backed
// by the same pool in this namespace, from a strong non-cached list.
func (r *LBVIPReconciler) usedVIPs(ctx context.Context, self *netv1.LoadBalancer, pool *netv1.LBPool) (map[netip.Addr]struct{}, error) {
	var list netv1.LoadBalancerList
	if err := r.APIReader.List(ctx, &list, client.InNamespace(self.Namespace)); err != nil {
		return nil, err
	}
	used := map[netip.Addr]struct{}{}
	for i := range list.Items {
		o := &list.Items[i]
		if (o.UID != "" && o.UID == self.UID) || (o.Name == self.Name && o.Namespace == self.Namespace) {
			continue
		}
		if o.Spec.PoolRef.Name != pool.Name {
			continue
		}
		if a, err := netip.ParseAddr(o.Status.AllocatedVIP); err == nil {
			used[a] = struct{}{}
		}
	}
	return used, nil
}

func (r *LBVIPReconciler) setState(ctx context.Context, lb *netv1.LoadBalancer, state, vip string) error {
	lb.Status.State = state
	lb.Status.AllocatedVIP = vip
	lb.Status.ObservedGeneration = lb.Generation
	if err := r.Client.Status().Update(ctx, lb); err != nil {
		return fmt.Errorf("update loadbalancer status: %w", err)
	}
	return nil
}

func (r *LBVIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.LoadBalancer{}).
		Watches(&netv1.LBPool{}, r.lbsForPool()).
		// Delete-only watch on the LB's own type: when a sibling LB is deleted
		// (freeing a VIP), re-enqueue same-pool peers parked in Exhausted/Pending
		// so they retry immediately instead of waiting for the ~10h resync. The
		// predicate suppresses create/update/generic so ordinary status churn does
		// not amplify reconciles.
		Watches(&netv1.LoadBalancer{}, r.peersNeedingRetry(),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(event.CreateEvent) bool { return false },
				UpdateFunc:  func(event.UpdateEvent) bool { return false },
				DeleteFunc:  func(event.DeleteEvent) bool { return true },
				GenericFunc: func(event.GenericEvent) bool { return false },
			})).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// peersNeedingRetry re-enqueues same-pool LoadBalancers parked in Exhausted/Pending
// when a sibling is deleted (freeing a VIP), instead of waiting for resync.
func (r *LBVIPReconciler) peersNeedingRetry() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		gone, ok := obj.(*netv1.LoadBalancer)
		if !ok {
			return nil
		}
		return lbPeersNeedingRetry(ctx, r.Client, gone)
	})
}

// lbPeersNeedingRetry lists same-namespace LoadBalancers and returns reconcile
// requests for every OTHER LB backed by gone's pool whose State is Exhausted or
// Pending — the ones that a freed VIP may now let allocate.
func lbPeersNeedingRetry(ctx context.Context, c client.Client, gone *netv1.LoadBalancer) []reconcile.Request {
	var list netv1.LoadBalancerList
	if err := c.List(ctx, &list, client.InNamespace(gone.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		o := &list.Items[i]
		if o.Name == gone.Name && o.Namespace == gone.Namespace {
			continue
		}
		if o.Spec.PoolRef.Name != gone.Spec.PoolRef.Name {
			continue
		}
		if o.Status.State == "Exhausted" || o.Status.State == "Pending" {
			reqs = append(reqs, reconcile.Request{NamespacedName: keyOf(o)})
		}
	}
	return reqs
}

// lbsForPool re-enqueues LoadBalancers referencing a pool when the LBPool
// changes (e.g. becomes Ready), so allocation retries without waiting for resync.
func (r *LBVIPReconciler) lbsForPool() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		pool, ok := obj.(*netv1.LBPool)
		if !ok {
			return nil
		}
		var list netv1.LoadBalancerList
		if err := r.Client.List(ctx, &list, client.InNamespace(pool.Namespace)); err != nil {
			return nil
		}
		var reqs []reconcile.Request
		for i := range list.Items {
			if list.Items[i].Spec.PoolRef.Name == pool.Name {
				reqs = append(reqs, reconcile.Request{NamespacedName: keyOf(&list.Items[i])})
			}
		}
		return reqs
	})
}
