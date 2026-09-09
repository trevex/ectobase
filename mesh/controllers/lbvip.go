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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
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
	} else {
		a, ok := allocator.LowestFree(prefix, used, resv)
		if !ok {
			return r.setState(ctx, lb, "Exhausted", "")
		}
		vip = a
	}
	return r.setState(ctx, lb, "Allocated", vip.String())
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
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
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
