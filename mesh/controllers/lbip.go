// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type LoadBalancerIPReconciler struct {
	Client    client.Client
	APIReader client.Reader
}

func (r *LoadBalancerIPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var lb netv1.LoadBalancer
	if err := r.Client.Get(ctx, req.NamespacedName, &lb); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if lb.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, r.Sync(ctx, &lb)
}

// Sync claims or adopts an LB address for one LoadBalancer from its IPPool and writes Status.
//
// The claim is an IPAllocation object whose name encodes (pool, address), not a scan of what
// other LoadBalancers report in their statuses. That is what lets a NAT gateway allocate from
// the same pool without either allocator knowing the other exists.
//
// Status is written AFTER the claim, deliberately: the IPAllocation is the allocation, the
// status is a cache of it. A crash between the two leaves an allocation whose status is empty,
// and the next reconcile adopts it by name. The reverse order would lose the address.
func (r *LoadBalancerIPReconciler) Sync(ctx context.Context, lb *netv1.LoadBalancer) error {
	if lb.Status.State == "Allocated" && lb.Status.ObservedGeneration == lb.Generation && lb.Status.AllocatedIP != "" {
		return nil
	}
	var pool netv1.IPPool
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: lb.Namespace, Name: lb.Spec.PoolRef.Name}, &pool); err != nil {
		return r.setState(ctx, lb, "Invalid", "")
	}
	// A load-balancer address is reached from outside the fabric. Handing one out of an
	// internal range would advertise an address that cannot be routed to, so a type mismatch
	// is the intent being wrong — Invalid, not a wait.
	if pool.Spec.Type != netv1.IPPoolTypePublic {
		return r.setState(ctx, lb, "Invalid", "")
	}
	if pool.Status.State != "Ready" {
		return r.setState(ctx, lb, "Pending", "")
	}

	var pinned *netip.Addr
	if lb.Spec.IP != "" {
		a, err := netip.ParseAddr(lb.Spec.IP)
		if err != nil {
			return r.setState(ctx, lb, "Invalid", "")
		}
		pinned = &a
	}
	// Prefer the LB's own current address when auto-allocating, so an unrelated spec edit
	// (generation bump) never silently renumbers a live LB. The allocation this LB already
	// holds outranks this hint; status matters on the first reconcile after the migration to
	// IPPool, when an LB has an address but no allocation object yet.
	var preferred *netip.Addr
	if a, err := netip.ParseAddr(lb.Status.AllocatedIP); err == nil {
		preferred = &a
	}

	addr, ok, err := claimAddress(ctx, r.Client, r.APIReader, &pool, lb, "LoadBalancer", pinned, preferred)
	switch {
	case errors.Is(err, errNotAllocatable):
		return r.setState(ctx, lb, "Invalid", "")
	case err != nil:
		return fmt.Errorf("claim lb address: %w", err)
	case !ok:
		return r.setState(ctx, lb, "Exhausted", "")
	}
	// A LoadBalancer holds exactly one address, so any other claim of ours is superseded
	// (spec.ip repointed) and goes back to the pool. Without this, every re-pin would leak
	// an address — the status scan this replaces freed the old one implicitly.
	if err := releaseClaimsExcept(ctx, r.Client, r.APIReader, &pool, lb, "LoadBalancer", addr); err != nil {
		return err
	}
	return r.setState(ctx, lb, "Allocated", addr.String())
}

func (r *LoadBalancerIPReconciler) setState(ctx context.Context, lb *netv1.LoadBalancer, state, lbIP string) error {
	lb.Status.State = state
	lb.Status.AllocatedIP = lbIP
	lb.Status.ObservedGeneration = lb.Generation
	if err := r.Client.Status().Update(ctx, lb); err != nil {
		return fmt.Errorf("update loadbalancer status: %w", err)
	}
	return nil
}

func (r *LoadBalancerIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.LoadBalancer{}).
		Watches(&netv1.IPPool{}, r.lbsForPool()).
		// Delete-only watch on IPAllocation: a freed address is an allocation that went
		// away, whoever freed it. Re-enqueue same-pool LoadBalancers parked in
		// Exhausted/Pending so they retry at once instead of waiting for the ~10h resync.
		// Watching the allocation rather than the LoadBalancer is what makes this cover a
		// NAT gateway releasing an address too. The predicate suppresses create/update/
		// generic so ordinary churn does not amplify reconciles.
		Watches(&netv1.IPAllocation{}, r.lbsWaitingOnFreedAddress(),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(event.CreateEvent) bool { return false },
				UpdateFunc:  func(event.UpdateEvent) bool { return false },
				DeleteFunc:  func(event.DeleteEvent) bool { return true },
				GenericFunc: func(event.GenericEvent) bool { return false },
			})).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// lbsWaitingOnFreedAddress re-enqueues the LoadBalancers that a just-deleted IPAllocation may
// now let allocate.
func (r *LoadBalancerIPReconciler) lbsWaitingOnFreedAddress() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		freed, ok := obj.(*netv1.IPAllocation)
		if !ok {
			return nil
		}
		return lbsWaitingOnPool(ctx, r.Client, freed.Namespace, freed.Spec.PoolRef.Name)
	})
}

// lbsWaitingOnPool returns reconcile requests for every LoadBalancer in namespace backed by
// pool whose State is Exhausted or Pending — the ones a freed address may now satisfy.
func lbsWaitingOnPool(ctx context.Context, c client.Client, namespace, pool string) []reconcile.Request {
	if pool == "" {
		return nil
	}
	var list netv1.LoadBalancerList
	if err := c.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		o := &list.Items[i]
		if o.Spec.PoolRef.Name != pool {
			continue
		}
		if o.Status.State == "Exhausted" || o.Status.State == "Pending" {
			reqs = append(reqs, reconcile.Request{NamespacedName: keyOf(o)})
		}
	}
	return reqs
}

// lbsForPool re-enqueues LoadBalancers referencing a pool when the IPPool changes (e.g. becomes
// Ready), so allocation retries without waiting for resync.
func (r *LoadBalancerIPReconciler) lbsForPool() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		pool, ok := obj.(*netv1.IPPool)
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
