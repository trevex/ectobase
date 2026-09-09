// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"net/netip"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

type LBPoolReconciler struct {
	Client    client.Client
	APIReader client.Reader
}

func (r *LBPoolReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var p netv1.LBPool
	if err := r.Client.Get(ctx, req.NamespacedName, &p); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if p.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, r.Sync(ctx, &p)
}

// Sync sets LBPool.Status.State to Invalid (bad or missing CIDR) or Ready, and
// fills the Total counter with the pool's combined allocatable address count.
func (r *LBPoolReconciler) Sync(ctx context.Context, p *netv1.LBPool) error {
	total := int32(0)
	ok := false
	if p.Spec.V4Prefix != nil {
		pre, err := netip.ParsePrefix(*p.Spec.V4Prefix)
		if err != nil || !pre.Addr().Is4() {
			return r.setState(ctx, p, "Invalid", 0)
		}
		total += totalHosts(ptrPrefix(pre.Masked()))
		ok = true
	}
	if p.Spec.V6Prefix != nil {
		pre, err := netip.ParsePrefix(*p.Spec.V6Prefix)
		if err != nil || pre.Addr().Is4() {
			return r.setState(ctx, p, "Invalid", 0)
		}
		total += totalHosts(ptrPrefix(pre.Masked()))
		ok = true
	}
	if !ok {
		return r.setState(ctx, p, "Invalid", 0)
	}
	return r.setState(ctx, p, "Ready", total)
}

func ptrPrefix(p netip.Prefix) *netip.Prefix { return &p }

func (r *LBPoolReconciler) setState(ctx context.Context, p *netv1.LBPool, state string, total int32) error {
	p.Status.State = state
	p.Status.Total = total
	if err := r.Client.Status().Update(ctx, p); err != nil {
		return fmt.Errorf("update lbpool status: %w", err)
	}
	return nil
}

func (r *LBPoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.LBPool{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}
