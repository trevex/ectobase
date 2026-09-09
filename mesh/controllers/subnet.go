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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type SubnetReconciler struct {
	Client    client.Client
	APIReader client.Reader
}

func (r *SubnetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var s netv1.Subnet
	if err := r.Client.Get(ctx, req.NamespacedName, &s); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if s.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, r.Sync(ctx, &s)
}

// Sync sets Subnet.Status.State to Invalid (bad CIDR), Conflict (overlaps a
// sibling in the same VPC) or Ready, and fills the V4/V6Total counters.
func (r *SubnetReconciler) Sync(ctx context.Context, s *netv1.Subnet) error {
	v4, v6, perr := parseSubnetPrefixes(s)
	if perr != nil {
		return r.setState(ctx, s, "Invalid", 0, 0)
	}

	var list netv1.SubnetList
	if err := r.APIReader.List(ctx, &list, client.InNamespace(s.Namespace)); err != nil {
		return fmt.Errorf("list subnets: %w", err)
	}
	for i := range list.Items {
		o := &list.Items[i]
		if (o.UID != "" && o.UID == s.UID) || (o.Name == s.Name && o.Namespace == s.Namespace) {
			continue
		}
		if o.Spec.VPCRef.Name != s.Spec.VPCRef.Name {
			continue
		}
		ov4, ov6, oerr := parseSubnetPrefixes(o)
		if oerr != nil {
			continue
		}
		// Overlap is symmetric, so only the lower-precedence sibling reports
		// Conflict (first writer wins); this keeps the resolution deterministic.
		if (overlaps(v4, ov4) || overlaps(v6, ov6)) && subnetPrecedes(o, s) {
			return r.setState(ctx, s, "Conflict", 0, 0)
		}
	}
	return r.setState(ctx, s, "Ready", totalHosts(v4), totalHosts(v6))
}

func parseSubnetPrefixes(s *netv1.Subnet) (v4, v6 *netip.Prefix, err error) {
	if s.Spec.V4Prefix != nil {
		p, e := netip.ParsePrefix(*s.Spec.V4Prefix)
		if e != nil || !p.Addr().Is4() {
			return nil, nil, fmt.Errorf("bad v4Prefix")
		}
		pm := p.Masked()
		v4 = &pm
	}
	if s.Spec.V6Prefix != nil {
		p, e := netip.ParsePrefix(*s.Spec.V6Prefix)
		if e != nil || p.Addr().Is4() {
			return nil, nil, fmt.Errorf("bad v6Prefix")
		}
		pm := p.Masked()
		v6 = &pm
	}
	if v4 == nil && v6 == nil {
		return nil, nil, fmt.Errorf("no prefixes")
	}
	return v4, v6, nil
}

// subnetPrecedes reports whether a has precedence over b for conflict
// resolution: the earlier-created object wins, with name then UID as stable
// tie-breakers so the ordering is total and independent of list order.
func subnetPrecedes(a, b *netv1.Subnet) bool {
	at, bt := a.CreationTimestamp, b.CreationTimestamp
	if !at.Equal(&bt) {
		return at.Before(&bt)
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.UID < b.UID
}

func overlaps(a, b *netip.Prefix) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Overlaps(*b)
}

// totalHosts returns the prefix's total address count (including the
// network/broadcast/reserved addresses), capped at int32, or 0 for nil.
func totalHosts(p *netip.Prefix) int32 {
	if p == nil {
		return 0
	}
	bits := p.Addr().BitLen() - p.Bits()
	if bits >= 31 {
		return int32(1<<31 - 1)
	}
	return int32(1 << bits)
}

func (r *SubnetReconciler) setState(ctx context.Context, s *netv1.Subnet, state string, v4Total, v6Total int32) error {
	s.Status.State = state
	s.Status.V4Total = v4Total
	s.Status.V6Total = v6Total
	if err := r.Client.Status().Update(ctx, s); err != nil {
		return fmt.Errorf("update subnet status: %w", err)
	}
	return nil
}

func (r *SubnetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.Subnet{}).
		Watches(&netv1.Subnet{}, r.siblingSubnets()).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// siblingSubnets re-enqueues the other Subnets in the same VPC when a Subnet
// changes or is deleted, so a Conflict loser can recompute (and go Ready) once
// the winning sibling is removed or fixed.
func (r *SubnetReconciler) siblingSubnets() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		changed, ok := obj.(*netv1.Subnet)
		if !ok {
			return nil
		}
		var list netv1.SubnetList
		if err := r.Client.List(ctx, &list, client.InNamespace(changed.Namespace)); err != nil {
			return nil
		}
		var reqs []reconcile.Request
		for i := range list.Items {
			o := &list.Items[i]
			if o.Name == changed.Name && o.Namespace == changed.Namespace {
				continue // skip the object itself (For() already handles it)
			}
			if o.Spec.VPCRef.Name == changed.Spec.VPCRef.Name {
				reqs = append(reqs, reconcile.Request{NamespacedName: keyOf(o)})
			}
		}
		return reqs
	})
}
