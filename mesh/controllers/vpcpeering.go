// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"net"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// VPCPeeringReconciler owns the mutual-consent Status of a VPCPeering (Pending/Ready/Invalid).
// It writes only VPCPeering.Status — never CompiledNIC (that lowering lives in CompiledNICReconciler).
type VPCPeeringReconciler struct{ Client client.Client }

// Reconcile evaluates a single VPCPeering and updates its Status.State/Message.
func (r *VPCPeeringReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var p netv1.VPCPeering
	if err := r.Client.Get(ctx, req.NamespacedName, &p); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	state, msg, err := r.evaluate(ctx, &p)
	if err != nil {
		return ctrl.Result{}, err
	}
	if p.Status.State != state || p.Status.Message != msg {
		p.Status.State, p.Status.Message = state, msg
		if err := r.Client.Status().Update(ctx, &p); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// evaluate returns (State, Message, error): Invalid on malformed exposedPrefix; Ready if a
// reciprocal peering (peer→local) exists; else Pending. A List error is propagated so
// Reconcile can return it and let controller-runtime requeue with backoff.
func (r *VPCPeeringReconciler) evaluate(ctx context.Context, p *netv1.VPCPeering) (string, string, error) {
	if p.Spec.VPCRef.Name == p.Spec.PeerVPCRef.Name && p.Namespace == p.Spec.PeerVPCRef.Namespace {
		return netv1.VPCPeeringInvalid, "a VPC cannot peer with itself", nil
	}
	for _, c := range p.Spec.ExposedPrefixes {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return netv1.VPCPeeringInvalid, "malformed exposedPrefix: " + c, nil
		}
	}
	var list netv1.VPCPeeringList
	if err := r.Client.List(ctx, &list); err != nil {
		return "", "", err
	}
	for i := range list.Items {
		q := &list.Items[i]
		if q.Spec.VPCRef.Name == p.Spec.PeerVPCRef.Name &&
			q.Namespace == p.Spec.PeerVPCRef.Namespace &&
			q.Spec.PeerVPCRef.Name == p.Spec.VPCRef.Name &&
			q.Spec.PeerVPCRef.Namespace == p.Namespace {
			return netv1.VPCPeeringReady, "reciprocal peering present", nil
		}
	}
	return netv1.VPCPeeringPending, "awaiting reciprocal peering", nil
}

// SetupWithManager registers the VPCPeeringReconciler. For(...) reconciles the object itself;
// the Watches(...reciprocals) re-enqueues the counterpart peering when one side changes so the
// pair converges to Ready together. controller-runtime dedups the two sources.
func (r *VPCPeeringReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.VPCPeering{}).
		Watches(&netv1.VPCPeering{}, handler.EnqueueRequestsFromMapFunc(r.reciprocals)).
		Complete(r)
}

// reciprocals re-enqueues the counterpart peering when one side changes, so the pair converges.
func (r *VPCPeeringReconciler) reciprocals(ctx context.Context, obj client.Object) []reconcile.Request {
	p, ok := obj.(*netv1.VPCPeering)
	if !ok {
		return nil
	}
	var list netv1.VPCPeeringList
	if err := r.Client.List(ctx, &list); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range list.Items {
		q := &list.Items[i]
		if q.Spec.VPCRef.Name == p.Spec.PeerVPCRef.Name && q.Namespace == p.Spec.PeerVPCRef.Namespace &&
			q.Spec.PeerVPCRef.Name == p.Spec.VPCRef.Name && q.Spec.PeerVPCRef.Namespace == p.Namespace {
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: q.Namespace, Name: q.Name}})
		}
	}
	return out
}
