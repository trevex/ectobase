// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package controllers holds the central control-plane reconcilers. The
// NATGateway reconciler assigns every source (each IP of every NetworkInterface
// in the selected VPC) a deterministic (public-IP, port-block) via the shared
// allocator and publishes the table to NATGateway.Status.Allocations. The
// determinism is what makes the datapath drain-safe: any gateway can recompute a
// source's block from this table without shared state.
package controllers

import (
	"context"
	"fmt"
	"sort"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"github.com/trevex/ectobase/netplane/allocator"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// defaultPortsPerSource is the block size used when Spec.PortsPerSource is nil.
const defaultPortsPerSource int32 = 1024

// NATGatewayReconciler assigns deterministic egress SNAT blocks for a NATGateway's VPC.
type NATGatewayReconciler struct {
	Client client.Client
	// APIReader is an uncached, strong reader used for the NIC allocation-input list, so the
	// allocation table is never computed from a stale cache (which could drop a just-added source).
	APIReader client.Reader
}

// keyOf returns the namespaced name of an object.
func keyOf(obj client.Object) types.NamespacedName {
	return types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
}

// Reconcile fetches the NATGateway named by req and Syncs it.
func (r *NATGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var natgw netv1.NATGateway
	if err := r.Client.Get(ctx, req.NamespacedName, &natgw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err := r.Sync(ctx, &natgw); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// Sync computes and persists the deterministic allocation table for natgw.
//
// It lists the NetworkInterfaces in natgw's namespace, keeps those whose VPCRef
// matches natgw's, collects and sorts their IPs (so allocation order is
// deterministic), assigns each a block from the allocator built over
// Spec.PublicIPs / PortsPerSource, and writes Status.Allocations + State=Ready.
func (r *NATGatewayReconciler) Sync(ctx context.Context, natgw *netv1.NATGateway) error {
	var nics netv1.NetworkInterfaceList
	if err := r.APIReader.List(ctx, &nics, client.InNamespace(natgw.Namespace)); err != nil {
		return fmt.Errorf("list networkinterfaces: %w", err)
	}

	var sources []string
	for i := range nics.Items {
		nic := &nics.Items[i]
		if nic.Spec.VPCRef.Name != natgw.Spec.VPCRef.Name {
			continue
		}
		sources = append(sources, nic.Spec.IPs...)
	}
	// Sorted only so that NEW sources fill free blocks deterministically; existing
	// sources keep their block via Preassign below regardless of order.
	sort.Strings(sources)

	size := defaultPortsPerSource
	if natgw.Spec.PortsPerSource != nil {
		size = *natgw.Spec.PortsPerSource
	}

	a := allocator.New(natgw.Spec.PublicIPs, size)
	// Seed existing assignments from the persisted Status so a source that is still
	// present keeps its exact block — adding/removing OTHER sources must never
	// re-NAT its live flows. Stale entries (source gone) are simply not re-emitted.
	for _, al := range natgw.Status.Allocations {
		a.Preassign(al.Source, allocator.Block{PublicIP: al.PublicIP, PortMin: al.PortMin, PortMax: al.PortMax})
	}
	allocations := make([]netv1.NATAllocation, 0, len(sources))
	exhausted := 0
	for _, src := range sources {
		b, ok := a.Assign(src)
		if !ok {
			// Pool exhausted: skip rather than emit a colliding block. Sources that DID
			// allocate keep their (stable) blocks; the shortfall is surfaced via State.
			exhausted++
			continue
		}
		allocations = append(allocations, netv1.NATAllocation{
			Source:   src,
			PublicIP: b.PublicIP,
			PortMin:  b.PortMin,
			PortMax:  b.PortMax,
		})
	}

	state := "Ready"
	if exhausted > 0 {
		state = "Exhausted"
		log.FromContext(ctx).Info("NATGateway port-block pool exhausted; some sources unallocated",
			"natgateway", natgw.Name, "unallocated", exhausted, "publicIPs", len(natgw.Spec.PublicIPs))
	}
	// Re-Get (strong read) and write status under RetryOnConflict so a racing update to the same
	// NATGateway doesn't drop this reconcile's allocation table.
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cur netv1.NATGateway
		if err := r.APIReader.Get(ctx, keyOf(natgw), &cur); err != nil {
			return err
		}
		cur.Status.Allocations = allocations
		cur.Status.State = state
		return r.Client.Status().Update(ctx, &cur)
	}); err != nil {
		return fmt.Errorf("update natgateway status: %w", err)
	}
	return nil
}

// SetupWithManager registers the NATGatewayReconciler with the controller-runtime Manager.
// Any NATGateway change is reconciled directly; any NetworkInterface change
// re-triggers all NATGateways in the same namespace, because the allocation
// table is computed over all NICs in the VPC.
func (r *NATGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.NATGateway{}).
		Watches(&netv1.NetworkInterface{}, handler.EnqueueRequestsFromMapFunc(r.natgwsForNIC)).
		// Serialize: the allocation table is a read-then-write over all NICs in the VPC; concurrent
		// reconciles could race on Status. Mirrors the VPC allocator.
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// natgwsForNIC maps a NetworkInterface event to reconcile requests for every
// NATGateway in the same namespace. Any NIC add/change may shift the
// allocation table, so all gateways in that namespace must re-sync.
func (r *NATGatewayReconciler) natgwsForNIC(ctx context.Context, obj client.Object) []reconcile.Request {
	var list netv1.NATGatewayList
	if err := r.Client.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		ctrl.Log.WithName("natgwsForNIC").Error(err, "list NATGateways", "namespace", obj.GetNamespace())
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		reqs = append(reqs, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: list.Items[i].Namespace,
				Name:      list.Items[i].Name,
			},
		})
	}
	return reqs
}
