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
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"github.com/trevex/ectobase/mesh/allocator"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
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
// deterministic), assigns each a block from the allocator built over the gateway's
// public addresses / PortsPerSource, and writes Status.Allocations + State=Ready.
//
// With Spec.PoolRef set, "the gateway's public addresses" are the IPAllocations it holds in that
// IPPool rather than a literal Spec.PublicIPs list, and the set GROWS by one address per pass
// whenever a source cannot be blocked. It never shrinks: an address whose blocks a live source
// still uses cannot be handed back without re-NATing that source.
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
		// Status, never Spec.IPs: spec is an optional PIN, status is the overlay identity
		// central IPAM committed. A NIC that auto-allocates (the normal case) pins nothing,
		// so keying on spec gave it no SNAT block at all. Status covers both paths — a BYO
		// pin is validated and then committed to status too.
		//
		// Deliberately NOT gated on State=="Allocated": once a NIC holds addresses those stay
		// its identity until it is deleted, and dropping a source on a transient regression
		// would free its block for reuse and re-NAT its live flows. An empty list (never
		// allocated) contributes nothing.
		sources = append(sources, nic.Status.AllocatedIPs...)
	}
	// Sorted only so that NEW sources fill free blocks deterministically; existing
	// sources keep their block via Preassign below regardless of order.
	sort.Strings(sources)

	size := defaultPortsPerSource
	if natgw.Spec.PortsPerSource != nil {
		size = *natgw.Spec.PortsPerSource
	}

	pool, addrs, state, err := r.publicAddresses(ctx, natgw)
	if err != nil {
		return err
	}
	if state != "" {
		// The address set could not be established at all: Invalid (the intent is wrong —
		// no pool, wrong type, a pin that is not in the pool) or Pending (the pool is not
		// Ready yet). Report it and leave Status.Allocations ALONE: the sources that
		// already hold blocks are still SNATing through them on the datapath, and wiping
		// the table on a transient pool problem would re-NAT every one of them.
		return r.setState(ctx, natgw, state)
	}

	allocations, unblocked := assignBlocks(natgw, addrs, size, sources)
	// Grow on demand: some source could not be blocked and every address this gateway holds is
	// full, so take ONE more from the pool and lay the blocks out again. One per pass on
	// purpose — a gateway that suddenly gains hundreds of NICs must not drain the pool in a
	// single tick, and the status write below re-enqueues us for the next one.
	if unblocked > 0 && pool != nil {
		extra, ok, cerr := claimAnotherAddress(ctx, r.Client, r.APIReader, pool, natgw, "NATGateway")
		switch {
		case errors.Is(cerr, errNotAllocatable):
			return r.setState(ctx, natgw, "Invalid")
		case cerr != nil:
			return fmt.Errorf("grow natgateway %s address set: %w", natgw.Name, cerr)
		case ok:
			// Inserted in order, not appended: the next reconcile reads this same set
			// back from consumerAddresses ASCENDING, and the block layout is positional,
			// so the two passes have to agree on the order. Existing sources are safe
			// either way — Preassign pins their block by value, not by index.
			addrs = insertSorted(addrs, extra)
			allocations, unblocked = assignBlocks(natgw, addrs, size, sources)
		}
	}

	state = "Ready"
	if unblocked > 0 {
		state = "Exhausted"
		log.FromContext(ctx).Info("NATGateway port-block pool exhausted; some sources unallocated",
			"natgateway", natgw.Name, "unallocated", unblocked, "publicIPs", len(addrs))
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

// assignBlocks lays the whole source set out over addrs, seeding every persisted assignment
// first, and returns the table plus how many sources could not be blocked.
//
// Preassign-before-Assign is the property that protects live traffic: the allocator maps a flat
// block index to an address BY POSITION in addrs, so adding an address renumbers the index
// space — but a persisted (source, publicIP, portMin) is re-pinned by VALUE, so the source keeps
// the exact block it had. Only NEW sources are handed the lowest free index.
func assignBlocks(natgw *netv1.NATGateway, addrs []string, size int32, sources []string) ([]netv1.NATAllocation, int) {
	a := allocator.New(addrs, size)
	for _, al := range natgw.Status.Allocations {
		a.Preassign(al.Source, allocator.Block{PublicIP: al.PublicIP, PortMin: al.PortMin, PortMax: al.PortMax})
	}
	out := make([]netv1.NATAllocation, 0, len(sources))
	unblocked := 0
	for _, src := range sources {
		b, ok := a.Assign(src)
		if !ok {
			// Skip rather than emit a colliding block: handing the same (public IP, port
			// range) to two sources overlaps their SNAT tuples. Sources that DID allocate
			// keep their (stable) blocks; the shortfall is surfaced via State.
			unblocked++
			continue
		}
		out = append(out, netv1.NATAllocation{
			Source:   src,
			PublicIP: b.PublicIP,
			PortMin:  b.PortMin,
			PortMax:  b.PortMax,
		})
	}
	return out, unblocked
}

// publicAddresses returns the pool this gateway draws from (nil when it draws from none) and the
// addresses its blocks are laid out over, in a stable ascending order.
//
// A non-empty state is terminal for this pass: the caller reports it and touches nothing else.
func (r *NATGatewayReconciler) publicAddresses(ctx context.Context, natgw *netv1.NATGateway) (*netv1.IPPool, []string, string, error) {
	// No pool: Spec.PublicIPs keeps its pre-pool meaning — literal addresses, allocated
	// nowhere and owned by nothing, in exactly the order the spec lists them. A gateway
	// written before IPPool existed keeps working, block for block.
	if natgw.Spec.PoolRef.Name == "" {
		return nil, natgw.Spec.PublicIPs, "", nil
	}

	var pool netv1.IPPool
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: natgw.Namespace, Name: natgw.Spec.PoolRef.Name}, &pool); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, nil, "", fmt.Errorf("get ippool %s: %w", natgw.Spec.PoolRef.Name, err)
		}
		return nil, nil, "Invalid", nil // the reference names nothing
	}
	// A NAT address is the source address of traffic leaving for the WAN, so it has to be
	// routable back from there. An internal range is the INTENT being wrong, not a wait.
	if pool.Spec.Type != netv1.IPPoolTypePublic {
		return nil, nil, "Invalid", nil
	}
	if pool.Status.State != "Ready" {
		return nil, nil, "Pending", nil
	}

	// Pins first, so a pinned address is part of the set before anything is laid out over it.
	for _, ip := range natgw.Spec.PublicIPs {
		a, perr := netip.ParseAddr(ip)
		if perr != nil {
			return nil, nil, "Invalid", nil
		}
		_, ok, err := claimAddress(ctx, r.Client, r.APIReader, &pool, natgw, "NATGateway", &a, nil)
		switch {
		case errors.Is(err, errNotAllocatable):
			// Outside the pool, reserved there, or held by somebody else. Nothing that
			// happens later fixes any of those.
			return nil, nil, "Invalid", nil
		case err != nil:
			return nil, nil, "", fmt.Errorf("pin natgateway address %s: %w", ip, err)
		case !ok:
			return nil, nil, "Exhausted", nil
		}
	}

	addrs, err := consumerAddresses(ctx, r.APIReader, &pool, natgw, "NATGateway")
	if err != nil {
		return nil, nil, "", err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return &pool, out, "", nil
}

// insertSorted places addr into an already-ascending address list at its ordered position.
//
// Position IS the block layout (allocator.blockAt indexes the list), so the order has to be a
// function of the SET alone: consumerAddresses hands the next reconcile the same addresses
// ascending, and a grown address appended at the end would put the two passes' layouts at odds.
func insertSorted(addrs []string, addr netip.Addr) []string {
	i := 0
	for ; i < len(addrs); i++ {
		a, err := netip.ParseAddr(addrs[i])
		if err != nil || addr.Compare(a) < 0 {
			break
		}
	}
	return slices.Insert(addrs, i, addr.String())
}

// setState reports a terminal state for this pass WITHOUT touching Status.Allocations. The
// allocation table is live datapath configuration: a gateway whose pool has gone missing still
// has sources SNATing through the blocks it published, and clearing them would re-NAT every one.
func (r *NATGatewayReconciler) setState(ctx context.Context, natgw *netv1.NATGateway, state string) error {
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cur netv1.NATGateway
		if err := r.APIReader.Get(ctx, keyOf(natgw), &cur); err != nil {
			return err
		}
		if cur.Status.State == state {
			return nil
		}
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
		// A gateway parked in Pending because its pool was not Ready (or was in Conflict)
		// has no other event coming: re-enqueue it when the pool changes rather than
		// leaving it to the ~10h resync.
		Watches(&netv1.IPPool{}, handler.EnqueueRequestsFromMapFunc(r.natgwsForPool)).
		// A gateway that drained its pool is Exhausted with nothing to wake it: growth is driven
		// by its own port blocks running out, not by anything that emits an event. Without this
		// it waits for NIC churn or the ~10h resync even though an address just came free.
		// Delete-only, so ordinary allocation churn does not amplify reconciles, and it fires for
		// an address freed by ANY consumer — a LoadBalancer releasing one unblocks a gateway.
		Watches(&netv1.IPAllocation{}, handler.EnqueueRequestsFromMapFunc(r.natgwsForFreedAddress),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(event.CreateEvent) bool { return false },
				UpdateFunc:  func(event.UpdateEvent) bool { return false },
				DeleteFunc:  func(event.DeleteEvent) bool { return true },
				GenericFunc: func(event.GenericEvent) bool { return false },
			})).
		// Serialize: the allocation table is a read-then-write over all NICs in the VPC; concurrent
		// reconciles could race on Status. Mirrors the VPC allocator.
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// natgwsForFreedAddress re-enqueues the gateways that a just-deleted IPAllocation may now let
// grow: those drawing from the same pool and parked in Exhausted or Pending.
func (r *NATGatewayReconciler) natgwsForFreedAddress(ctx context.Context, obj client.Object) []reconcile.Request {
	freed, ok := obj.(*netv1.IPAllocation)
	if !ok || freed.Spec.PoolRef.Name == "" {
		return nil
	}
	var list netv1.NATGatewayList
	if err := r.Client.List(ctx, &list, client.InNamespace(freed.Namespace)); err != nil {
		ctrl.Log.WithName("natgwsForFreedAddress").Error(err, "list NATGateways", "namespace", freed.Namespace)

		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		o := &list.Items[i]
		if o.Spec.PoolRef.Name != freed.Spec.PoolRef.Name {
			continue
		}
		if o.Status.State == "Exhausted" || o.Status.State == "Pending" {
			reqs = append(reqs, reconcile.Request{NamespacedName: keyOf(o)})
		}
	}

	return reqs
}

// natgwsForPool maps an IPPool event to the NATGateways that draw from it.
func (r *NATGatewayReconciler) natgwsForPool(ctx context.Context, obj client.Object) []reconcile.Request {
	pool, ok := obj.(*netv1.IPPool)
	if !ok {
		return nil
	}
	var list netv1.NATGatewayList
	if err := r.Client.List(ctx, &list, client.InNamespace(pool.Namespace)); err != nil {
		ctrl.Log.WithName("natgwsForPool").Error(err, "list NATGateways", "namespace", pool.Namespace)
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		if list.Items[i].Spec.PoolRef.Name == pool.Name {
			reqs = append(reqs, reconcile.Request{NamespacedName: keyOf(&list.Items[i])})
		}
	}
	return reqs
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
