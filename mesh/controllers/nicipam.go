package controllers

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"

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

type NICIPAMReconciler struct {
	Client    client.Client
	APIReader client.Reader
}

func (r *NICIPAMReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var nic netv1.NetworkInterface
	if err := r.Client.Get(ctx, req.NamespacedName, &nic); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if nic.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, r.Sync(ctx, &nic)
}

// Sync allocates or adopts overlay IPs for one NIC and writes Status.
func (r *NICIPAMReconciler) Sync(ctx context.Context, nic *netv1.NetworkInterface) error {
	if nic.Status.State == "Allocated" &&
		nic.Status.ObservedGeneration == nic.Generation &&
		len(nic.Status.AllocatedIPs) > 0 &&
		nic.Status.AllocatedMAC != "" {
		return nil
	}

	sub, err := r.resolveSubnet(ctx, nic)
	if err != nil {
		return r.setState(ctx, nic, "Invalid", nil)
	}
	if sub.Status.State != "Ready" {
		return r.setState(ctx, nic, "Pending", nil)
	}
	v4, v6, err := parseSubnetPrefixes(sub)
	if err != nil {
		return r.setState(ctx, nic, "Pending", nil)
	}

	usedV4, usedV6, usedMAC, err := r.usedSets(ctx, nic, sub)
	if err != nil {
		return fmt.Errorf("build used-set: %w", err)
	}

	var pinnedV4, pinnedV6 *netip.Addr
	for _, s := range nic.Spec.IPs {
		a, perr := netip.ParseAddr(s)
		if perr != nil {
			return r.setState(ctx, nic, "Invalid", nil)
		}
		if a.Is4() {
			pinnedV4 = &a
		} else {
			pinnedV6 = &a
		}
	}

	// An explicit spec.ips list is authoritative: only the pinned families are
	// assigned. Auto-allocation across every family the subnet offers happens
	// only when the NIC pins nothing.
	hasPins := len(nic.Spec.IPs) > 0

	// Prefer the NIC's own current allocation when auto-allocating, so an
	// unrelated spec edit (generation bump) never silently renumbers it.
	var prefV4, prefV6 *netip.Addr
	for _, s := range nic.Status.AllocatedIPs {
		if a, err := netip.ParseAddr(s); err == nil {
			if a.Is4() {
				prefV4 = &a
			} else {
				prefV6 = &a
			}
		}
	}

	var out []string
	if v4 != nil {
		if pinnedV4 != nil || !hasPins {
			ip, ok := r.assignFamily(*v4, pinnedV4, prefV4, usedV4, sub.Spec.ReservedIPs)
			if !ok {
				return r.setState(ctx, nic, exhaustedOrInvalid(pinnedV4), nil)
			}
			out = append(out, ip.String())
		}
	} else if pinnedV4 != nil {
		return r.setState(ctx, nic, "Invalid", nil)
	}
	if v6 != nil {
		if pinnedV6 != nil || !hasPins {
			ip, ok := r.assignFamily(*v6, pinnedV6, prefV6, usedV6, sub.Spec.ReservedIPs)
			if !ok {
				return r.setState(ctx, nic, exhaustedOrInvalid(pinnedV6), nil)
			}
			out = append(out, ip.String())
		}
	} else if pinnedV6 != nil {
		return r.setState(ctx, nic, "Invalid", nil)
	}

	if len(out) == 0 {
		return r.setState(ctx, nic, "Invalid", nil)
	}

	// MAC is allocated alongside the IP: a stable, VPC-unique locally-administered
	// address. setState leaves Status.AllocatedMAC untouched, so assigning it here
	// persists it in the same status write; a failed pin surfaces as Invalid.
	mac, ok := r.assignMAC(nic, usedMAC)
	if !ok {
		return r.setState(ctx, nic, "Invalid", nil)
	}
	nic.Status.AllocatedMAC = mac
	return r.setState(ctx, nic, "Allocated", out)
}

// assignMAC resolves the NIC's L2 address: an explicit Spec.MAC pin (validated
// for format and VPC-uniqueness), else the sticky Status.AllocatedMAC if still
// free, else a fresh MAC derived from the NIC's stable identity. ok=false means
// an invalid or already-taken pin. Returned MACs are canonical lowercase.
func (r *NICIPAMReconciler) assignMAC(nic *netv1.NetworkInterface, used map[string]struct{}) (string, bool) {
	if nic.Spec.MAC != "" {
		hw, err := net.ParseMAC(nic.Spec.MAC)
		if err != nil {
			return "", false
		}
		m := hw.String()
		if _, taken := used[m]; taken {
			return "", false
		}
		return m, true
	}
	// Sticky: keep the previously-allocated MAC if still free, so an unrelated
	// spec edit (or a collision-loser's re-derivation) never renumbers a live NIC.
	if cur := nic.Status.AllocatedMAC; cur != "" {
		if hw, err := net.ParseMAC(cur); err == nil {
			if _, taken := used[hw.String()]; !taken {
				return hw.String(), true
			}
		}
	}
	return allocator.LowestFreeMAC(macSeed(nic), used)
}

// macSeed is the stable identity a NIC's derived MAC hashes from. UID is
// preferred (survives spec edits, matches the interface_id the agent derives
// from downstream); namespace/name is the fallback when UID is unset.
func macSeed(nic *netv1.NetworkInterface) string {
	if nic.UID != "" {
		return string(nic.UID)
	}
	return nic.Namespace + "/" + nic.Name
}

// assignFamily adopts a pinned in-prefix, free address, or allocates the lowest
// free one. When not pinned it prefers the previously-allocated address (sticky)
// before falling back to the lowest free one. ok=false means exhaustion (nil
// pinned) or an invalid/taken pin.
func (r *NICIPAMReconciler) assignFamily(prefix netip.Prefix, pinned, preferred *netip.Addr, used map[netip.Addr]struct{}, reserved []string) (netip.Addr, bool) {
	resv := append(allocator.ReservedFor(prefix), parseAddrs(reserved)...)
	if pinned != nil {
		if !allocator.InPrefix(prefix, *pinned) {
			return netip.Addr{}, false
		}
		if _, taken := used[*pinned]; taken {
			return netip.Addr{}, false
		}
		for _, x := range resv {
			if x == *pinned {
				return netip.Addr{}, false
			}
		}
		return *pinned, true
	}
	// Sticky: keep the previously-allocated address if still valid and free,
	// so an unrelated spec edit never renumbers a live workload.
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

// exhaustedOrInvalid distinguishes a failed pin (Invalid) from a full pool
// (Exhausted) for status reporting.
func exhaustedOrInvalid(pinned *netip.Addr) string {
	if pinned != nil {
		return "Invalid"
	}
	return "Exhausted"
}

// usedSets returns the v4 addresses, v6 addresses, and MACs already allocated to
// OTHER NICs in the same VPC, from a strong non-cached list. MAC keys are
// canonical net.HardwareAddr.String() form.
func (r *NICIPAMReconciler) usedSets(ctx context.Context, self *netv1.NetworkInterface, sub *netv1.Subnet) (map[netip.Addr]struct{}, map[netip.Addr]struct{}, map[string]struct{}, error) {
	var list netv1.NetworkInterfaceList
	if err := r.APIReader.List(ctx, &list, client.InNamespace(self.Namespace)); err != nil {
		return nil, nil, nil, err
	}
	usedV4 := map[netip.Addr]struct{}{}
	usedV6 := map[netip.Addr]struct{}{}
	usedMAC := map[string]struct{}{}
	for i := range list.Items {
		o := &list.Items[i]
		if (o.UID != "" && o.UID == self.UID) || (o.Name == self.Name && o.Namespace == self.Namespace) {
			continue
		}
		if o.Spec.VPCRef.Name != self.Spec.VPCRef.Name {
			continue
		}
		for _, s := range o.Status.AllocatedIPs {
			if a, err := netip.ParseAddr(s); err == nil {
				if a.Is4() {
					usedV4[a] = struct{}{}
				} else {
					usedV6[a] = struct{}{}
				}
			}
		}
		if hw, err := net.ParseMAC(o.Status.AllocatedMAC); err == nil {
			usedMAC[hw.String()] = struct{}{}
		}
	}
	return usedV4, usedV6, usedMAC, nil
}

func (r *NICIPAMReconciler) resolveSubnet(ctx context.Context, nic *netv1.NetworkInterface) (*netv1.Subnet, error) {
	if nic.Spec.SubnetRef.Name != "" {
		var s netv1.Subnet
		if err := r.Client.Get(ctx, client.ObjectKey{Namespace: nic.Namespace, Name: nic.Spec.SubnetRef.Name}, &s); err != nil {
			return nil, err
		}
		if s.Spec.VPCRef.Name != nic.Spec.VPCRef.Name {
			return nil, fmt.Errorf("subnet %q belongs to a different VPC", s.Name)
		}
		return &s, nil
	}
	var list netv1.SubnetList
	if err := r.APIReader.List(ctx, &list, client.InNamespace(nic.Namespace)); err != nil {
		return nil, err
	}
	var match []*netv1.Subnet
	for i := range list.Items {
		if list.Items[i].Spec.VPCRef.Name == nic.Spec.VPCRef.Name {
			match = append(match, &list.Items[i])
		}
	}
	if len(match) != 1 {
		return nil, fmt.Errorf("subnetRef required: VPC %q has %d subnets", nic.Spec.VPCRef.Name, len(match))
	}
	return match[0], nil
}

func parseAddrs(ss []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func (r *NICIPAMReconciler) setState(ctx context.Context, nic *netv1.NetworkInterface, state string, allocated []string) error {
	sort.Strings(allocated)
	nic.Status.State = state
	nic.Status.ObservedGeneration = nic.Generation
	nic.Status.AllocatedIPs = allocated
	if err := r.Client.Status().Update(ctx, nic); err != nil {
		return fmt.Errorf("update nic status: %w", err)
	}
	return nil
}

func (r *NICIPAMReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("nicipam").
		For(&netv1.NetworkInterface{}).
		Watches(&netv1.Subnet{}, handlerNICsForSubnet(r.Client)).
		// Delete-only watch on the NIC's own type: when a sibling NIC is deleted
		// (freeing an address), re-enqueue same-VPC peers parked in Exhausted/Pending
		// so they retry immediately instead of waiting for the ~10h resync. The
		// predicate suppresses create/update/generic so ordinary status churn does
		// not amplify reconciles.
		Watches(&netv1.NetworkInterface{}, r.peersNeedingRetry(),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(event.CreateEvent) bool { return false },
				UpdateFunc:  func(event.UpdateEvent) bool { return false },
				DeleteFunc:  func(event.DeleteEvent) bool { return true },
				GenericFunc: func(event.GenericEvent) bool { return false },
			})).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// peersNeedingRetry re-enqueues same-VPC NICs parked in Exhausted/Pending when
// a sibling is deleted (freeing an address), instead of waiting for resync.
func (r *NICIPAMReconciler) peersNeedingRetry() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		gone, ok := obj.(*netv1.NetworkInterface)
		if !ok {
			return nil
		}
		return nicPeersNeedingRetry(ctx, r.Client, gone)
	})
}

// nicPeersNeedingRetry lists same-namespace NICs and returns reconcile requests
// for every OTHER NIC in gone's VPC whose State is Exhausted or Pending — the
// ones that a freed address may now let allocate.
func nicPeersNeedingRetry(ctx context.Context, c client.Client, gone *netv1.NetworkInterface) []reconcile.Request {
	var list netv1.NetworkInterfaceList
	if err := c.List(ctx, &list, client.InNamespace(gone.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		o := &list.Items[i]
		if o.Name == gone.Name && o.Namespace == gone.Namespace {
			continue
		}
		if o.Spec.VPCRef.Name != gone.Spec.VPCRef.Name {
			continue
		}
		if o.Status.State == "Exhausted" || o.Status.State == "Pending" {
			reqs = append(reqs, reconcile.Request{NamespacedName: keyOf(o)})
		}
	}
	return reqs
}

// handlerNICsForSubnet re-enqueues NICs in a subnet's VPC when the Subnet
// changes (e.g. becomes Ready), so allocation retries without waiting for resync.
func handlerNICsForSubnet(c client.Client) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		sub, ok := obj.(*netv1.Subnet)
		if !ok {
			return nil
		}
		var list netv1.NetworkInterfaceList
		if err := c.List(ctx, &list, client.InNamespace(sub.Namespace)); err != nil {
			return nil
		}
		var reqs []reconcile.Request
		for i := range list.Items {
			if list.Items[i].Spec.VPCRef.Name == sub.Spec.VPCRef.Name {
				reqs = append(reqs, reconcile.Request{NamespacedName: keyOf(&list.Items[i])})
			}
		}
		return reqs
	})
}
