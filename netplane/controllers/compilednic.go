// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"reflect"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// PeerImportSpec is a pre-resolved peering import for a specific LOCAL VPC (peerVNI + the peer's
// exposed prefixes). The controller computes these from Ready VPCPeerings; Compile just filters by
// the NIC's VPC.
type PeerImportSpec struct {
	VPCName        string // the LOCAL vpc this import applies to (matches nic.Spec.VPCRef.Name)
	PeerVNI        int32
	ImportPrefixes []string
}

// Compile lowers a NetworkInterface into a self-contained CompiledNIC — the sole per-NIC input the
// dataplane agent reads (it never reads the source NetworkInterface, VPC, or NATGateway).
//
// It copies identity (name, nodeName, underlayRoute, port, overlayIPs) from the NIC and stamps the
// caller-resolved vni; translates each policy whose interfaceSelector matches the NIC's labels into
// CompiledFwRules; records LB membership and peer imports; and, for each overlay IP with a
// NATGateway allocation (natBySource, keyed by source overlay IP), records a CompiledNATSource.
// peerings is a pre-resolved slice of PeerImportSpecs; only entries whose VPCName matches the NIC's
// VPC are emitted. The returned CompiledNIC has no Status set (caller fills that in if needed).
func Compile(nic *netv1.NetworkInterface, vni int32, policies []netv1.NetworkPolicy, lbs []netv1.LoadBalancer, peerings []PeerImportSpec, natBySource map[string]netv1.NATAllocation) netv1.CompiledNIC {
	nodeName := ""
	if nic.Spec.NodeName != nil {
		nodeName = *nic.Spec.NodeName
	}

	port := netv1.PortStatus{}
	if nic.Status.Port != nil {
		port = *nic.Status.Port
	}

	compiled := netv1.CompiledNIC{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "net.ectobase.dev/v1alpha1",
			Kind:       "CompiledNIC",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", nic.Namespace, nic.Name),
			Namespace: nic.Namespace,
		},
		Spec: netv1.CompiledNICSpec{
			NodeName:      nodeName,
			NICRef:        netv1.LocalObjectReference{Name: nic.Name},
			VNI:           vni,
			Port:          port,
			UnderlayRoute: nic.Status.UnderlayRoute,
			OverlayIPs:    append([]string(nil), nic.Spec.IPs...),
			Firewall:      netv1.CompiledFirewall{},
		},
	}

	nicLabels := labels.Set(nic.Labels)

	for _, policy := range policies {
		if policy.Spec.InterfaceSelector == nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(policy.Spec.InterfaceSelector)
		if err != nil {
			// Invalid selector — skip this policy.
			continue
		}
		if !sel.Matches(nicLabels) {
			continue
		}

		// Translate ingress rules.
		for _, r := range policy.Spec.Ingress {
			compiled.Spec.Firewall.Ingress = append(compiled.Spec.Firewall.Ingress, netv1.CompiledFwRule{
				CIDR:   r.CIDR,
				Proto:  r.Proto,
				Port:   r.Port,
				Action: r.Action,
			})
		}

		// Translate egress rules.
		for _, r := range policy.Spec.Egress {
			compiled.Spec.Firewall.Egress = append(compiled.Spec.Firewall.Egress, netv1.CompiledFwRule{
				CIDR:   r.CIDR,
				Proto:  r.Proto,
				Port:   r.Port,
				Action: r.Action,
			})
		}
	}

	// k8s default-allow is PER DIRECTION: a direction with no compiled rules is not governed by any
	// policy, so materialize an explicit allow-all for it (the dataplane is deny-by-default, so an
	// empty direction would otherwise drop). A direction that a policy governs keeps only its rules.
	allowAll := netv1.CompiledFwRule{CIDR: "0.0.0.0/0", Action: "Allow"} // Proto "" = any, Port 0 = any
	if len(compiled.Spec.Firewall.Ingress) == 0 {
		compiled.Spec.Firewall.Ingress = append(compiled.Spec.Firewall.Ingress, allowAll)
	}
	if len(compiled.Spec.Firewall.Egress) == 0 {
		compiled.Spec.Firewall.Egress = append(compiled.Spec.Firewall.Egress, allowAll)
	}

	// LB membership: for each LoadBalancer whose selector matches this NIC's labels or whose
	// TargetRefs name it, record a CompiledLB. This is forwarding membership ONLY — it adds no
	// firewall rule (permission comes solely from NetworkPolicy).
	for i := range lbs {
		lb := &lbs[i]
		if !lbMatchesNIC(lb, nic, nicLabels) {
			continue
		}
		ports := make([]netv1.CompiledLBPort, 0, len(lb.Spec.Ports))
		for _, p := range lb.Spec.Ports {
			ports = append(ports, netv1.CompiledLBPort{Port: p.Port, Proto: p.Proto})
		}
		compiled.Spec.LB = append(compiled.Spec.LB, netv1.CompiledLB{VIP: lb.Spec.VIP, Ports: ports})
	}

	for _, p := range peerings {
		if p.VPCName != nic.Spec.VPCRef.Name {
			continue
		}
		compiled.Spec.PeerImports = append(compiled.Spec.PeerImports, netv1.CompiledPeerImport{
			PeerVNI:        p.PeerVNI,
			ImportPrefixes: append([]string(nil), p.ImportPrefixes...),
		})
	}

	// Egress SNAT: record a CompiledNATSource for every overlay IP a NATGateway has allocated a
	// block to. Iterating over the NIC's IPs (not the map) keeps output order stable, so an
	// unchanged NIC recompiles to an identical spec (no spurious CompiledNIC write / RV churn).
	for _, ip := range nic.Spec.IPs {
		a, ok := natBySource[ip]
		if !ok {
			continue
		}
		compiled.Spec.NAT = append(compiled.Spec.NAT, netv1.CompiledNATSource{
			SourceIP: ip, NATIP: a.PublicIP, PortMin: a.PortMin, PortMax: a.PortMax,
		})
	}

	return compiled
}

// CompiledNICReconciler watches NetworkInterfaces and NetworkPolicies, then
// writes (create/update) CompiledNIC objects by calling Compile().
type CompiledNICReconciler struct{ Client client.Client }

// vpcVNI resolves a VPC's effective VNI from its status.vni, returning 0 if the VPC is
// not found or has no VNI allocated yet. (The agent has an equivalent vpcVNIFor helper,
// but it lives in a package we can't import here.)
func (r *CompiledNICReconciler) vpcVNI(ctx context.Context, namespace, name string) int32 {
	var vpc netv1.VPC
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &vpc); err != nil {
		return 0
	}
	return vpc.Status.VNI
}

// resolvePeerImports returns a PeerImportSpec per Ready VPCPeering, keyed by the LOCAL vpc name.
// A Ready peering P (VPCRef=local, PeerVPCRef=peer) contributes an import of the PEER's VNI,
// filtered by what the PEER exposes to us — the reciprocal peering (peer→local) ExposedPrefixes.
func (r *CompiledNICReconciler) resolvePeerImports(ctx context.Context) ([]PeerImportSpec, error) {
	var peerings netv1.VPCPeeringList
	if err := r.Client.List(ctx, &peerings); err != nil {
		return nil, err
	}
	// index every peering's exposedPrefixes by (namespace, fromVPC, toVPC)
	type k struct{ ns, from, to string }
	exposed := map[k][]string{}
	for i := range peerings.Items {
		p := &peerings.Items[i]
		exposed[k{p.Namespace, p.Spec.VPCRef.Name, p.Spec.PeerVPCRef.Name}] = p.Spec.ExposedPrefixes
	}
	var out []PeerImportSpec
	for i := range peerings.Items {
		p := &peerings.Items[i]
		if p.Status.State != netv1.VPCPeeringReady {
			continue
		}
		peerVNI := r.vpcVNI(ctx, p.Spec.PeerVPCRef.Namespace, p.Spec.PeerVPCRef.Name)
		if peerVNI == 0 {
			continue
		}
		// reciprocal (peer→local) exposedPrefixes = what the peer exposes to us
		recip := exposed[k{p.Spec.PeerVPCRef.Namespace, p.Spec.PeerVPCRef.Name, p.Spec.VPCRef.Name}]
		out = append(out, PeerImportSpec{
			VPCName:        p.Spec.VPCRef.Name,
			PeerVNI:        peerVNI,
			ImportPrefixes: recip,
		})
	}
	return out, nil
}

// natAllocationsBySource indexes every NATGateway allocation in the namespace by its source overlay
// IP. Compile uses it to stamp a NIC's egress-SNAT sources without the agent ever reading NATGateway.
func (r *CompiledNICReconciler) natAllocationsBySource(ctx context.Context, namespace string) (map[string]netv1.NATAllocation, error) {
	var gws netv1.NATGatewayList
	if err := r.Client.List(ctx, &gws, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	out := map[string]netv1.NATAllocation{}
	for gi := range gws.Items {
		for _, a := range gws.Items[gi].Status.Allocations {
			out[a.Source] = a
		}
	}
	return out, nil
}

// Reconcile fetches the NetworkInterface named by req and upserts its CompiledNIC.
func (r *CompiledNICReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var nic netv1.NetworkInterface
	if err := r.Client.Get(ctx, req.NamespacedName, &nic); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	var policies netv1.NetworkPolicyList
	if err := r.Client.List(ctx, &policies, client.InNamespace(nic.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list networkpolicies: %w", err)
	}
	var lbs netv1.LoadBalancerList
	if err := r.Client.List(ctx, &lbs, client.InNamespace(nic.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list loadbalancers: %w", err)
	}
	peerImports, err := r.resolvePeerImports(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("resolve peer imports: %w", err)
	}
	// Resolve the effective VNI here (status.vni, else the VPC's status.vni) so the CompiledNIC is
	// self-contained — the agent never has to resolve it from the NIC/VPC.
	vni := nic.Status.VNI
	if vni == 0 {
		vni = r.vpcVNI(ctx, nic.Namespace, nic.Spec.VPCRef.Name)
	}
	// Gather every NATGateway allocation keyed by source overlay IP so Compile can stamp this NIC's
	// egress-SNAT sources. Allocations for other NICs are simply not matched by Compile.
	natBySource, err := r.natAllocationsBySource(ctx, nic.Namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("gather nat allocations: %w", err)
	}
	compiled := Compile(&nic, vni, policies.Items, lbs.Items, peerImports, natBySource)
	key := types.NamespacedName{Namespace: compiled.Namespace, Name: compiled.Name}
	var existing netv1.CompiledNIC
	err = r.Client.Get(ctx, key, &existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := controllerutil.SetControllerReference(&nic, &compiled, r.Client.Scheme()); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Client.Create(ctx, &compiled); err != nil {
			return ctrl.Result{}, fmt.Errorf("create compilednic: %w", err)
		}
	case err != nil:
		return ctrl.Result{}, err
	default:
		if reflect.DeepEqual(existing.Spec, compiled.Spec) {
			return ctrl.Result{}, nil // unchanged: no write, no resourceVersion churn
		}
		existing.Spec = compiled.Spec
		if err := r.Client.Update(ctx, &existing); err != nil {
			return ctrl.Result{}, fmt.Errorf("update compilednic: %w", err)
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the CompiledNICReconciler with the controller-runtime Manager.
// It watches NetworkInterfaces directly (Owns their CompiledNICs) and re-enqueues NICs
// whenever a matching NetworkPolicy changes.
func (r *CompiledNICReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.NetworkInterface{}).
		Owns(&netv1.CompiledNIC{}).
		Watches(&netv1.NetworkPolicy{}, handler.EnqueueRequestsFromMapFunc(r.nicsForPolicy),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&netv1.LoadBalancer{}, handler.EnqueueRequestsFromMapFunc(r.nicsForLB),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&netv1.VPCPeering{}, handler.EnqueueRequestsFromMapFunc(r.nicsForPeering)).
		// NATGateway allocations and VPC VNIs land in .status (no generation bump), so these watches
		// use the default predicate (react to status updates) rather than GenerationChangedPredicate.
		Watches(&netv1.NATGateway{}, handler.EnqueueRequestsFromMapFunc(r.nicsForNAT)).
		Watches(&netv1.VPC{}, handler.EnqueueRequestsFromMapFunc(r.nicsForVPC)).
		Complete(r)
}

// nicsForNAT maps a NATGateway event to reconcile requests for every NetworkInterface in the same
// namespace that owns one of the gateway's allocation source IPs (so its CompiledNIC.NAT refreshes).
func (r *CompiledNICReconciler) nicsForNAT(ctx context.Context, obj client.Object) []reconcile.Request {
	gw, ok := obj.(*netv1.NATGateway)
	if !ok {
		return nil
	}
	sources := map[string]struct{}{}
	for _, a := range gw.Status.Allocations {
		sources[a.Source] = struct{}{}
	}
	var nics netv1.NetworkInterfaceList
	if err := r.Client.List(ctx, &nics, client.InNamespace(gw.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range nics.Items {
		for _, ip := range nics.Items[i].Spec.IPs {
			if _, ok := sources[ip]; ok {
				reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
					Namespace: nics.Items[i].Namespace, Name: nics.Items[i].Name,
				}})
				break
			}
		}
	}
	return reqs
}

// nicsForVPC maps a VPC event to reconcile requests for every NetworkInterface referencing it, so a
// newly-allocated VPC VNI propagates into the CompiledNIC.VNI of its NICs.
func (r *CompiledNICReconciler) nicsForVPC(ctx context.Context, obj client.Object) []reconcile.Request {
	vpc, ok := obj.(*netv1.VPC)
	if !ok {
		return nil
	}
	var nics netv1.NetworkInterfaceList
	if err := r.Client.List(ctx, &nics, client.InNamespace(vpc.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range nics.Items {
		if nics.Items[i].Spec.VPCRef.Name == vpc.Name {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: nics.Items[i].Namespace, Name: nics.Items[i].Name,
			}})
		}
	}
	return reqs
}

// nicsForPolicy maps a NetworkPolicy event to reconcile requests for every
// NetworkInterface in the same namespace whose labels match the policy's InterfaceSelector.
func (r *CompiledNICReconciler) nicsForPolicy(ctx context.Context, obj client.Object) []reconcile.Request {
	pol, ok := obj.(*netv1.NetworkPolicy)
	if !ok || pol.Spec.InterfaceSelector == nil {
		return nil
	}
	sel, err := metav1.LabelSelectorAsSelector(pol.Spec.InterfaceSelector)
	if err != nil {
		return nil
	}
	var nics netv1.NetworkInterfaceList
	if err := r.Client.List(ctx, &nics, client.InNamespace(pol.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range nics.Items {
		if sel.Matches(labels.Set(nics.Items[i].Labels)) {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: nics.Items[i].Namespace, Name: nics.Items[i].Name,
			}})
		}
	}
	return reqs
}

// nicsForLB maps a LoadBalancer event to reconcile requests for every NetworkInterface in the same
// namespace it targets (TargetRefs by name or TargetSelector by label).
func (r *CompiledNICReconciler) nicsForLB(ctx context.Context, obj client.Object) []reconcile.Request {
	lb, ok := obj.(*netv1.LoadBalancer)
	if !ok {
		return nil
	}
	var nics netv1.NetworkInterfaceList
	if err := r.Client.List(ctx, &nics, client.InNamespace(lb.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range nics.Items {
		if lbMatchesNIC(lb, &nics.Items[i], labels.Set(nics.Items[i].Labels)) {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: nics.Items[i].Namespace, Name: nics.Items[i].Name,
			}})
		}
	}
	return reqs
}

// nicsForPeering maps a VPCPeering event to reconcile requests for every NetworkInterface in the
// peering's namespace whose VPC is either side of the peering. Enqueuing BOTH sides means the local
// VPC's NICs recompile when the peering (or its reciprocal, referenced by the same VPC pair) changes.
func (r *CompiledNICReconciler) nicsForPeering(ctx context.Context, obj client.Object) []reconcile.Request {
	p, ok := obj.(*netv1.VPCPeering)
	if !ok {
		return nil
	}
	var nics netv1.NetworkInterfaceList
	if err := r.Client.List(ctx, &nics, client.InNamespace(p.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range nics.Items {
		vpc := nics.Items[i].Spec.VPCRef.Name
		if vpc != p.Spec.VPCRef.Name && vpc != p.Spec.PeerVPCRef.Name {
			continue
		}
		reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: nics.Items[i].Namespace, Name: nics.Items[i].Name,
		}})
	}
	return reqs
}

// lbMatchesNIC reports whether the LoadBalancer targets this NIC — either its TargetSelector matches
// the NIC's labels or a TargetRef names it.
func lbMatchesNIC(lb *netv1.LoadBalancer, nic *netv1.NetworkInterface, nicLabels labels.Set) bool {
	for _, ref := range lb.Spec.TargetRefs {
		if ref.Name == nic.Name {
			return true
		}
	}
	if lb.Spec.TargetSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(lb.Spec.TargetSelector)
		if err == nil && sel.Matches(nicLabels) {
			return true
		}
	}
	return false
}
