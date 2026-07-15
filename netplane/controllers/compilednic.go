// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Compile lowers a NetworkInterface + the NetworkPolicies that select it into a CompiledNIC.
//
// It copies identity (name, nodeName, vni, underlayRoute, port, overlayIPs) from the NIC, then
// translates each policy whose interfaceSelector matches the NIC's labels into CompiledFwRules.
// The returned CompiledNIC has no Status set (caller fills that in if needed).
func Compile(nic *netv1.NetworkInterface, policies []netv1.NetworkPolicy, lbs []netv1.LoadBalancer) netv1.CompiledNIC {
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
			VNI:           nic.Status.VNI,
			Port:          port,
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

	return compiled
}

// CompiledNICReconciler watches NetworkInterfaces and NetworkPolicies, then
// writes (create/update) CompiledNIC objects by calling Compile().
type CompiledNICReconciler struct{ Client client.Client }

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
	compiled := Compile(&nic, policies.Items, lbs.Items)
	key := types.NamespacedName{Namespace: compiled.Namespace, Name: compiled.Name}
	var existing netv1.CompiledNIC
	err := r.Client.Get(ctx, key, &existing)
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
		Watches(&netv1.NetworkPolicy{}, handler.EnqueueRequestsFromMapFunc(r.nicsForPolicy)).
		Complete(r)
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
