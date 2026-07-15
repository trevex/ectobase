// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"fmt"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Compile lowers a NetworkInterface + the NetworkPolicies that select it into a CompiledNIC.
//
// It copies identity (name, nodeName, vni, underlayRoute, port, overlayIPs) from the NIC, then
// translates each policy whose interfaceSelector matches the NIC's labels into CompiledFwRules.
// The returned CompiledNIC has no Status set (caller fills that in if needed).
func Compile(nic *netv1.NetworkInterface, policies []netv1.NetworkPolicy) netv1.CompiledNIC {
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
			UnderlayRoute: nic.Status.UnderlayRoute,
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

	return compiled
}
