// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FirewallPolicySpec is the desired state of a FirewallPolicy.
type FirewallPolicySpec struct {
	// InterfaceSelector selects the NetworkInterfaces this policy applies to via label matching.
	InterfaceSelector *metav1.LabelSelector
	// Ingress is the ordered list of ingress rules to apply to selected interfaces.
	Ingress []FirewallPolicyRule
	// Egress is the ordered list of egress rules to apply to selected interfaces.
	Egress []FirewallPolicyRule
}

// FirewallPolicyRule is a single allow/deny rule for ingress or egress traffic.
type FirewallPolicyRule struct {
	// CIDR is the source (ingress) or destination (egress) CIDR to match.
	CIDR string
	// Proto is the IP protocol to match ("TCP", "UDP", "ICMP", or "" for any).
	Proto string
	// Port is the destination port to match (0 = any).
	Port int32
	// Action is "Allow" or "Deny".
	Action string
}

// FirewallPolicyStatus is the observed state of a FirewallPolicy.
//
// SCAFFOLD ONLY: intentionally empty.
type FirewallPolicyStatus struct {
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FirewallPolicy is a scaffold-only resource. Selector-based distributed firewall (§3.4).
type FirewallPolicy struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   FirewallPolicySpec
	Status FirewallPolicyStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FirewallPolicyList is a list of FirewallPolicy objects.
type FirewallPolicyList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []FirewallPolicy
}
