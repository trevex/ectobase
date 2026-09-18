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
	// Priority orders this policy against the other policies selecting the same interface: lower
	// wins. 0-65535; unset means 32768.
	Priority *int32
	// Ingress is the ordered list of ingress rules to apply to selected interfaces.
	Ingress []FirewallPolicyRule
	// Egress is the ordered list of egress rules to apply to selected interfaces.
	Egress []FirewallPolicyRule
}

// FirewallPolicyRule is a single allow/deny rule for ingress or egress traffic.
type FirewallPolicyRule struct {
	// CIDR is the source (ingress) or destination (egress) CIDR to match.
	CIDR string
	// Proto is the IP protocol to match ("TCP", "UDP", "ICMP", or "" for any). ICMP means the ICMP
	// of the CIDR's family.
	Proto string
	// Port is the destination port to match (0 = any). Requires Proto TCP or UDP.
	Port int32
	// EndPort, if set, makes the rule match the inclusive destination-port range Port-EndPort.
	EndPort *int32
	// ICMPType restricts an ICMP rule to one message type; unset matches every type.
	ICMPType *int32
	// ICMPCode restricts the rule further to one code of ICMPType; unset matches every code.
	ICMPCode *int32
	// Action is "Allow" or "Deny".
	Action string
	// Priority orders this rule against the other rules of equally-prioritized policies: lower
	// wins. 0-65535; unset means 32768.
	Priority *int32
}

// FirewallPolicyStatus is the observed state of a FirewallPolicy. Intentionally empty: the outcome
// of compiling a policy is reported per interface, on the NetworkInterface's FirewallCompiled
// condition.
type FirewallPolicyStatus struct {
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FirewallPolicy is a set of prioritized allow/deny rules applied to the NetworkInterfaces its
// selector matches; the distributed firewall enforces it per interface in the datapath.
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
