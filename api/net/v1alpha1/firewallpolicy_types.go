// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Firewall rule priorities, GCP-style: an integer in [FirewallPriorityMin, FirewallPriorityMax],
// lower wins. An unset priority means FirewallPriorityDefault, the midpoint, so a policy or rule can
// be placed ahead of or behind every unprioritized one.
const (
	FirewallPriorityMin     int32 = 0
	FirewallPriorityMax     int32 = 65535
	FirewallPriorityDefault int32 = 32768
)

// FirewallPolicySpec is the desired state of a FirewallPolicy.
type FirewallPolicySpec struct {
	// InterfaceSelector selects the NetworkInterfaces this policy applies to via label matching.
	// +optional
	InterfaceSelector *metav1.LabelSelector `json:"interfaceSelector,omitempty"`
	// Priority orders this policy against the other policies selecting the same interface: lower
	// wins. 0-65535; unset means 32768. Policies of equal priority are ordered by their rules'
	// priorities, then by policy name.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	Priority *int32 `json:"priority,omitempty"`
	// Ingress is the ordered list of ingress rules to apply to selected interfaces.
	// +optional
	Ingress []FirewallPolicyRule `json:"ingress,omitempty"`
	// Egress is the ordered list of egress rules to apply to selected interfaces.
	// +optional
	Egress []FirewallPolicyRule `json:"egress,omitempty"`
}

// FirewallPolicyRule is a single allow/deny rule for ingress or egress traffic.
type FirewallPolicyRule struct {
	// CIDR is the source (ingress) or destination (egress) CIDR to match.
	// "0.0.0.0/0" matches all IPv4 addresses, "::/0" all IPv6 addresses.
	CIDR string `json:"cidr"`
	// Proto is the IP protocol to match ("TCP", "UDP", "ICMP", or "" for any). ICMP means the ICMP
	// of the CIDR's family (ICMPv6 for an IPv6 CIDR).
	// +optional
	// +kubebuilder:validation:Enum=TCP;UDP;ICMP
	Proto string `json:"proto,omitempty"`
	// Port is the destination port to match (0 = any). Requires Proto TCP or UDP.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`
	// Action is "Allow" or "Deny".
	// +kubebuilder:validation:Enum=Allow;Deny
	Action string `json:"action"`
	// Priority orders this rule against the other rules of equally-prioritized policies: lower
	// wins. 0-65535; unset means 32768. Rules of equal priority keep their list order.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	Priority *int32 `json:"priority,omitempty"`
}

// FirewallPolicyStatus is the observed state of a FirewallPolicy. Intentionally empty: the outcome
// of compiling a policy is reported per interface, on the NetworkInterface's FirewallCompiled
// condition.
type FirewallPolicyStatus struct {
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=fwpol

// FirewallPolicy is a set of prioritized allow/deny rules applied to the NetworkInterfaces its
// selector matches; the distributed firewall enforces it per interface in the datapath.
type FirewallPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   FirewallPolicySpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status FirewallPolicyStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FirewallPolicyList is a list of FirewallPolicy objects.
type FirewallPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []FirewallPolicy `json:"items" protobuf:"bytes,2,rep,name=items"`
}
