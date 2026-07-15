// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkPolicySpec is the desired state of a NetworkPolicy.
type NetworkPolicySpec struct {
	// InterfaceSelector selects the NetworkInterfaces this policy applies to via label matching.
	// +optional
	InterfaceSelector *metav1.LabelSelector `json:"interfaceSelector,omitempty"`
	// Ingress is the ordered list of ingress rules to apply to selected interfaces.
	// +optional
	Ingress []NetworkPolicyRule `json:"ingress,omitempty"`
	// Egress is the ordered list of egress rules to apply to selected interfaces.
	// +optional
	Egress []NetworkPolicyRule `json:"egress,omitempty"`
}

// NetworkPolicyRule is a single allow/deny rule for ingress or egress traffic.
type NetworkPolicyRule struct {
	// CIDR is the source (ingress) or destination (egress) CIDR to match.
	// "0.0.0.0/0" matches all addresses.
	CIDR string `json:"cidr"`
	// Proto is the IP protocol to match ("TCP", "UDP", "ICMP", or "" for any).
	// +optional
	Proto string `json:"proto,omitempty"`
	// Port is the destination port to match (0 = any).
	// +optional
	Port int32 `json:"port,omitempty"`
	// Action is "Allow" or "Deny".
	Action string `json:"action"`
}

// NetworkPolicyStatus is the observed state of a NetworkPolicy.
//
// SCAFFOLD ONLY: intentionally empty.
type NetworkPolicyStatus struct {
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NetworkPolicy is a scaffold-only resource. Selector-based distributed firewall (§3.4).
type NetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   NetworkPolicySpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status NetworkPolicyStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyList is a list of NetworkPolicy objects.
type NetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []NetworkPolicy `json:"items" protobuf:"bytes,2,rep,name=items"`
}
