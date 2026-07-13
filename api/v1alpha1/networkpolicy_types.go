// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkPolicySpec is the desired state of a NetworkPolicy.
//
// SCAFFOLD ONLY: intentionally empty. Selector-based distributed firewall (§3.4).
// Fleshed out in a later plan (YAGNI here).
type NetworkPolicySpec struct {
}

// NetworkPolicyStatus is the observed state of a NetworkPolicy.
//
// SCAFFOLD ONLY: intentionally empty.
type NetworkPolicyStatus struct {
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

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
