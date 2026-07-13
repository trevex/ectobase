// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NATGatewaySpec is the desired state of a NATGateway.
//
// SCAFFOLD ONLY: intentionally empty. Selector-membership NAT gateway (§3.6).
// Fleshed out in a later plan (YAGNI here).
type NATGatewaySpec struct {
}

// NATGatewayStatus is the observed state of a NATGateway.
//
// SCAFFOLD ONLY: intentionally empty.
type NATGatewayStatus struct {
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NATGateway is a scaffold-only resource. Selector-membership NAT gateway (§3.6).
type NATGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   NATGatewaySpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status NATGatewayStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NATGatewayList is a list of NATGateway objects.
type NATGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []NATGateway `json:"items" protobuf:"bytes,2,rep,name=items"`
}
