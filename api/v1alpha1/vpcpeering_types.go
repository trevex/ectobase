// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VPCPeeringSpec is the desired state of a VPCPeering.
//
// SCAFFOLD ONLY: intentionally empty. Mutual-consent VPC peering (§3.3).
// Fleshed out in a later plan (YAGNI here).
type VPCPeeringSpec struct {
}

// VPCPeeringStatus is the observed state of a VPCPeering.
//
// SCAFFOLD ONLY: intentionally empty.
type VPCPeeringStatus struct {
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCPeering is a scaffold-only resource. Mutual-consent VPC peering (§3.3).
type VPCPeering struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   VPCPeeringSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status VPCPeeringStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCPeeringList is a list of VPCPeering objects.
type VPCPeeringList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []VPCPeering `json:"items" protobuf:"bytes,2,rep,name=items"`
}
