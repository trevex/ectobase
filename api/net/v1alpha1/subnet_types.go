// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SubnetSpec is the desired state of a Subnet (a VPC-scoped v4/v6 prefix range).
type SubnetSpec struct {
	// VPCRef references the owning VPC within the same namespace.
	VPCRef LocalObjectReference `json:"vpcRef" protobuf:"bytes,1,opt,name=vpcRef"`
	// V4Prefix optionally pins the IPv4 CIDR for this subnet.
	// +optional
	V4Prefix *string `json:"v4Prefix,omitempty" protobuf:"bytes,2,opt,name=v4Prefix"`
	// V6Prefix optionally pins the IPv6 CIDR for this subnet.
	// +optional
	V6Prefix *string `json:"v6Prefix,omitempty" protobuf:"bytes,3,opt,name=v6Prefix"`
	// ReservedIPs are addresses held back from allocation within this subnet.
	// +optional
	ReservedIPs []string `json:"reservedIPs,omitempty" protobuf:"bytes,4,rep,name=reservedIPs"`
}

// SubnetStatus is the observed state of a Subnet.
type SubnetStatus struct {
	// State is the current lifecycle state (e.g. Pending, Ready).
	// +optional
	State string `json:"state,omitempty" protobuf:"bytes,1,opt,name=state"`
	// V4Total is the total number of allocatable IPv4 addresses.
	// +optional
	V4Total int32 `json:"v4Total,omitempty" protobuf:"varint,3,opt,name=v4Total"`
	// V6Total is the total number of allocatable IPv6 addresses.
	// +optional
	V6Total int32 `json:"v6Total,omitempty" protobuf:"varint,5,opt,name=v6Total"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Subnet is a VPC-scoped range of IPv4/IPv6 prefixes.
type Subnet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   SubnetSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status SubnetStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SubnetList is a list of Subnet objects.
type SubnetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []Subnet `json:"items" protobuf:"bytes,2,rep,name=items"`
}
