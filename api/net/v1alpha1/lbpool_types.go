// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LBPoolSpec is the desired state of an LBPool (a fleet-scoped VIP prefix range).
type LBPoolSpec struct {
	// V4Prefix optionally pins the IPv4 CIDR for this VIP pool.
	// +optional
	V4Prefix *string `json:"v4Prefix,omitempty" protobuf:"bytes,1,opt,name=v4Prefix"`
	// V6Prefix optionally pins the IPv6 CIDR for this VIP pool.
	// +optional
	V6Prefix *string `json:"v6Prefix,omitempty" protobuf:"bytes,2,opt,name=v6Prefix"`
	// ReservedIPs are addresses held back from allocation within this pool.
	// +optional
	ReservedIPs []string `json:"reservedIPs,omitempty" protobuf:"bytes,3,rep,name=reservedIPs"`
}

// LBPoolStatus is the observed state of an LBPool.
type LBPoolStatus struct {
	// State is the current lifecycle state (e.g. Pending, Ready).
	// +optional
	State string `json:"state,omitempty" protobuf:"bytes,1,opt,name=state"`
	// Total is the total number of allocatable VIP addresses.
	// +optional
	Total int32 `json:"total,omitempty" protobuf:"varint,3,opt,name=total"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// LBPool is a fleet-scoped range of IPv4/IPv6 VIP prefixes.
type LBPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   LBPoolSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status LBPoolStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LBPoolList is a list of LBPool objects.
type LBPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []LBPool `json:"items" protobuf:"bytes,2,rep,name=items"`
}
