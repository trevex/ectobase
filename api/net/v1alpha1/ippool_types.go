// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IPPoolType is what the addresses in a pool are for. A consumer states the type it needs and is
// refused a pool of any other type, so an internal range can never be handed out as a public NAT
// or LB address.
// +kubebuilder:validation:Enum=public;internal
type IPPoolType string

const (
	// IPPoolTypePublic is an internet-routable range: NAT gateway addresses, LB addresses.
	IPPoolTypePublic IPPoolType = "public"
	// IPPoolTypeInternal is a range that never leaves the fabric (e.g. internal LBs).
	IPPoolTypeInternal IPPoolType = "internal"
)

// IPPoolSpec is the desired state of an IPPool (a fleet-scoped address range).
type IPPoolSpec struct {
	// Type is what the addresses in this pool are for.
	Type IPPoolType `json:"type" protobuf:"bytes,1,opt,name=type,casttype=IPPoolType"`
	// V4Prefix optionally pins the IPv4 CIDR for this pool.
	// +optional
	V4Prefix *string `json:"v4Prefix,omitempty" protobuf:"bytes,2,opt,name=v4Prefix"`
	// V6Prefix optionally pins the IPv6 CIDR for this pool.
	// +optional
	V6Prefix *string `json:"v6Prefix,omitempty" protobuf:"bytes,3,opt,name=v6Prefix"`
	// ReservedIPs are addresses held back from allocation within this pool.
	// +optional
	ReservedIPs []string `json:"reservedIPs,omitempty" protobuf:"bytes,4,rep,name=reservedIPs"`
}

// IPPoolStatus is the observed state of an IPPool.
type IPPoolStatus struct {
	// State is the current lifecycle state: Pending, Ready, Invalid or Conflict.
	// +optional
	State string `json:"state,omitempty" protobuf:"bytes,1,opt,name=state"`
	// Total is the number of allocatable addresses across this pool's prefixes.
	// +optional
	Total int32 `json:"total,omitempty" protobuf:"varint,2,opt,name=total"`
	// Allocated is how many IPAllocations currently name this pool. A convenience for
	// operators, derived on each sync — never the source of truth for what is free.
	// +optional
	Allocated int32 `json:"allocated,omitempty" protobuf:"varint,3,opt,name=allocated"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// IPPool is a fleet-scoped, typed range of IPv4/IPv6 prefixes that any consumer
// (LoadBalancer, NATGateway, ...) allocates addresses from.
type IPPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   IPPoolSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status IPPoolStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPPoolList is a list of IPPool objects.
type IPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []IPPool `json:"items" protobuf:"bytes,2,rep,name=items"`
}
