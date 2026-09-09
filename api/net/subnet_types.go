// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SubnetSpec is the desired state of a Subnet (a VPC-scoped v4/v6 prefix range).
type SubnetSpec struct {
	// VPCRef references the owning VPC within the same namespace.
	VPCRef LocalObjectReference
	// V4Prefix optionally pins the IPv4 CIDR for this subnet.
	V4Prefix *string
	// V6Prefix optionally pins the IPv6 CIDR for this subnet.
	V6Prefix *string
	// ReservedIPs are addresses held back from allocation within this subnet.
	ReservedIPs []string
}

// SubnetStatus is the observed state of a Subnet.
type SubnetStatus struct {
	// State is the current lifecycle state (e.g. Pending, Ready).
	State string
	// V4Used is the number of allocated IPv4 addresses.
	V4Used int32
	// V4Total is the total number of allocatable IPv4 addresses.
	V4Total int32
	// V6Used is the number of allocated IPv6 addresses.
	V6Used int32
	// V6Total is the total number of allocatable IPv6 addresses.
	V6Total int32
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Subnet is a VPC-scoped range of IPv4/IPv6 prefixes.
type Subnet struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   SubnetSpec
	Status SubnetStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SubnetList is a list of Subnet objects.
type SubnetList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []Subnet
}
