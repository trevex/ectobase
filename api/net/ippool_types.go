// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IPPoolSpec is the desired state of an IPPool (a fleet-scoped address range).
type IPPoolSpec struct {
	// Type is what the addresses in this pool are for ("public" or "internal").
	// Kubebuilder enum markers live only in v1alpha1; conversion-gen casts.
	Type string
	// V4Prefix optionally pins the IPv4 CIDR for this pool.
	V4Prefix *string
	// V6Prefix optionally pins the IPv6 CIDR for this pool.
	V6Prefix *string
	// ReservedIPs are addresses held back from allocation within this pool.
	ReservedIPs []string
}

// IPPoolStatus is the observed state of an IPPool.
type IPPoolStatus struct {
	// State is the current lifecycle state: Pending, Ready, Invalid or Conflict.
	State string
	// Total is the number of allocatable addresses across this pool's prefixes.
	Total int32
	// Allocated is how many IPAllocations currently name this pool.
	Allocated int32
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPPool is a fleet-scoped, typed range of IPv4/IPv6 prefixes that any consumer
// (LoadBalancer, NATGateway, ...) allocates addresses from.
type IPPool struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   IPPoolSpec
	Status IPPoolStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPPoolList is a list of IPPool objects.
type IPPoolList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []IPPool
}
