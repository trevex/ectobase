// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LBPoolSpec is the desired state of an LBPool (a fleet-scoped VIP prefix range).
type LBPoolSpec struct {
	// V4Prefix optionally pins the IPv4 CIDR for this VIP pool.
	V4Prefix *string
	// V6Prefix optionally pins the IPv6 CIDR for this VIP pool.
	V6Prefix *string
	// ReservedIPs are addresses held back from allocation within this pool.
	ReservedIPs []string
}

// LBPoolStatus is the observed state of an LBPool.
type LBPoolStatus struct {
	// State is the current lifecycle state (e.g. Pending, Ready).
	State string
	// Total is the total number of allocatable VIP addresses.
	Total int32
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LBPool is a fleet-scoped range of IPv4/IPv6 VIP prefixes.
type LBPool struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   LBPoolSpec
	Status LBPoolStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LBPoolList is a list of LBPool objects.
type LBPoolList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []LBPool
}
