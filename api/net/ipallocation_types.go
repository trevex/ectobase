// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IPAllocationSpec is the desired state of an IPAllocation. There is no status: the
// object's EXISTENCE is the state, and its name — derived from (pool, address) — is what
// makes Create a compare-and-swap.
type IPAllocationSpec struct {
	// PoolRef is the IPPool this address came from.
	PoolRef LocalObjectReference
	// Address is the allocated address, canonical form.
	Address string
	// ConsumerRef records who asked for it, for humans and diagnostics. The authoritative
	// lifetime link is the ownerReference, not this field.
	ConsumerRef TypedLocalObjectReference
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPAllocation is one address held out of one IPPool.
type IPAllocation struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec IPAllocationSpec
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPAllocationList is a list of IPAllocation objects.
type IPAllocationList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []IPAllocation
}
