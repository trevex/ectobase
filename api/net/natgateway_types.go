// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NATGatewaySpec is the desired state of a NATGateway.
type NATGatewaySpec struct {
	// VPCRef selects the VPC whose interfaces egress through this gateway.
	VPCRef LocalObjectReference
	// PublicIPs PINS addresses within PoolRef; it is no longer the pool itself.
	PublicIPs []string
	// PoolRef selects the IPPool to draw public addresses from.
	PoolRef LocalObjectReference
	// PortsPerSource is the deterministic port-block size handed to each source.
	PortsPerSource *int32
	// EdgeUnderlay is DEPRECATED and IGNORED.
	EdgeUnderlay string
}

// NATAllocation records one source's deterministic mapping.
type NATAllocation struct {
	// Source is the overlay IP (a NetworkInterface IP) being SNATed.
	Source string
	// PublicIP + [PortMin,PortMax] is the deterministic block.
	PublicIP string
	PortMin  int32
	PortMax  int32
}

// NATGatewayStatus is the observed state.
type NATGatewayStatus struct {
	// Allocations is the deterministic source->block table.
	Allocations []NATAllocation
	State       string
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NATGateway is a drain-safe egress SNAT for the sources in a VPC.
type NATGateway struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   NATGatewaySpec
	Status NATGatewayStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NATGatewayList is a list of NATGateway objects.
type NATGatewayList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []NATGateway
}
