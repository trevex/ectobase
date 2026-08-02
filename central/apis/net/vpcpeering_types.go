// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VPCReference references a VPC by namespace + name.
type VPCReference struct {
	Namespace string
	Name      string
}

// VPCPeeringSpec is the desired state of a one-directional VPC peering.
type VPCPeeringSpec struct {
	// VPCRef is this side's VPC (same namespace as this VPCPeering object).
	VPCRef LocalObjectReference
	// PeerVPCRef references the other VPC (namespace + name).
	PeerVPCRef VPCReference
	// ExposedPrefixes is the CIDR allow-list THIS side offers to the peer.
	ExposedPrefixes []string
}

// VPCPeeringStatus is the observed state of a VPCPeering.
type VPCPeeringStatus struct {
	// State is the peering lifecycle: Pending, Ready, or Invalid.
	State string
	// Message is a human-readable reason for the current State.
	Message string
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCPeering is one direction of a mutual-consent VPC peering.
type VPCPeering struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   VPCPeeringSpec
	Status VPCPeeringStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCPeeringList is a list of VPCPeering objects.
type VPCPeeringList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []VPCPeering
}
