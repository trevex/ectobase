// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VPCReference references a VPC by namespace + name (peering may be cross-namespace,
// since it is central-authored).
type VPCReference struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// VPCPeeringSpec is the desired state of a one-directional VPC peering. A mutual peering
// is formed by a reciprocal pair (A→B and B→A). Reachability only — never a firewall grant.
type VPCPeeringSpec struct {
	// VPCRef is this side's VPC (same namespace as this VPCPeering object).
	VPCRef LocalObjectReference `json:"vpcRef"`
	// PeerVPCRef references the other VPC (namespace + name).
	PeerVPCRef VPCReference `json:"peerVpcRef"`
	// ExposedPrefixes is the CIDR allow-list THIS side offers to the peer: only local routes
	// within these CIDRs become reachable to the peer VPC. Empty = expose nothing (fail-closed).
	// +optional
	ExposedPrefixes []string `json:"exposedPrefixes,omitempty"`
}

// VPCPeeringStatus is the observed state of a VPCPeering.
type VPCPeeringStatus struct {
	// State is the peering lifecycle: Pending (awaiting the reciprocal), Ready (both sides
	// consent), or Invalid (validation failed).
	// +optional
	State string `json:"state,omitempty"`
	// Message is a human-readable reason for the current State.
	// +optional
	Message string `json:"message,omitempty"`
}

// Peering state constants.
const (
	VPCPeeringPending = "Pending"
	VPCPeeringReady   = "Ready"
	VPCPeeringInvalid = "Invalid"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VPCPeering is one direction of a mutual-consent VPC peering; a reciprocal pair (A→B and B→A)
// forms an active peering. Reachability only — it grants no firewall permission.
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
