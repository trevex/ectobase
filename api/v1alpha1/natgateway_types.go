// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NATGatewaySpec is the desired state of a NATGateway: a drain-safe egress SNAT
// for the sources in a VPC, using deterministic (public-IP, port-block) allocation.
type NATGatewaySpec struct {
	// VPCRef selects the VPC whose interfaces egress through this gateway.
	VPCRef LocalObjectReference `json:"vpcRef" protobuf:"bytes,1,opt,name=vpcRef"`
	// PublicIPs is the pool of public IPv4s SNAT sources are mapped onto.
	PublicIPs []string `json:"publicIPs,omitempty" protobuf:"bytes,2,rep,name=publicIPs"`
	// PortsPerSource is the deterministic port-block size handed to each source
	// (RFC 7422 / GCP-static style). Default 1024.
	// +optional
	PortsPerSource *int32 `json:"portsPerSource,omitempty" protobuf:"varint,3,opt,name=portsPerSource"`
	// EdgeUnderlay is DEPRECATED and IGNORED. The edge fleet self-advertises via
	// EDGE_UNDERLAY: egress (0.0.0.0/0 and 64:ff9b::/96 for NAT64) is originated by
	// any agent started with --edge-loopback, nexthop'd at that edge's own anycast
	// underlay. Retained only to avoid a CRD breaking change; set nothing here.
	// +optional
	EdgeUnderlay string `json:"edgeUnderlay,omitempty" protobuf:"bytes,4,opt,name=edgeUnderlay"`
}

// NATAllocation records one source's deterministic mapping.
type NATAllocation struct {
	// Source is the overlay IP (a NetworkInterface IP) being SNATed.
	Source string `json:"source" protobuf:"bytes,1,opt,name=source"`
	// PublicIP + [PortMin,PortMax] is the deterministic block.
	PublicIP string `json:"publicIP" protobuf:"bytes,2,opt,name=publicIP"`
	PortMin  int32  `json:"portMin" protobuf:"varint,3,opt,name=portMin"`
	PortMax  int32  `json:"portMax" protobuf:"varint,4,opt,name=portMax"`
}

// NATGatewayStatus is the observed state.
type NATGatewayStatus struct {
	// Allocations is the deterministic source→block table (published to all gateways).
	// +optional
	Allocations []NATAllocation `json:"allocations,omitempty" protobuf:"bytes,1,rep,name=allocations"`
	// +optional
	State string `json:"state,omitempty" protobuf:"bytes,2,opt,name=state"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NATGateway is a drain-safe egress SNAT for the sources in a VPC, using
// deterministic (public-IP, port-block) allocation.
type NATGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   NATGatewaySpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status NATGatewayStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NATGatewayList is a list of NATGateway objects.
type NATGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []NATGateway `json:"items" protobuf:"bytes,2,rep,name=items"`
}
