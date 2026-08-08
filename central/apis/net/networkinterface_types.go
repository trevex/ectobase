// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkInterfaceSpec is the desired state of a NetworkInterface (a thin NIC).
type NetworkInterfaceSpec struct {
	// VPCRef references the VPC this interface belongs to.
	VPCRef LocalObjectReference
	// IPs are the user-specified overlay IPs (v4 and/or v6).
	IPs []string
	// MAC is the interface's L2 address.
	MAC string
	// NodeName is the node the interface is scheduled onto.
	NodeName *string
	// QoS caps/shapes throughput for this interface. Nil = unlimited.
	QoS *InterfaceQoS
	// ClusterName is the compute cluster this standalone (e.g. Pod) NIC targets.
	ClusterName string
}

// InterfaceQoS is per-interface traffic control.
type InterfaceQoS struct {
	// Egress shapes outbound (VM->out) throughput.
	Egress *EgressQoS
	// Ingress polices inbound (out->VM) throughput.
	Ingress *RateLimit
}

// EgressQoS shapes total egress (EDT) with an optional external sub-cap.
type EgressQoS struct {
	// RateMbps is the EDT-shaped total egress rate in Mbit/s. 0 = unlimited.
	RateMbps uint32
	// BurstKB is an optional burst allowance in KB.
	BurstKB uint32
	// PublicMbps caps external/NATed egress in Mbit/s (policed). 0 = unlimited.
	PublicMbps uint32
}

// RateLimit is a token-bucket policing cap.
type RateLimit struct {
	// RateMbps caps throughput in Mbit/s. 0 = unlimited.
	RateMbps uint32
	// BurstKB is an optional burst allowance in KB.
	BurstKB uint32
}

// NetworkInterfaceStatus is the observed state of a NetworkInterface.
type NetworkInterfaceStatus struct {
	// VNI is the effective VXLAN network identifier resolved from the VPC.
	VNI int32
	// UnderlayRoute is the allocated underlay /128 from the host's underlay /64.
	UnderlayRoute string
	// Port describes the dataplane port allocated for this interface.
	Port *PortStatus
	// State is the current lifecycle state (e.g. Pending, Ready).
	State string
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkInterface is a thin NIC attached to a VM: identity plus user-specified overlay IPs.
type NetworkInterface struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   NetworkInterfaceSpec
	Status NetworkInterfaceStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkInterfaceList is a list of NetworkInterface objects.
type NetworkInterfaceList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []NetworkInterface
}
