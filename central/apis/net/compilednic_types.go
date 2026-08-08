// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledNICSpec is the fully lowered per-NIC STATIC POLICY the control plane hands to a node.
type CompiledNICSpec struct {
	// ClusterName is the cluster this compiled NIC is bound to. The per-cluster broker selects on this field.
	ClusterName string
	// NodeName is the node this NIC is scheduled on.
	NodeName string
	// VNI is the effective VXLAN network identifier for this NIC.
	VNI int32
	// Port describes the dataplane port allocated for this interface.
	Port PortStatus
	// OverlayIPs are the guest overlay IP addresses.
	OverlayIPs []string
	// Firewall holds the compiled ingress and egress firewall rules.
	Firewall CompiledFirewall
	// NAT lists the egress-SNAT sources for this NIC's overlay IPs.
	NAT []CompiledNATSource
	// LB lists the load balancers this NIC is a backend of.
	LB []CompiledLB
	// PeerImports lists peer VPCs whose routes this NIC imports.
	PeerImports []CompiledPeerImport
	// MAC is the guest L2 address copied from the source NetworkInterface.
	MAC string
}

// CompiledFirewall holds pre-compiled ingress and egress rules for a NIC.
type CompiledFirewall struct {
	// Ingress is the ordered list of ingress firewall rules.
	Ingress []CompiledFwRule
	// Egress is the ordered list of egress firewall rules.
	Egress []CompiledFwRule
}

// CompiledFwRule is a single compiled firewall rule.
type CompiledFwRule struct {
	// CIDR is the destination CIDR to match ("0.0.0.0/0" = any).
	CIDR string
	// Proto is the IP protocol ("TCP", "UDP", "ICMP", or "" for any).
	Proto string
	// Port is the destination port (0 = any).
	Port int32
	// Action is the rule action: "Allow" or "Deny".
	Action string
}

// CompiledNATSource is one egress-SNAT mapping.
type CompiledNATSource struct {
	// SourceIP is the overlay IP being SNATed (one of the NIC's OverlayIPs).
	SourceIP string
	// NATIP is the public NAT IPv4 address.
	NATIP string
	// PortMin is the start of the source-port range (inclusive).
	PortMin int32
	// PortMax is the end of the source-port range (inclusive).
	PortMax int32
}

// CompiledLB is one load-balancer this NIC backs.
type CompiledLB struct {
	// VIP is the load-balancer virtual IP (IPv4 or IPv6).
	VIP string
	// Ports are the LB service (port, proto) tuples.
	Ports []CompiledLBPort
}

// CompiledLBPort is one LB service tuple.
type CompiledLBPort struct {
	Port  int32
	Proto string
}

// CompiledPeerImport is one peer VPC's reachability import for a NIC.
type CompiledPeerImport struct {
	// PeerVNI is the peer VPC's VNI to subscribe to on routebus.
	PeerVNI int32
	// ImportPrefixes is the peer's exposedPrefixes.
	ImportPrefixes []string
}

// CompiledNICStatus is the observed state of a CompiledNIC.
type CompiledNICStatus struct {
	// State is the current lifecycle state (e.g. Applied, Pending).
	State string
	// GenerationApplied is the ObjectMeta.Generation of the CompiledNIC last applied.
	GenerationApplied int64
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledNIC is a lowered, node-local bundle of all static per-NIC dataplane config.
type CompiledNIC struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   CompiledNICSpec
	Status CompiledNICStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledNICList is a list of CompiledNIC objects.
type CompiledNICList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []CompiledNIC
}
