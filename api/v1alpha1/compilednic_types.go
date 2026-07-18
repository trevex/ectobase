// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledNICSpec is the fully lowered, node-local NIC configuration bundle.
// It captures everything the dataplane agent needs for a single NIC: identity,
// underlay, firewall rules (resolved from NetworkPolicy selectors), and NAT block.
// Dynamic routes learned via routebus are NOT included here.
type CompiledNICSpec struct {
	// NodeName is the node this NIC is scheduled on.
	NodeName string `json:"nodeName"`
	// NICRef references the source NetworkInterface by name.
	NICRef LocalObjectReference `json:"nicRef"`
	// VNI is the effective VXLAN network identifier for this NIC.
	VNI int32 `json:"vni"`
	// Port describes the dataplane port allocated for this interface.
	Port PortStatus `json:"port"`
	// OverlayIPs are the guest overlay IP addresses.
	// +optional
	OverlayIPs []string `json:"overlayIPs,omitempty"`
	// Firewall holds the compiled ingress and egress firewall rules.
	Firewall CompiledFirewall `json:"firewall"`
	// NAT holds NAT gateway config for this NIC, if any.
	// +optional
	NAT *CompiledNAT `json:"nat,omitempty"`
	// LB lists the load balancers this NIC is a backend of. Pure forwarding membership —
	// it grants NO firewall permission (that comes solely from NetworkPolicy).
	// +optional
	LB []CompiledLB `json:"lb,omitempty"`
	// PeerImports lists peer VPCs whose routes this NIC imports (reachability only — grants NO
	// firewall permission; that comes solely from NetworkPolicy). Populated from Ready VPCPeerings
	// involving this NIC's VPC.
	// +optional
	PeerImports []CompiledPeerImport `json:"peerImports,omitempty"`
}

// CompiledFirewall holds pre-compiled ingress and egress rules for a NIC.
type CompiledFirewall struct {
	// Ingress is the ordered list of ingress firewall rules.
	// +optional
	Ingress []CompiledFwRule `json:"ingress,omitempty"`
	// Egress is the ordered list of egress firewall rules.
	// +optional
	Egress []CompiledFwRule `json:"egress,omitempty"`
}

// CompiledFwRule is a single compiled firewall rule (destination CIDR + proto + port + action).
type CompiledFwRule struct {
	// CIDR is the destination CIDR to match ("0.0.0.0/0" = any).
	CIDR string `json:"cidr"`
	// Proto is the IP protocol ("TCP", "UDP", "ICMP", or "" for any).
	// +optional
	Proto string `json:"proto,omitempty"`
	// Port is the destination port (0 = any).
	// +optional
	Port int32 `json:"port,omitempty"`
	// Action is the rule action: "Allow" or "Deny".
	Action string `json:"action"`
}

// CompiledNAT holds the NAT gateway configuration for this NIC.
type CompiledNAT struct {
	// NATIP is the public NAT IPv4 address.
	NATIP string `json:"natIP"`
	// PortMin is the start of the source-port range (inclusive).
	PortMin int32 `json:"portMin"`
	// PortMax is the end of the source-port range (inclusive).
	PortMax int32 `json:"portMax"`
}

// CompiledLB is one load-balancer this NIC backs: the VIP (v4 or v6) and its service ports.
type CompiledLB struct {
	// VIP is the load-balancer virtual IP (IPv4 or IPv6).
	VIP string `json:"vip"`
	// Ports are the LB service (port, proto) tuples.
	// +optional
	Ports []CompiledLBPort `json:"ports,omitempty"`
}

// CompiledLBPort is one LB service tuple.
type CompiledLBPort struct {
	Port  int32  `json:"port"`
	Proto string `json:"proto"`
}

// CompiledPeerImport is one peer VPC's reachability import for a NIC.
type CompiledPeerImport struct {
	// PeerVNI is the peer VPC's VNI to subscribe to on routebus.
	PeerVNI int32 `json:"peerVni"`
	// ImportPrefixes is the peer's exposedPrefixes: only peer routes within these CIDRs are
	// imported (filter applied importer-side).
	// +optional
	ImportPrefixes []string `json:"importPrefixes,omitempty"`
}

// CompiledNICStatus is the observed state of a CompiledNIC.
type CompiledNICStatus struct {
	// State is the current lifecycle state (e.g. Applied, Pending).
	// +optional
	State string `json:"state,omitempty"`
	// GenerationApplied is the ObjectMeta.Generation of the CompiledNIC last applied.
	// +optional
	GenerationApplied int64 `json:"generationApplied,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// CompiledNIC is a lowered, node-local bundle of all static per-NIC dataplane config.
// It is produced by the Compile() function from a NetworkInterface + matching NetworkPolicies.
type CompiledNIC struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CompiledNICSpec   `json:"spec,omitempty"`
	Status CompiledNICStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledNICList is a list of CompiledNIC objects.
type CompiledNICList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CompiledNIC `json:"items"`
}
