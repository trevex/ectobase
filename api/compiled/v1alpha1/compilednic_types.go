// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledNICSpec is the fully lowered per-NIC STATIC POLICY the control plane hands to a node:
// identity, VNI, overlay IPs, firewall rules (resolved from FirewallPolicy selectors), egress-SNAT
// allocations, LB membership, and peer imports — derived from the NetworkInterface + VPC +
// FirewallPolicy + LoadBalancer + NATGateway + VPCPeering so the agent never reads those directly.
//
// The source NetworkInterface is the CompiledNIC's OWNER (a controller ownerReference) and its name
// is encoded in the object name — so the spec carries no NICRef. It also deliberately does NOT carry
// the NIC's underlay /128: that is node-local state the dataplane allocates at attach, and the agent
// obtains it from the local DataplaneNode (ListInterfaces) to announce overlay routes with the
// correct node-local nexthop. Keeping node-local state out of this central object avoids a
// compile->sync round-trip that would lag (and flap) the announced nexthop.
type CompiledNICSpec struct {
	// ClusterName is the cluster this compiled NIC is bound to (the pod->node
	// binding). Set by the compiler from the owning VirtualMachine's placement,
	// or the compiler's --cluster-name default for NICs with no owning VM.
	// The per-cluster broker selects on this field.
	// +optional
	ClusterName string `json:"clusterName,omitempty"`
	// VNI is the effective VXLAN network identifier for this NIC (resolved from the NIC's
	// status.vni, falling back to its VPC's status.vni).
	VNI int32 `json:"vni"`
	// Port describes the dataplane port allocated for this interface.
	Port PortStatus `json:"port"`
	// OverlayIPs are the guest overlay IP addresses.
	// +optional
	OverlayIPs []string `json:"overlayIPs,omitempty"`
	// Firewall holds the compiled ingress and egress firewall rules.
	Firewall CompiledFirewall `json:"firewall"`
	// NAT lists the egress-SNAT sources for this NIC's overlay IPs — one entry per NATGateway
	// allocation whose source is one of this NIC's IPs. Empty if the NIC's VPC has no NAT gateway.
	// +optional
	NAT []CompiledNATSource `json:"nat,omitempty"`
	// LB lists the load balancers this NIC is a backend of. Pure forwarding membership —
	// it grants NO firewall permission (that comes solely from FirewallPolicy).
	// +optional
	LB []CompiledLB `json:"lb,omitempty"`
	// PeerImports lists peer VPCs whose routes this NIC imports (reachability only — grants NO
	// firewall permission; that comes solely from FirewallPolicy). Populated from Ready VPCPeerings
	// involving this NIC's VPC.
	// +optional
	PeerImports []CompiledPeerImport `json:"peerImports,omitempty"`
	// MAC is the guest L2 address copied from the source NetworkInterface. The CNI
	// programs it as the datapath guest MAC (empty for containers — the datapath derives one).
	// +optional
	MAC string `json:"mac,omitempty"`
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

// CompiledNATSource is one egress-SNAT mapping: an overlay source IP SNATed onto a public NAT IP
// and source-port range. It corresponds to a single NATGateway allocation for one of the NIC's IPs.
type CompiledNATSource struct {
	// SourceIP is the overlay IP being SNATed (one of the NIC's OverlayIPs).
	SourceIP string `json:"sourceIP"`
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
