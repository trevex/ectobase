// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkInterfaceSpec is the desired state of a NetworkInterface (a thin NIC).
type NetworkInterfaceSpec struct {
	// VPCRef references the VPC this interface belongs to.
	VPCRef LocalObjectReference `json:"vpcRef" protobuf:"bytes,1,opt,name=vpcRef"`
	// IPs are the user-specified overlay IPs (v4 and/or v6). The platform does
	// not allocate these.
	// +optional
	IPs []string `json:"ips,omitempty" protobuf:"bytes,2,rep,name=ips"`
	// MAC is the interface's L2 address. REQUIRED for a KubeVirt VM (device_type
	// pod-tap/tap): the datapath programs this as the guest MAC, and the VMI's
	// spec.domain.devices.interfaces[].macAddress MUST be set to the same value so
	// KubeVirt gives the VM's virtio NIC that MAC. Empty for containers (derived).
	// +optional
	MAC string `json:"mac,omitempty" protobuf:"bytes,5,opt,name=mac"`
	// NodeName is the node the interface is scheduled onto. Set by the scheduler.
	// +optional
	NodeName *string `json:"nodeName,omitempty" protobuf:"bytes,3,opt,name=nodeName"`
	// QoS caps/shapes throughput for this interface. Nil = unlimited.
	// +optional
	QoS *InterfaceQoS `json:"qos,omitempty" protobuf:"bytes,4,opt,name=qos"`
	// ClusterName is the compute cluster this standalone (e.g. Pod) NIC targets. The
	// compiler uses it for placement (CompiledNIC.spec.clusterName) when no
	// VirtualMachine owns this NIC; an owning VM's placement takes precedence.
	// +optional
	ClusterName string `json:"clusterName,omitempty" protobuf:"bytes,6,opt,name=clusterName"`
}

// InterfaceQoS is per-interface traffic control. Egress is EDT-shaped (smoothed) at the uplink fq
// qdisc; ingress is token-bucket policed. Programmed into the dataplane via DataplaneNode/ConfigureQoS.
type InterfaceQoS struct {
	// Egress shapes outbound (VM->out) throughput.
	// +optional
	Egress *EgressQoS `json:"egress,omitempty" protobuf:"bytes,1,opt,name=egress"`
	// Ingress polices inbound (out->VM) throughput.
	// +optional
	Ingress *RateLimit `json:"ingress,omitempty" protobuf:"bytes,2,opt,name=ingress"`
}

// EgressQoS shapes total egress (EDT) with an optional external sub-cap.
type EgressQoS struct {
	// RateMbps is the EDT-shaped total egress rate in Mbit/s. 0 = unlimited.
	// +optional
	RateMbps uint32 `json:"rateMbps,omitempty" protobuf:"varint,1,opt,name=rateMbps"`
	// BurstKB is an optional burst allowance in KB. Reserved (EDT ignores it in v1). 0 = default.
	// +optional
	BurstKB uint32 `json:"burstKB,omitempty" protobuf:"varint,2,opt,name=burstKB"`
	// PublicMbps caps external/NATed egress in Mbit/s (policed). 0 = unlimited.
	// +optional
	PublicMbps uint32 `json:"publicMbps,omitempty" protobuf:"varint,3,opt,name=publicMbps"`
}

// RateLimit is a token-bucket policing cap.
type RateLimit struct {
	// RateMbps caps throughput in Mbit/s. 0 = unlimited.
	// +optional
	RateMbps uint32 `json:"rateMbps,omitempty" protobuf:"varint,1,opt,name=rateMbps"`
	// BurstKB is an optional burst allowance in KB. Reserved (default burst in v1). 0 = default.
	// +optional
	BurstKB uint32 `json:"burstKB,omitempty" protobuf:"varint,2,opt,name=burstKB"`
}

// NetworkInterfaceStatus is the observed state of a NetworkInterface.
type NetworkInterfaceStatus struct {
	// VNI is the effective VXLAN network identifier resolved from the VPC.
	// +optional
	VNI int32 `json:"vni,omitempty" protobuf:"varint,1,opt,name=vni"`
	// UnderlayRoute is the allocated underlay /128 from the host's underlay /64.
	// +optional
	UnderlayRoute string `json:"underlayRoute,omitempty" protobuf:"bytes,2,opt,name=underlayRoute"`
	// Port describes the dataplane port allocated for this interface.
	// +optional
	Port *PortStatus `json:"port,omitempty" protobuf:"bytes,3,opt,name=port"`
	// State is the current lifecycle state (e.g. Pending, Ready).
	// +optional
	State string `json:"state,omitempty" protobuf:"bytes,4,opt,name=state"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NetworkInterface is a thin NIC attached to a VM: identity plus user-specified overlay IPs.
type NetworkInterface struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   NetworkInterfaceSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status NetworkInterfaceStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkInterfaceList is a list of NetworkInterface objects.
type NetworkInterfaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []NetworkInterface `json:"items" protobuf:"bytes,2,rep,name=items"`
}
