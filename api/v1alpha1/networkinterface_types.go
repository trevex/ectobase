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
	// NodeName is the node the interface is scheduled onto. Set by the scheduler.
	// +optional
	NodeName *string `json:"nodeName,omitempty" protobuf:"bytes,3,opt,name=nodeName"`
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
