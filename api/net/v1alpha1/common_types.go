// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// LocalObjectReference references an object by name within the same namespace.
type LocalObjectReference struct {
	// Name is the name of the referenced object.
	Name string `json:"name" protobuf:"bytes,1,opt,name=name"`
}

// PortType is the kind of dataplane port backing a NetworkInterface.
// +kubebuilder:validation:Enum=tap;vf
type PortType string

const (
	// PortTypeTap is a tap-backed (vhost-user) port.
	PortTypeTap PortType = "tap"
	// PortTypeVF is an SR-IOV virtual-function passthrough port.
	PortTypeVF PortType = "vf"
)

// PortStatus describes the dataplane port allocated for a NetworkInterface.
type PortStatus struct {
	// Type is the port type (e.g. tap or vf).
	Type PortType `json:"type,omitempty" protobuf:"bytes,1,opt,name=type,casttype=PortType"`
	// Name is the host-side interface name (e.g. dtapvf_0) for tap ports.
	// +optional
	Name string `json:"name,omitempty" protobuf:"bytes,2,opt,name=name"`
	// PCIAddress is the PCI address for vf ports.
	// +optional
	PCIAddress string `json:"pciAddress,omitempty" protobuf:"bytes,3,opt,name=pciAddress"`
}
