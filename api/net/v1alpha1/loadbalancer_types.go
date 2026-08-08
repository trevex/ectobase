// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LoadBalancerSpec is the desired state of a LoadBalancer. The VIP is the LB's identity
// (v4 or v6); backends are the NetworkInterfaces matched by TargetSelector or named by TargetRefs.
type LoadBalancerSpec struct {
	// VIP is the virtual IP (IPv4 or IPv6). It is the LB identity and the AddLbVip id.
	VIP string `json:"vip"`
	// Ports are the LB service (port, proto) tuples.
	Ports []LoadBalancerPort `json:"ports"`
	// TargetSelector selects backend NetworkInterfaces by label. Mutually exclusive with TargetRefs.
	// +optional
	TargetSelector *metav1.LabelSelector `json:"targetSelector,omitempty"`
	// TargetRefs names backend NetworkInterfaces explicitly. Mutually exclusive with TargetSelector.
	// +optional
	TargetRefs []LocalObjectReference `json:"targetRefs,omitempty"`
}

// LoadBalancerPort is one LB service tuple.
type LoadBalancerPort struct {
	// Port is the service port.
	Port int32 `json:"port"`
	// Proto is the IP protocol ("TCP" or "UDP").
	Proto string `json:"proto"`
}

// LoadBalancerStatus is the observed state of a LoadBalancer.
type LoadBalancerStatus struct {
	// State is the lifecycle state (Pending | Ready).
	// +optional
	State string `json:"state,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// LoadBalancer is a scaffold-only resource. Selector-target load balancer (§3.5).
type LoadBalancer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   LoadBalancerSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status LoadBalancerStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LoadBalancerList is a list of LoadBalancer objects.
type LoadBalancerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []LoadBalancer `json:"items" protobuf:"bytes,2,rep,name=items"`
}
