// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LoadBalancerSpec is the desired state of a LoadBalancer.
type LoadBalancerSpec struct {
	// VIP is the virtual IP (IPv4 or IPv6). It is the LB identity and the AddLbVip id.
	VIP string
	// Ports are the LB service (port, proto) tuples.
	Ports []LoadBalancerPort
	// TargetSelector selects backend NetworkInterfaces by label.
	TargetSelector *metav1.LabelSelector
	// TargetRefs names backend NetworkInterfaces explicitly.
	TargetRefs []LocalObjectReference
}

// LoadBalancerPort is one LB service tuple.
type LoadBalancerPort struct {
	// Port is the service port.
	Port int32
	// Proto is the IP protocol ("TCP" or "UDP").
	Proto string
}

// LoadBalancerStatus is the observed state of a LoadBalancer.
type LoadBalancerStatus struct {
	// State is the lifecycle state (Pending | Ready).
	State string
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LoadBalancer is a scaffold-only resource. Selector-target load balancer (§3.5).
type LoadBalancer struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   LoadBalancerSpec
	Status LoadBalancerStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LoadBalancerList is a list of LoadBalancer objects.
type LoadBalancerList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []LoadBalancer
}
