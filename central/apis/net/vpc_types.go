// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VPCPolicy is the default firewall posture of a VPC.
type VPCPolicy string

const (
	// VPCPolicyAllow keeps k8s semantics: interfaces are open until selected by a policy.
	VPCPolicyAllow VPCPolicy = "Allow"
	// VPCPolicyDeny makes the VPC default-deny: traffic is dropped unless explicitly allowed.
	VPCPolicyDeny VPCPolicy = "Deny"
)

// VPCSpec is the desired state of a VPC (an isolation domain / overlay network).
type VPCSpec struct {
	// VNI optionally pins the VXLAN network identifier. When nil or 0, the VNI is
	// allocated by the central cluster from the global VNI space.
	VNI *int32
	// DefaultPolicy overrides the global default firewall posture for this VPC.
	// One of Allow (k8s semantics) or Deny (VPC-wide default-deny).
	DefaultPolicy *string
}

// VPCStatus is the observed state of a VPC.
type VPCStatus struct {
	// VNI is the effective, allocated VXLAN network identifier.
	VNI int32
	// State is the current lifecycle state (e.g. Pending, Ready).
	State string
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPC is an isolation domain (overlay network) identified by a VNI on the shared underlay.
type VPC struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   VPCSpec
	Status VPCStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCList is a list of VPC objects.
type VPCList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []VPC
}
