// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VPCPolicy is the default firewall posture of a VPC.
// +kubebuilder:validation:Enum=Allow;Deny
type VPCPolicy string

const (
	// VPCPolicyAllow ends every interface's ingress and egress with an implicit lowest-priority
	// allow-all: traffic flows unless a rule denies it, so a lone Deny rule denies just its match.
	VPCPolicyAllow VPCPolicy = "Allow"
	// VPCPolicyDeny makes the VPC default-deny: traffic is dropped unless a rule allows it, in both
	// directions, whether or not any policy selects the interface.
	VPCPolicyDeny VPCPolicy = "Deny"
)

// VPCSpec is the desired state of a VPC (an isolation domain / overlay network).
type VPCSpec struct {
	// VNI optionally pins the Geneve virtual network identifier. When nil or 0, the VNI is
	// allocated by the dispatch from the global VNI space.
	// +optional
	VNI *int32 `json:"vni,omitempty" protobuf:"varint,1,opt,name=vni"`
	// DefaultPolicy sets what happens to traffic no firewall rule matches. Allow: it passes (rules
	// carve out denies). Deny: it drops, in every direction (rules carve out allows). Unset keeps
	// Kubernetes NetworkPolicy semantics per direction: a direction no policy governs is open, a
	// governed direction admits only what its rules allow. The VPC's FirewallDefault condition
	// reports the posture in effect.
	// +optional
	// +kubebuilder:validation:Enum=Allow;Deny
	DefaultPolicy *string `json:"defaultPolicy,omitempty" protobuf:"bytes,2,opt,name=defaultPolicy"`
}

// VPCStatus is the observed state of a VPC.
type VPCStatus struct {
	// VNI is the effective, allocated Geneve virtual network identifier.
	// +optional
	VNI int32 `json:"vni,omitempty" protobuf:"varint,1,opt,name=vni"`
	// State is the current lifecycle state (e.g. Pending, Ready).
	// +optional
	State string `json:"state,omitempty" protobuf:"bytes,2,opt,name=state"`
	// Conditions report observations about the VPC. FirewallDefault states the default firewall
	// posture in effect (reason Allow, Deny or PerDirection).
	// +optional
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,3,rep,name=conditions"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VPC is an isolation domain (overlay network) identified by a VNI on the shared underlay.
type VPC struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   VPCSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status VPCStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCList is a list of VPC objects.
type VPCList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []VPC `json:"items" protobuf:"bytes,2,rep,name=items"`
}
