// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FloatingIPSpec is the desired state of a FloatingIP.
//
// SCAFFOLD ONLY: intentionally empty. Floating/movable virtual IP (§3.7).
// Fleshed out in a later plan (YAGNI here).
type FloatingIPSpec struct {
}

// FloatingIPStatus is the observed state of a FloatingIP.
//
// SCAFFOLD ONLY: intentionally empty.
type FloatingIPStatus struct {
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=fip

// FloatingIP is a scaffold-only resource. Floating/movable virtual IP (§3.7).
type FloatingIP struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   FloatingIPSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status FloatingIPStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FloatingIPList is a list of FloatingIP objects.
type FloatingIPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []FloatingIP `json:"items" protobuf:"bytes,2,rep,name=items"`
}
