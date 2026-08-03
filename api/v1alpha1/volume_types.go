// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VolumeSpec defines a persistent RBD-backed disk for a VM.
type VolumeSpec struct {
	// Size is the requested disk size (e.g. 10Gi).
	// +kubebuilder:validation:Required
	Size resource.Quantity `json:"size"`
	// StorageClass is the ceph-csi RBD StorageClass; empty uses the cluster default.
	// +optional
	StorageClass string `json:"storageClass,omitempty"`
	// BootImage, if set, is a containerDisk/registry image imported into the disk
	// (making it bootable). Empty leaves a blank data disk of Size.
	// +optional
	BootImage string `json:"bootImage,omitempty"`
}

// VolumeStatus is the observed state of a Volume.
type VolumeStatus struct {
	// Phase is the current lifecycle phase of the Volume.
	// +optional
	Phase string `json:"phase,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Volume is a persistent RBD-backed disk referenced by a VirtualMachine.
type Volume struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VolumeSpec   `json:"spec,omitempty"`
	Status VolumeStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// VolumeList is a list of Volume objects.
type VolumeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Volume `json:"items"`
}
