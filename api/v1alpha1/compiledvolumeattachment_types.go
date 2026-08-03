// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledVolumeAttachmentSpec is the lowered, cluster-bound attachment of one
// Volume to one VM: the RBD disk parameters a downstream materializer turns into a
// CDI DataVolume (RBD PVC).
type CompiledVolumeAttachmentSpec struct {
	// ClusterName is the cluster this attachment is bound to (the pod->node binding);
	// the per-cluster broker selects on this field.
	// +optional
	ClusterName string `json:"clusterName,omitempty"`
	// Size is the RBD disk size.
	// +kubebuilder:validation:Required
	Size resource.Quantity `json:"size"`
	// StorageClass is the ceph-csi RBD StorageClass (empty = cluster default).
	// +optional
	StorageClass string `json:"storageClass,omitempty"`
	// BootImage, if set, is imported into the disk (bootable); empty = blank disk.
	// +optional
	BootImage string `json:"bootImage,omitempty"`
	// Boot marks this attachment as the VM's boot disk.
	// +optional
	Boot bool `json:"boot,omitempty"`
}

// CompiledVolumeAttachmentStatus is the observed state.
type CompiledVolumeAttachmentStatus struct {
	// State is the materialization state.
	// +optional
	State string `json:"state,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// CompiledVolumeAttachment binds one Volume to one VM on a cluster.
type CompiledVolumeAttachment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CompiledVolumeAttachmentSpec   `json:"spec,omitempty"`
	Status CompiledVolumeAttachmentStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// CompiledVolumeAttachmentList is a list of CompiledVolumeAttachment objects.
type CompiledVolumeAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CompiledVolumeAttachment `json:"items"`
}
