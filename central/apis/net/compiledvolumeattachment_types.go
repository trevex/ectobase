// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledVolumeAttachmentSpec is the lowered, cluster-bound attachment of one
// Volume to one VM: the RBD disk parameters a downstream materializer turns into a
// CDI DataVolume (RBD PVC).
type CompiledVolumeAttachmentSpec struct {
	// ClusterName is the cluster this attachment is bound to. The per-cluster broker selects on this field.
	ClusterName string
	// Size is the RBD disk size.
	Size resource.Quantity
	// StorageClass is the ceph-csi RBD StorageClass (empty = cluster default).
	StorageClass string
	// BootImage, if set, is imported into the disk (bootable); empty = blank disk.
	BootImage string
	// Boot marks this attachment as the VM's boot disk.
	Boot bool
}

// CompiledVolumeAttachmentStatus is the observed state.
type CompiledVolumeAttachmentStatus struct {
	// State is the materialization state.
	State string
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledVolumeAttachment binds one Volume to one VM on a cluster.
type CompiledVolumeAttachment struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   CompiledVolumeAttachmentSpec
	Status CompiledVolumeAttachmentStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledVolumeAttachmentList is a list of CompiledVolumeAttachment objects.
type CompiledVolumeAttachmentList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []CompiledVolumeAttachment
}
