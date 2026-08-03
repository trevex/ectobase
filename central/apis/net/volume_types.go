// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VolumeSpec defines a persistent RBD-backed disk for a VM.
type VolumeSpec struct {
	// Size is the requested disk size (e.g. 10Gi).
	Size resource.Quantity
	// StorageClass is the ceph-csi RBD StorageClass; empty uses the cluster default.
	StorageClass string
	// BootImage, if set, is a containerDisk/registry image imported into the disk
	// (making it bootable). Empty leaves a blank data disk of Size.
	BootImage string
}

// VolumeStatus is the observed state of a Volume.
type VolumeStatus struct {
	// Phase is the current lifecycle phase of the Volume.
	Phase string
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Volume is a persistent RBD-backed disk referenced by a VirtualMachine.
type Volume struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   VolumeSpec
	Status VolumeStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VolumeList is a list of Volume objects.
type VolumeList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []Volume
}
