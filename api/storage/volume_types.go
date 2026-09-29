// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DiskIdentity is the CSI identity of the disk actually provisioned for this Volume, as observed by
// the pool that provisioned it. It is what makes the disk's lifetime belong to the Volume — which is
// cluster-agnostic — rather than to the placement-scoped attachment that references it.
//
// Deliberately a separate declaration from compiled.DiskIdentity, mirroring the
// compute.VMPlacement / compiled.VMPlacement split.
type DiskIdentity struct {
	// CSI is the provisioned PersistentVolume's CSI source, copied as-is.
	CSI *corev1.CSIPersistentVolumeSource
	// Capacity is the PV's actual capacity, which a driver may round up from the requested Size.
	Capacity resource.Quantity
}

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
	// DiskIdentity, once set, is the disk backing this Volume. Mirrored here from the
	// CompiledVolumeAttachment a pool reported it on.
	DiskIdentity *DiskIdentity
	// DiskReclaimStarted records that the objects handing this Volume's image back to its CSI driver
	// for deletion have been created. It distinguishes "the reclaim has not begun" from "the driver
	// finished and removed the PersistentVolume" — both of which present as an absent PV.
	DiskReclaimStarted bool
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
