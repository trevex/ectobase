// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DiskIdentity is the CSI identity of the disk actually provisioned for this Volume, as observed by
// the pool that provisioned it. It is what makes the disk's lifetime belong to the Volume — which is
// cluster-agnostic — rather than to the placement-scoped attachment that happens to reference it.
//
// The entire CSI source is kept verbatim rather than a handle plus reconstructed parameters:
// rebuilding a ceph-csi PV from StorageClass parameters means re-deriving clusterID, pool, imageName,
// journalPool and up to five distinct secret references by hand, and dropping any one of them yields
// a PV that binds and then fails to mount at NodeStage.
//
// Deliberately a separate declaration from compiled.DiskIdentity, mirroring the
// compute.VMPlacement / compiled.VMPlacement split: the compiled group is self-contained so a pool
// never needs the source API, and an import either way would break that.
type DiskIdentity struct {
	// CSI is the provisioned PersistentVolume's CSI source, copied as-is.
	// +optional
	CSI *corev1.CSIPersistentVolumeSource `json:"csi,omitempty"`
	// Capacity is the PV's actual capacity, which a driver may round up from the requested Size.
	// +optional
	Capacity resource.Quantity `json:"capacity,omitempty"`
}

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
	// DiskIdentity, once set, is the disk backing this Volume. It is mirrored here from the
	// CompiledVolumeAttachment a pool reported it on, and is what a later attachment in ANOTHER
	// cluster is stamped with so it adopts this disk instead of provisioning a blank one.
	// +optional
	DiskIdentity *DiskIdentity `json:"diskIdentity,omitempty"`
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
