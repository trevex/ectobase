// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compiled

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DiskIdentity is the CSI identity of an already-provisioned disk, captured from the
// PersistentVolume the driver produced for it. It is what lets an attachment compiled into a
// DIFFERENT cluster bind the SAME underlying image instead of provisioning a blank one.
//
// The entire CSI source is kept verbatim rather than a handle plus reconstructed parameters:
// rebuilding a ceph-csi PV from StorageClass parameters means re-deriving clusterID, pool, imageName,
// journalPool and up to five distinct secret references by hand, and dropping any one of them yields
// a PV that binds and then fails to mount at NodeStage.
//
// Deliberately redeclared here rather than reusing storage.DiskIdentity, for the same reason
// VMPlacement is (compiledvm_types.go): the compiled group is self-contained.
type DiskIdentity struct {
	// CSI is the provisioned PersistentVolume's CSI source, copied as-is.
	CSI *corev1.CSIPersistentVolumeSource
	// Capacity is the PV's actual capacity, which a driver may round up from the requested Size.
	Capacity resource.Quantity
}

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
	// VolumeRef is the name of the source Volume, in the VM's namespace. Carried explicitly because
	// this object's name is <vmNamespace>-<vmName>-<volumeRef> (ambiguous to split) and the stamped
	// source annotations name the VirtualMachine, since attachments are 1:N per VM.
	VolumeRef string
	// DiskIdentity, if set, is an existing disk this attachment must ADOPT rather than provision.
	// Travels downward in spec; the same information travels upward in status.
	DiskIdentity *DiskIdentity
}

// CompiledVolumeAttachmentStatus is the observed state.
type CompiledVolumeAttachmentStatus struct {
	// State is the materialization state.
	State string
	// DiskIdentity is the identity of the disk actually provisioned for this attachment, reported
	// upward by the pool that provisioned it. It lands here rather than on the source Volume because
	// the broker's writes are scoped to its own pool namespace; a mesh controller mirrors it across.
	DiskIdentity *DiskIdentity
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
