// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DiskIdentity is the CSI identity of an already-provisioned disk, captured from the
// PersistentVolume the driver produced for it. It is what lets an attachment compiled into a
// DIFFERENT cluster bind the SAME underlying image instead of provisioning a blank one: without it
// a cluster rebind destroys the disk (see
// docs/superpowers/plans/2026-09-24-phase0-non-destructive-move.md).
//
// The entire CSI source is kept verbatim rather than a handle plus reconstructed parameters.
// Rebuilding a ceph-csi PV from StorageClass parameters means re-deriving clusterID, pool,
// imageName, journalPool and up to five distinct secret references by hand, and dropping any one of
// them yields a PV that binds and then fails to mount at NodeStage. Replaying what the driver itself
// emitted cannot drift from the driver's own conventions.
//
// Deliberately redeclared here rather than reusing storage.DiskIdentity, for the same reason
// VMPlacement is (compiledvm_types.go): the compiled group is self-contained, and a pool consumes
// only compiled.ectobase.dev and never needs the source API.
type DiskIdentity struct {
	// CSI is the provisioned PersistentVolume's CSI source, copied as-is.
	// +optional
	CSI *corev1.CSIPersistentVolumeSource `json:"csi,omitempty"`
	// Capacity is the PV's actual capacity, which a driver may round up from the requested Size;
	// a replayed PV must declare what exists, not what was asked for.
	// +optional
	Capacity resource.Quantity `json:"capacity,omitempty"`
}

// CompiledVolumeAttachmentSpec is the lowered, cluster-bound attachment of one
// Volume to one VM: the RBD disk parameters a downstream materializer turns into a
// CDI DataVolume (RBD PVC).
type CompiledVolumeAttachmentSpec struct {
	// ClusterName is the cluster this attachment is bound to (the pod->node binding). The twin
	// lives in the pool's pool-<clusterName> namespace on the dispatch, which is the namespace
	// the pool's broker syncs.
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
	// VolumeRef is the name of the source Volume, in the VM's namespace.
	//
	// Carried explicitly because consumers need to get back to the Volume and neither alternative
	// works: this object's name is <vmNamespace>-<vmName>-<volumeRef>, which is ambiguous to split
	// as soon as any component contains a '-', and the stamped source annotations name the
	// VirtualMachine, since attachments are 1:N per VM.
	// +optional
	VolumeRef string `json:"volumeRef,omitempty"`
	// DiskIdentity, if set, is an existing disk this attachment must ADOPT rather than provision.
	// The compiler stamps it from the Volume's observed identity, so a twin landing in a new cluster
	// binds the image that already holds the data.
	//
	// It travels downward in spec, while the same information travels upward in status: the target
	// cluster must be handed the identity, never have to go and read an observation.
	// +optional
	DiskIdentity *DiskIdentity `json:"diskIdentity,omitempty"`
}

// CompiledVolumeAttachmentStatus is the observed state.
type CompiledVolumeAttachmentStatus struct {
	// State is the materialization state.
	// +optional
	State string `json:"state,omitempty"`
	// DiskIdentity is the identity of the disk actually provisioned for this attachment, reported
	// upward by the pool that provisioned it. It lands here rather than directly on the source
	// Volume because the broker's writes are scoped to its own pool namespace; a mesh controller
	// mirrors it onto the Volume.
	// +optional
	DiskIdentity *DiskIdentity `json:"diskIdentity,omitempty"`
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
