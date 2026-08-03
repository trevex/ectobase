// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VirtualMachineSpec defines the desired state of a VirtualMachine: the cluster
// binding (placement anchor), the NetworkInterfaces it owns, its compute resources,
// and — since Phase 4 — its boot intent (containerDisk Image + RunStrategy). The
// compiler propagates ClusterName (and a workload=<name> label) onto the CompiledNICs
// of the referenced interfaces and onto a CompiledVM. Ceph-backed volume lifecycle
// is a later phase.
type VirtualMachineSpec struct {
	// ClusterName is the cluster this workload is bound to. Set manually or by
	// the compiler default in Phase 1b; the Phase-3 scheduler writes it later.
	// +optional
	ClusterName string `json:"clusterName,omitempty"`
	// InterfaceRefs names the NetworkInterfaces (same namespace) this VM owns.
	// +optional
	InterfaceRefs []LocalObjectReference `json:"interfaceRefs,omitempty"`
	// VolumeRefs names the Volumes (same namespace) this VM attaches. A referenced
	// Volume with a BootImage is the boot disk; others are data disks. When empty the
	// VM boots ephemerally from Image (containerDisk).
	// +optional
	VolumeRefs []LocalObjectReference `json:"volumeRefs,omitempty"`
	// Resources is the compute resource request/limit for this workload. Only
	// Requests is used for scheduling capacity fit; Limits is carried for parity.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// Image is the containerDisk image the VM boots from (e.g. quay.io/containerdisks/fedora:41).
	// +optional
	Image string `json:"image,omitempty"`
	// RunStrategy is the KubeVirt run strategy (Always, RerunOnFailure, Manual, Halted).
	// Empty defaults to RerunOnFailure (Tier-1 local restart on node death).
	// +optional
	RunStrategy string `json:"runStrategy,omitempty"`
	// PoolSelector, if set, restricts scheduling to ClusterPools whose labels match.
	// +optional
	PoolSelector *metav1.LabelSelector `json:"poolSelector,omitempty"`
}

// VirtualMachineStatus defines the observed state of a VirtualMachine.
type VirtualMachineStatus struct {
	// Phase is the current lifecycle phase of the VirtualMachine.
	Phase string `json:"phase,omitempty"`
	// Conditions capture scheduling/failover observations (Scheduled, Unschedulable, FailoverBlocked).
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VirtualMachine is the placement anchor for a workload.
type VirtualMachine struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VirtualMachineSpec   `json:"spec,omitempty"`
	Status VirtualMachineStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// VirtualMachineList is a list of VirtualMachine objects.
type VirtualMachineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []VirtualMachine `json:"items"`
}
