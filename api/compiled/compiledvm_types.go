// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compiled

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledVMSpec is the fully lowered, ready-to-materialize boot intent for a VM.
type CompiledVMSpec struct {
	// ClusterName is the cluster this compiled VM is bound to. The per-cluster broker selects on this field.
	ClusterName string
	// Image is the containerDisk image to boot from.
	Image string
	// Resources is the compute request/limit; maps to the KubeVirt domain resources.
	Resources corev1.ResourceRequirements
	// RunStrategy is the KubeVirt run strategy.
	RunStrategy string
	// Interfaces are the VM's overlay interfaces (one per owned NetworkInterface).
	Interfaces []CompiledVMInterface
}

// CompiledVMInterface is a resolved overlay interface for a VM.
type CompiledVMInterface struct {
	// MAC is the pinned L2 address (from the NetworkInterface).
	MAC string
	// NetworkName is the multus NetworkAttachmentDefinition name for the overlay binding.
	NetworkName string
}

// CompiledVMStatus is the observed state of a CompiledVM.
type CompiledVMStatus struct {
	// State is the materialization state (e.g. Applied, Pending).
	State string
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledVM is the lowered boot intent for a scheduled VirtualMachine.
type CompiledVM struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   CompiledVMSpec
	Status CompiledVMStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledVMList is a list of CompiledVM objects.
type CompiledVMList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []CompiledVM
}
