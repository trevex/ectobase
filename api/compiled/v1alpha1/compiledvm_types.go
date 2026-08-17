// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledVMSpec is the fully lowered, ready-to-materialize boot intent for a VM:
// the containerDisk image, compute resources, run strategy, the cluster binding,
// and the per-interface MAC + overlay network name. A downstream materializer
// turns this into a kubevirt.io/v1.VirtualMachine.
type CompiledVMSpec struct {
	// ClusterName is the cluster this compiled VM is bound to (the pod->node binding).
	// The per-cluster broker selects on this field.
	// +optional
	ClusterName string `json:"clusterName,omitempty"`
	// Image is the containerDisk image to boot from.
	// +optional
	Image string `json:"image,omitempty"`
	// Resources is the compute request/limit; maps to the KubeVirt domain resources.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// RunStrategy is the KubeVirt run strategy (defaulted upstream by the compiler).
	// +optional
	RunStrategy string `json:"runStrategy,omitempty"`
	// Interfaces are the VM's overlay interfaces (one per owned NetworkInterface).
	// +optional
	Interfaces []CompiledVMInterface `json:"interfaces,omitempty"`
	// CloudInit, if set, is guest bootstrap delivered as a cloud-init NoCloud datasource.
	// +optional
	CloudInit *CloudInit `json:"cloudInit,omitempty"`
}

// CloudInit is guest bootstrap config for a compiled VM, delivered by the materializer
// as a cloud-init NoCloud datasource.
type CloudInit struct {
	// UserData is the cloud-init user-data (commonly a #cloud-config document).
	// +optional
	UserData string `json:"userData,omitempty"`
}

// CompiledVMInterface is a resolved overlay interface for a VM: the pinned MAC
// and the multus network (NetworkAttachmentDefinition) name for the flowplane binding.
type CompiledVMInterface struct {
	// MAC is the pinned L2 address (from the NetworkInterface).
	// +optional
	MAC string `json:"mac,omitempty"`
	// NetworkName is the multus NetworkAttachmentDefinition name for the overlay binding.
	// +optional
	NetworkName string `json:"networkName,omitempty"`
}

// CompiledVMStatus is the observed state of a CompiledVM. It is intentionally
// minimal (State only): the downstream materializer reconciles CompiledVM into a
// KubeVirt VirtualMachine via declarative set-reconcile, so — unlike CompiledNIC,
// whose node agent tracks an applied generation — no GenerationApplied is needed here.
type CompiledVMStatus struct {
	// State is the materialization state (e.g. Applied, Pending).
	// +optional
	State string `json:"state,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// CompiledVM is the lowered boot intent for a scheduled VirtualMachine.
type CompiledVM struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CompiledVMSpec   `json:"spec,omitempty"`
	Status CompiledVMStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// CompiledVMList is a list of CompiledVM objects.
type CompiledVMList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CompiledVM `json:"items"`
}
