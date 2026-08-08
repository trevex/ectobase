// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledContainerSpec is the lowered, ready-to-materialize intent for a container workload: the pod
// template + the cluster/node binding + the per-interface overlay wiring. A downstream pod-materializer
// turns this into a v1.Pod.
type CompiledContainerSpec struct {
	// ClusterName is the cluster this compiled container is bound to. The broker selects on this field.
	// +optional
	ClusterName string `json:"clusterName,omitempty"`
	// NodeName is the pod nodeSelector (kubernetes.io/hostname).
	// +optional
	NodeName string `json:"nodeName,omitempty"`
	// Image is the container image.
	// +optional
	Image string `json:"image,omitempty"`
	// Command overrides the image entrypoint.
	// +optional
	Command []string `json:"command,omitempty"`
	// Args are the container args.
	// +optional
	Args []string `json:"args,omitempty"`
	// Env are the container environment variables.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`
	// Resources is the compute request/limit.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// RestartPolicy is the Pod restart policy.
	// +optional
	RestartPolicy corev1.RestartPolicy `json:"restartPolicy,omitempty"`
	// Interfaces are the container's overlay interfaces (one per owned NetworkInterface).
	// +optional
	Interfaces []CompiledContainerInterface `json:"interfaces,omitempty"`
}

// CompiledContainerInterface is a resolved overlay interface for a container.
type CompiledContainerInterface struct {
	// NetworkName is the multus NetworkAttachmentDefinition name for the overlay binding.
	// +optional
	NetworkName string `json:"networkName,omitempty"`
	// NetworkInterfaceRef is "<namespace>/<nic>" — the pod's net.ectobase.dev/network-interface
	// annotation, which flowplane-cni resolves to the CompiledNIC.
	// +optional
	NetworkInterfaceRef string `json:"networkInterfaceRef,omitempty"`
	// MAC is the pinned L2 address (from the NetworkInterface).
	// +optional
	MAC string `json:"mac,omitempty"`
}

// CompiledContainerStatus is the observed state of a CompiledContainer.
type CompiledContainerStatus struct {
	// State is the materialization state (e.g. Applied, Pending).
	// +optional
	State string `json:"state,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// CompiledContainer is the lowered pod intent for a Container.
type CompiledContainer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CompiledContainerSpec   `json:"spec,omitempty"`
	Status CompiledContainerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// CompiledContainerList is a list of CompiledContainer objects.
type CompiledContainerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CompiledContainer `json:"items"`
}
