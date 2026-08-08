// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compiled

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledContainerSpec is the lowered, ready-to-materialize intent for a container workload: the pod
// template + the cluster/node binding + the per-interface overlay wiring. A downstream pod-materializer
// turns this into a v1.Pod.
type CompiledContainerSpec struct {
	// ClusterName is the cluster this compiled container is bound to. The broker selects on this field.
	ClusterName string
	// NodeName is the pod nodeSelector (kubernetes.io/hostname).
	NodeName string
	// Image is the container image.
	Image string
	// Command overrides the image entrypoint.
	Command []string
	// Args are the container args.
	Args []string
	// Env are the container environment variables.
	Env []corev1.EnvVar
	// Resources is the compute request/limit.
	Resources corev1.ResourceRequirements
	// RestartPolicy is the Pod restart policy.
	RestartPolicy corev1.RestartPolicy
	// Interfaces are the container's overlay interfaces (one per owned NetworkInterface).
	Interfaces []CompiledContainerInterface
}

// CompiledContainerInterface is a resolved overlay interface for a container.
type CompiledContainerInterface struct {
	// NetworkName is the multus NetworkAttachmentDefinition name for the overlay binding.
	NetworkName string
	// NetworkInterfaceRef is "<namespace>/<nic>" — the pod's net.ectobase.dev/network-interface
	// annotation, which flowplane-cni resolves to the CompiledNIC.
	NetworkInterfaceRef string
	// MAC is the pinned L2 address (from the NetworkInterface).
	MAC string
}

// CompiledContainerStatus is the observed state of a CompiledContainer.
type CompiledContainerStatus struct {
	// State is the materialization state (e.g. Applied, Pending).
	State string
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledContainer is the lowered pod intent for a Container.
type CompiledContainer struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   CompiledContainerSpec
	Status CompiledContainerStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledContainerList is a list of CompiledContainer objects.
type CompiledContainerList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []CompiledContainer
}
