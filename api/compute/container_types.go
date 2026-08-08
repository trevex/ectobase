// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContainerSpec is a schedulable container workload: it owns NetworkInterfaces and carries the pod
// template. Placement (ClusterName/NodeName) is the authority for its owned NICs; in this slice it is
// set by hand (no scheduler binds it yet).
type ContainerSpec struct {
	// ClusterName is the cluster this container is bound to (the placement authority for owned NICs).
	ClusterName string
	// NodeName pins the Pod (and the owned NICs) to a node; the agent firewall reconcile gates on it.
	NodeName string
	// InterfaceRefs names the NetworkInterfaces (same namespace) this container owns.
	InterfaceRefs []LocalObjectReference
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
	// RestartPolicy is the Pod restart policy (default Always).
	RestartPolicy corev1.RestartPolicy
}

// ContainerStatus is the observed state of a Container.
type ContainerStatus struct {
	// State is the compile/materialization state (e.g. Compiled, Pending).
	State string
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Container is a schedulable container workload on the ectobase overlay.
type Container struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   ContainerSpec
	Status ContainerStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ContainerList is a list of Container objects.
type ContainerList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []Container
}
