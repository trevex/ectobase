// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledWorkloadSpec defines the desired state of a CompiledWorkload.
type CompiledWorkloadSpec struct {
	// ClusterName is the name of the cluster the workload is bound to
	// (the pod->node binding).
	ClusterName string
	// Payload is the compiled workload payload.
	Payload string
}

// CompiledWorkloadStatus defines the observed state of a CompiledWorkload.
type CompiledWorkloadStatus struct {
	// Phase is the current lifecycle phase of the CompiledWorkload.
	Phase string
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledWorkload is a compiled workload bound to a cluster.
type CompiledWorkload struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   CompiledWorkloadSpec
	Status CompiledWorkloadStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledWorkloadList is a list of CompiledWorkload objects.
type CompiledWorkloadList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []CompiledWorkload
}
