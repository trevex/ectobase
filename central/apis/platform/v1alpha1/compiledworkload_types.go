// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledWorkloadSpec defines the desired state of a CompiledWorkload.
type CompiledWorkloadSpec struct {
	// ClusterName is the name of the cluster the workload is bound to
	// (the pod->node binding).
	ClusterName string `json:"clusterName,omitempty" protobuf:"bytes,1,opt,name=clusterName"`
	// Payload is the compiled workload payload.
	Payload string `json:"payload,omitempty" protobuf:"bytes,2,opt,name=payload"`
}

// CompiledWorkloadStatus defines the observed state of a CompiledWorkload.
type CompiledWorkloadStatus struct {
	// Phase is the current lifecycle phase of the CompiledWorkload.
	Phase string `json:"phase,omitempty" protobuf:"bytes,1,opt,name=phase"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledWorkload is a compiled workload bound to a cluster.
type CompiledWorkload struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   CompiledWorkloadSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status CompiledWorkloadStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CompiledWorkloadList is a list of CompiledWorkload objects.
type CompiledWorkloadList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []CompiledWorkload `json:"items" protobuf:"bytes,2,rep,name=items"`
}
