// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterPoolSpec defines the desired state of a ClusterPool.
type ClusterPoolSpec struct {
	// Region is the region the attached cluster resides in.
	Region string `json:"region,omitempty" protobuf:"bytes,1,opt,name=region"`
	// Endpoint is the reachable API endpoint of the attached cluster.
	Endpoint string `json:"endpoint,omitempty" protobuf:"bytes,2,opt,name=endpoint"`
}

// ClusterPoolStatus defines the observed state of a ClusterPool.
type ClusterPoolStatus struct {
	// Phase is the current lifecycle phase of the ClusterPool.
	Phase string `json:"phase,omitempty" protobuf:"bytes,1,opt,name=phase"`
	// Conditions represent the latest available observations of the ClusterPool's state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,2,rep,name=conditions"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterPool is an attached cluster exposed as a schedulable capacity domain.
type ClusterPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   ClusterPoolSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status ClusterPoolStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterPoolList is a list of ClusterPool objects.
type ClusterPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []ClusterPool `json:"items" protobuf:"bytes,2,rep,name=items"`
}
