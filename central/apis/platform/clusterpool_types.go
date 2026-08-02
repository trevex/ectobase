// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterPoolSpec defines the desired state of a ClusterPool.
type ClusterPoolSpec struct {
	// Region is the region the attached cluster resides in.
	Region string
	// Endpoint is the reachable API endpoint of the attached cluster.
	Endpoint string
}

// ClusterPoolStatus defines the observed state of a ClusterPool.
type ClusterPoolStatus struct {
	// Phase is the current lifecycle phase of the ClusterPool.
	Phase string
	// Conditions represent the latest available observations of the ClusterPool's state.
	Conditions []metav1.Condition
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterPool is an attached cluster exposed as a schedulable capacity domain.
type ClusterPool struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   ClusterPoolSpec
	Status ClusterPoolStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterPoolList is a list of ClusterPool objects.
type ClusterPoolList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []ClusterPool
}
