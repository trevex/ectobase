// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	corev1 "k8s.io/api/core/v1"
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
	// Allocatable is the schedulable capacity the broker reports for this pool.
	Allocatable corev1.ResourceList
	// Lease is the broker heartbeat; a stale RenewTime drives Phase to Unknown.
	Lease *ClusterPoolLease
	// NodePrefixes is the set of node /64 underlay prefixes composing this cluster.
	NodePrefixes []string
	// FencedPrefixes is the subset of NodePrefixes central has fenced.
	FencedPrefixes []string
	// NodeDrain reports per-/64 drain confirmation gating fence release.
	NodeDrain []NodeDrainStatus
}

// NodeDrainStatus is the per-/64 drain confirmation used to gate fence release.
type NodeDrainStatus struct {
	Prefix  string
	Drained bool
}

// ClusterPoolLease is the broker's heartbeat on a ClusterPool.
type ClusterPoolLease struct {
	// HolderIdentity is the broker instance currently reporting for this pool.
	HolderIdentity string
	// RenewTime is when the holder last renewed the lease.
	RenewTime *metav1.MicroTime
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
