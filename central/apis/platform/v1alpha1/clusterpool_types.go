// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
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
	// Allocatable is the schedulable capacity the broker reports for this pool.
	// +optional
	Allocatable corev1.ResourceList `json:"allocatable,omitempty" protobuf:"bytes,3,rep,name=allocatable,casttype=k8s.io/api/core/v1.ResourceList,castkey=k8s.io/api/core/v1.ResourceName"`
	// Lease is the broker heartbeat; a stale RenewTime drives Phase to Unknown.
	// +optional
	Lease *ClusterPoolLease `json:"lease,omitempty" protobuf:"bytes,4,opt,name=lease"`
	// NodePrefixes is the set of node /64 underlay prefixes composing this cluster,
	// reported by the broker. Central fences these (Ceph NetworkFence + route
	// blocklist) to evacuate a lost pool without reaching it.
	// +optional
	NodePrefixes []string `json:"nodePrefixes,omitempty" protobuf:"bytes,5,rep,name=nodePrefixes"`
	// FencedPrefixes is the subset of NodePrefixes central has fenced (evacuation).
	// +optional
	FencedPrefixes []string `json:"fencedPrefixes,omitempty" protobuf:"bytes,6,rep,name=fencedPrefixes"`
	// NodeDrain reports, per fenced /64, whether the returning broker has confirmed
	// its stale VMIs are terminated (safe to release the fence).
	// +optional
	// +listType=map
	// +listMapKey=prefix
	NodeDrain []NodeDrainStatus `json:"nodeDrain,omitempty" protobuf:"bytes,7,rep,name=nodeDrain"`
}

// NodeDrainStatus is the per-/64 drain confirmation used to gate fence release.
type NodeDrainStatus struct {
	// Prefix is the node /64 underlay prefix.
	Prefix string `json:"prefix" protobuf:"bytes,1,opt,name=prefix"`
	// Drained is true once the broker confirms the /64's stale VMIs are gone.
	Drained bool `json:"drained,omitempty" protobuf:"varint,2,opt,name=drained"`
}

// ClusterPoolLease is the broker's heartbeat on a ClusterPool: the identity
// holding it and when it was last renewed. Stale RenewTime => the pool is Unknown.
type ClusterPoolLease struct {
	// HolderIdentity is the broker instance currently reporting for this pool.
	// +optional
	HolderIdentity string `json:"holderIdentity,omitempty" protobuf:"bytes,1,opt,name=holderIdentity"`
	// RenewTime is when the holder last renewed the lease.
	// +optional
	RenewTime *metav1.MicroTime `json:"renewTime,omitempty" protobuf:"bytes,2,opt,name=renewTime"`
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
