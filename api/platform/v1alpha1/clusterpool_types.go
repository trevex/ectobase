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
	// UnderlayPrefix is this cluster's underlay aggregate (a CIDR that contains every node's
	// underlay address, e.g. "fd00:cafe:1a2b::/48"). Declaring it makes Tier-2 fencing COMPLETE by
	// construction: the dispatch fences this one prefix instead of enumerating node /64s, so a node it
	// never observed — one that joined while the pool was unreachable — is fenced too.
	//
	// It is also the pool's route-bus certificate constraint: the dispatch signer IP-name-constrains
	// the pool's intermediate CA to exactly this prefix, so the pool can only mint node leaves whose
	// IP SAN lies inside it, and the reflector only trusts nexthops equal to such a SAN. A pool must
	// declare it to join the route bus: with it empty, the signer denies the pool's intermediate.
	//
	// It must be a CIDR in canonical form (no host bits, no IPv4-mapped IPv6), at least /32 for
	// IPv6 or /16 for IPv4. The signer also denies a prefix that overlaps another ClusterPool's
	// (the pool enrolled later is denied) or a fleet identity's permitted ranges. If a reported node
	// /64 lies outside it, failover treats its coverage as incomplete and blocks the rebind.
	//
	// It is dispatch configuration, set when the pool is registered, deliberately NOT reported by
	// the broker: neither a fence coordinate nor a certificate constraint may be derived from the
	// entity it bounds. A fenced pool is by definition the one you have lost contact with, and a
	// constraint the pool chooses itself constrains nothing.
	//
	// It is the ONLY coordinate failover fences: broker-reported status.nodePrefixes never are. A
	// pool that declares no prefix (or one that fails these rules, stored before they existed) is
	// neither fenced nor rebound when lost; failover blocks its VMs with FailoverBlocked. A reported
	// node prefix outside the declared one also blocks the rebind, since the prefix then may miss a
	// node. See docs/architecture/failover.md.
	// +optional
	UnderlayPrefix string `json:"underlayPrefix,omitempty" protobuf:"bytes,3,opt,name=underlayPrefix"`
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
	// NodePrefixes is the set of node /64 underlay prefixes composing this cluster, reported by
	// the broker. They key the drain report. They are never fenced: the pool writes them itself,
	// so failover fences only spec.underlayPrefix, and a reported prefix outside it blocks the
	// rebind.
	// +optional
	NodePrefixes []string `json:"nodePrefixes,omitempty" protobuf:"bytes,5,rep,name=nodePrefixes"`
	// FencedPrefixes are the prefixes the dispatch has fenced (spec.underlayPrefix) while
	// evacuating the pool; recovery releases them.
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
