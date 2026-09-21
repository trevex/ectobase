// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PoolLabel names the IPPool an IPAllocation belongs to, so a pool's allocations are one
// label-selector list. Aggregated APIs offer no field selectors for arbitrary fields, so the
// used-set query has to go through a label.
const PoolLabel = "net.ectobase.dev/pool"

// ConsumerLabel carries the UID of the consumer holding an IPAllocation, so one consumer's
// claims are a single label-selector list. The pool label answers "what is taken in this pool";
// this one answers "what do I hold", which is how a consumer releases a claim it has superseded
// — including one left in a DIFFERENT pool after spec.poolRef was repointed, where a
// pool-scoped query would never find it. UID rather than name, because a deleted-and-recreated
// consumer of the same name is a different consumer.
//
// It is an index, never an authority: the controller ownerReference decides what a consumer
// actually owns.
const ConsumerLabel = "net.ectobase.dev/consumer-uid"

// IPAllocationSpec is the desired state of an IPAllocation.
//
// There is no status: the object's EXISTENCE is the state. Its name is derived from
// (pool, address) and object names are unique within a namespace, which makes Create a
// compare-and-swap — two allocators racing for one address cannot both succeed, without
// either of them assuming it is the only writer.
type IPAllocationSpec struct {
	// PoolRef is the IPPool this address came from.
	PoolRef LocalObjectReference `json:"poolRef" protobuf:"bytes,1,opt,name=poolRef"`
	// Address is the allocated address, canonical form.
	Address string `json:"address" protobuf:"bytes,2,opt,name=address"`
	// ConsumerRef records who asked for it, for humans and diagnostics. The authoritative
	// lifetime link is the ownerReference, not this field.
	ConsumerRef TypedLocalObjectReference `json:"consumerRef" protobuf:"bytes,3,opt,name=consumerRef"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// IPAllocation is one address held out of one IPPool. It is created by the consumer's
// allocator and reclaimed by Kubernetes garbage collection when its ownerReference's
// consumer is deleted.
type IPAllocation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec IPAllocationSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPAllocationList is a list of IPAllocation objects.
type IPAllocationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []IPAllocation `json:"items" protobuf:"bytes,2,rep,name=items"`
}
