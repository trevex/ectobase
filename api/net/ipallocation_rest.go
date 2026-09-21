// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (o *IPAllocation) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *IPAllocation) NamespaceScoped() bool {
	return true
}

func (o *IPAllocation) New() runtime.Object {
	return &IPAllocation{}
}

func (o *IPAllocation) NewList() runtime.Object {
	return &IPAllocationList{}
}

func (o *IPAllocation) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("ipallocations").GroupResource()
}

// No CopyStatusTo: an IPAllocation has no status. Its existence is the state, so there is
// nothing for a status subresource to carry and the kit's ObjectWithStatusSubResource hook
// is deliberately left unimplemented.
