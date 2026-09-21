// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
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

// PrepareForCreate starts the object at generation 1. See generation.go for why this group sets
// its own generation.
func (o *IPAllocation) PrepareForCreate(ctx context.Context) {
	o.Generation = 1
}

// PrepareForUpdate advances the generation when the spec changed. See generation.go.
func (o *IPAllocation) PrepareForUpdate(ctx context.Context, old runtime.Object) {
	p, ok := old.(*IPAllocation)
	if !ok {
		return
	}
	o.Generation = nextGeneration(p.Generation, !apiequality.Semantic.DeepEqual(o.Spec, p.Spec))
}
