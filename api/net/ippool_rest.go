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

func (o *IPPool) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *IPPool) NamespaceScoped() bool {
	return true
}

func (o *IPPool) New() runtime.Object {
	return &IPPool{}
}

func (o *IPPool) NewList() runtime.Object {
	return &IPPoolList{}
}

func (o *IPPool) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("ippools").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *IPPool) CopyStatusTo(to runtime.Object) {
	to.(*IPPool).Status = *o.Status.DeepCopy()
}

// PrepareForCreate starts the object at generation 1. See generation.go for why this group sets
// its own generation.
func (o *IPPool) PrepareForCreate(ctx context.Context) {
	o.Generation = 1
}

// PrepareForUpdate advances the generation when the spec changed. See generation.go.
func (o *IPPool) PrepareForUpdate(ctx context.Context, old runtime.Object) {
	p, ok := old.(*IPPool)
	if !ok {
		return
	}
	o.Generation = nextGeneration(p.Generation, !apiequality.Semantic.DeepEqual(o.Spec, p.Spec))
}
