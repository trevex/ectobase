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

func (o *VPC) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *VPC) NamespaceScoped() bool {
	return true
}

func (o *VPC) New() runtime.Object {
	return &VPC{}
}

func (o *VPC) NewList() runtime.Object {
	return &VPCList{}
}

func (o *VPC) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("vpcs").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *VPC) CopyStatusTo(to runtime.Object) {
	to.(*VPC).Status = *o.Status.DeepCopy()
}

// PrepareForCreate starts the object at generation 1. See generation.go for why this group sets
// its own generation.
func (o *VPC) PrepareForCreate(ctx context.Context) {
	o.Generation = 1
}

// PrepareForUpdate advances the generation when the spec changed. See generation.go.
func (o *VPC) PrepareForUpdate(ctx context.Context, old runtime.Object) {
	p, ok := old.(*VPC)
	if !ok {
		return
	}
	o.Generation = nextGeneration(p.Generation, !apiequality.Semantic.DeepEqual(o.Spec, p.Spec))
}
