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

func (o *LoadBalancer) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *LoadBalancer) NamespaceScoped() bool {
	return true
}

func (o *LoadBalancer) New() runtime.Object {
	return &LoadBalancer{}
}

func (o *LoadBalancer) NewList() runtime.Object {
	return &LoadBalancerList{}
}

func (o *LoadBalancer) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("loadbalancers").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *LoadBalancer) CopyStatusTo(to runtime.Object) {
	to.(*LoadBalancer).Status = *o.Status.DeepCopy()
}

// PrepareForCreate starts the object at generation 1. See generation.go for why this group sets
// its own generation.
func (o *LoadBalancer) PrepareForCreate(ctx context.Context) {
	o.Generation = 1
}

// PrepareForUpdate advances the generation when the spec changed. See generation.go.
func (o *LoadBalancer) PrepareForUpdate(ctx context.Context, old runtime.Object) {
	p, ok := old.(*LoadBalancer)
	if !ok {
		return
	}
	o.Generation = nextGeneration(p.Generation, !apiequality.Semantic.DeepEqual(o.Spec, p.Spec))
}
