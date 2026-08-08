// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"go.opendefense.cloud/kit/apiserver/resource"
	kitrest "go.opendefense.cloud/kit/apiserver/rest"
)

var (
	_ resource.Object                         = &CompiledContainer{}
	_ resource.ObjectWithStatusSubResource    = &CompiledContainer{}
	_ kitrest.SelectableFieldsProvider        = &CompiledContainer{}
	_ kitrest.SupportedFieldSelectorsProvider = &CompiledContainer{}
)

func (o *CompiledContainer) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *CompiledContainer) NamespaceScoped() bool {
	return true
}

func (o *CompiledContainer) New() runtime.Object {
	return &CompiledContainer{}
}

func (o *CompiledContainer) NewList() runtime.Object {
	return &CompiledContainerList{}
}

func (o *CompiledContainer) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("compiledcontainers").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *CompiledContainer) CopyStatusTo(to runtime.Object) {
	to.(*CompiledContainer).Status = *o.Status.DeepCopy()
}

// SelectableFields contributes CompiledContainer spec fields for field-selector
// filtering (e.g. `--field-selector spec.clusterName=c1`). The per-cluster
// broker selects on this to pull only its cluster's compiled containers.
func (o *CompiledContainer) SelectableFields() fields.Set {
	return fields.Set{
		"spec.clusterName": o.Spec.ClusterName,
	}
}

// SupportedFieldSelectors advertises the additional field-selector keys the
// CompiledContainer resource supports, so the apiserver accepts them during
// list-options conversion.
func (o *CompiledContainer) SupportedFieldSelectors() []string {
	return []string{"spec.clusterName"}
}
