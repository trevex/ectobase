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
	_ resource.Object                         = &CompiledNIC{}
	_ resource.ObjectWithStatusSubResource    = &CompiledNIC{}
	_ kitrest.SelectableFieldsProvider        = &CompiledNIC{}
	_ kitrest.SupportedFieldSelectorsProvider = &CompiledNIC{}
)

func (o *CompiledNIC) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *CompiledNIC) NamespaceScoped() bool {
	return true
}

func (o *CompiledNIC) New() runtime.Object {
	return &CompiledNIC{}
}

func (o *CompiledNIC) NewList() runtime.Object {
	return &CompiledNICList{}
}

func (o *CompiledNIC) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("compilednics").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *CompiledNIC) CopyStatusTo(to runtime.Object) {
	to.(*CompiledNIC).Status = *o.Status.DeepCopy()
}

// SelectableFields contributes CompiledNIC spec fields for field-selector
// filtering (e.g. `--field-selector spec.clusterName=c1`). The per-cluster
// broker selects on this to pull only its cluster's compiled NICs.
func (o *CompiledNIC) SelectableFields() fields.Set {
	return fields.Set{
		"spec.clusterName": o.Spec.ClusterName,
	}
}

// SupportedFieldSelectors advertises the additional field-selector keys the
// CompiledNIC resource supports, so the apiserver accepts them during
// list-options conversion.
func (o *CompiledNIC) SupportedFieldSelectors() []string {
	return []string{"spec.clusterName"}
}
