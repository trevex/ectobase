// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"go.opendefense.cloud/kit/apiserver/resource"
	kitrest "go.opendefense.cloud/kit/apiserver/rest"
)

var (
	_ resource.Object                         = &CompiledWorkload{}
	_ resource.ObjectWithStatusSubResource    = &CompiledWorkload{}
	_ kitrest.SelectableFieldsProvider        = &CompiledWorkload{}
	_ kitrest.SupportedFieldSelectorsProvider = &CompiledWorkload{}
)

func (o *CompiledWorkload) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *CompiledWorkload) NamespaceScoped() bool {
	return false
}

func (o *CompiledWorkload) New() runtime.Object {
	return &CompiledWorkload{}
}

func (o *CompiledWorkload) NewList() runtime.Object {
	return &CompiledWorkloadList{}
}

func (o *CompiledWorkload) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("compiledworkloads").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *CompiledWorkload) CopyStatusTo(to runtime.Object) {
	to.(*CompiledWorkload).Status = *o.Status.DeepCopy()
}

// SelectableFields contributes CompiledWorkload spec fields for field-selector
// filtering (e.g. `--field-selector spec.clusterName=c1`).
func (o *CompiledWorkload) SelectableFields() fields.Set {
	return fields.Set{
		"spec.clusterName": o.Spec.ClusterName,
	}
}

// SupportedFieldSelectors advertises the additional field-selector keys the
// CompiledWorkload resource supports, so the apiserver accepts them during
// list-options conversion.
func (o *CompiledWorkload) SupportedFieldSelectors() []string {
	return []string{"spec.clusterName"}
}
