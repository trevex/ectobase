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
	_ resource.Object                         = &ClusterPool{}
	_ resource.ObjectWithStatusSubResource    = &ClusterPool{}
	_ kitrest.SelectableFieldsProvider        = &ClusterPool{}
	_ kitrest.SupportedFieldSelectorsProvider = &ClusterPool{}
)

func (o *ClusterPool) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *ClusterPool) NamespaceScoped() bool {
	return false
}

func (o *ClusterPool) New() runtime.Object {
	return &ClusterPool{}
}

func (o *ClusterPool) NewList() runtime.Object {
	return &ClusterPoolList{}
}

func (o *ClusterPool) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("clusterpools").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *ClusterPool) CopyStatusTo(to runtime.Object) {
	to.(*ClusterPool).Status = *o.Status.DeepCopy()
}

// SelectableFields contributes ClusterPool spec fields for field-selector
// filtering (e.g. `--field-selector spec.region=eu`).
func (o *ClusterPool) SelectableFields() fields.Set {
	return fields.Set{
		"spec.region": o.Spec.Region,
	}
}

// SupportedFieldSelectors advertises the additional field-selector keys the
// ClusterPool resource supports, so the apiserver accepts them during
// list-options conversion.
func (o *ClusterPool) SupportedFieldSelectors() []string {
	return []string{"spec.region"}
}
