// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (o *RouteBusIdentity) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *RouteBusIdentity) NamespaceScoped() bool {
	return false
}

func (o *RouteBusIdentity) New() runtime.Object {
	return &RouteBusIdentity{}
}

func (o *RouteBusIdentity) NewList() runtime.Object {
	return &RouteBusIdentityList{}
}

func (o *RouteBusIdentity) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("routebusidentities").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *RouteBusIdentity) CopyStatusTo(to runtime.Object) {
	to.(*RouteBusIdentity).Status = *o.Status.DeepCopy()
}

// SelectableFields contributes RouteBusIdentity spec fields for field-selector filtering
// (e.g. `--field-selector spec.poolName=k02`).
func (o *RouteBusIdentity) SelectableFields() fields.Set {
	return fields.Set{
		"spec.poolName": o.Spec.PoolName,
	}
}

// SupportedFieldSelectors advertises the additional field-selector keys the resource
// supports, so the apiserver accepts them during list-options conversion.
func (o *RouteBusIdentity) SupportedFieldSelectors() []string {
	return []string{"spec.poolName"}
}
