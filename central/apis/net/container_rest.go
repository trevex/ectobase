// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"go.opendefense.cloud/kit/apiserver/resource"
)

var (
	_ resource.Object                      = &Container{}
	_ resource.ObjectWithStatusSubResource = &Container{}
)

func (o *Container) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *Container) NamespaceScoped() bool {
	return true
}

func (o *Container) New() runtime.Object {
	return &Container{}
}

func (o *Container) NewList() runtime.Object {
	return &ContainerList{}
}

func (o *Container) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("containers").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *Container) CopyStatusTo(to runtime.Object) {
	to.(*Container).Status = *o.Status.DeepCopy()
}
