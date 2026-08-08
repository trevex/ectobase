// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (o *Volume) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *Volume) NamespaceScoped() bool {
	return true
}

func (o *Volume) New() runtime.Object {
	return &Volume{}
}

func (o *Volume) NewList() runtime.Object {
	return &VolumeList{}
}

func (o *Volume) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("volumes").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *Volume) CopyStatusTo(to runtime.Object) {
	to.(*Volume).Status = *o.Status.DeepCopy()
}
