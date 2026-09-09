// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (o *LBPool) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *LBPool) NamespaceScoped() bool {
	return true
}

func (o *LBPool) New() runtime.Object {
	return &LBPool{}
}

func (o *LBPool) NewList() runtime.Object {
	return &LBPoolList{}
}

func (o *LBPool) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("lbpools").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *LBPool) CopyStatusTo(to runtime.Object) {
	to.(*LBPool).Status = *o.Status.DeepCopy()
}
