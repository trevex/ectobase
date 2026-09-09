// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (o *Subnet) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *Subnet) NamespaceScoped() bool {
	return true
}

func (o *Subnet) New() runtime.Object {
	return &Subnet{}
}

func (o *Subnet) NewList() runtime.Object {
	return &SubnetList{}
}

func (o *Subnet) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("subnets").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *Subnet) CopyStatusTo(to runtime.Object) {
	to.(*Subnet).Status = *o.Status.DeepCopy()
}
