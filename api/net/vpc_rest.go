// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (o *VPC) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *VPC) NamespaceScoped() bool {
	return true
}

func (o *VPC) New() runtime.Object {
	return &VPC{}
}

func (o *VPC) NewList() runtime.Object {
	return &VPCList{}
}

func (o *VPC) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("vpcs").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *VPC) CopyStatusTo(to runtime.Object) {
	to.(*VPC).Status = *o.Status.DeepCopy()
}
