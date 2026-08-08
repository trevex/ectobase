// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (o *VPCPeering) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *VPCPeering) NamespaceScoped() bool {
	return true
}

func (o *VPCPeering) New() runtime.Object {
	return &VPCPeering{}
}

func (o *VPCPeering) NewList() runtime.Object {
	return &VPCPeeringList{}
}

func (o *VPCPeering) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("vpcpeerings").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *VPCPeering) CopyStatusTo(to runtime.Object) {
	to.(*VPCPeering).Status = *o.Status.DeepCopy()
}
