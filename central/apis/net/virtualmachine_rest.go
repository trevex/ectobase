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
	_ resource.Object                      = &VirtualMachine{}
	_ resource.ObjectWithStatusSubResource = &VirtualMachine{}
)

func (o *VirtualMachine) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *VirtualMachine) NamespaceScoped() bool {
	return true
}

func (o *VirtualMachine) New() runtime.Object {
	return &VirtualMachine{}
}

func (o *VirtualMachine) NewList() runtime.Object {
	return &VirtualMachineList{}
}

func (o *VirtualMachine) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("virtualmachines").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *VirtualMachine) CopyStatusTo(to runtime.Object) {
	to.(*VirtualMachine).Status = *o.Status.DeepCopy()
}
