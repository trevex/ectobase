// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compiled

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (o *CompiledVM) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *CompiledVM) NamespaceScoped() bool {
	return true
}

func (o *CompiledVM) New() runtime.Object {
	return &CompiledVM{}
}

func (o *CompiledVM) NewList() runtime.Object {
	return &CompiledVMList{}
}

func (o *CompiledVM) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("compiledvms").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *CompiledVM) CopyStatusTo(to runtime.Object) {
	to.(*CompiledVM).Status = *o.Status.DeepCopy()
}

// SelectableFields contributes CompiledVM spec fields for field-selector
// filtering (e.g. `--field-selector spec.clusterName=c1`). The per-cluster
// broker selects on this to pull only its cluster's compiled VMs.
func (o *CompiledVM) SelectableFields() fields.Set {
	return fields.Set{
		"spec.clusterName": o.Spec.ClusterName,
	}
}

// SupportedFieldSelectors advertises the additional field-selector keys the
// CompiledVM resource supports, so the apiserver accepts them during
// list-options conversion.
func (o *CompiledVM) SupportedFieldSelectors() []string {
	return []string{"spec.clusterName"}
}
