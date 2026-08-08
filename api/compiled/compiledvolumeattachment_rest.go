// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compiled

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (o *CompiledVolumeAttachment) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *CompiledVolumeAttachment) NamespaceScoped() bool {
	return true
}

func (o *CompiledVolumeAttachment) New() runtime.Object {
	return &CompiledVolumeAttachment{}
}

func (o *CompiledVolumeAttachment) NewList() runtime.Object {
	return &CompiledVolumeAttachmentList{}
}

func (o *CompiledVolumeAttachment) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("compiledvolumeattachments").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *CompiledVolumeAttachment) CopyStatusTo(to runtime.Object) {
	to.(*CompiledVolumeAttachment).Status = *o.Status.DeepCopy()
}

// SelectableFields contributes CompiledVolumeAttachment spec fields for
// field-selector filtering (e.g. `--field-selector spec.clusterName=c1`). The
// per-cluster broker selects on this to pull only its cluster's attachments.
func (o *CompiledVolumeAttachment) SelectableFields() fields.Set {
	return fields.Set{
		"spec.clusterName": o.Spec.ClusterName,
	}
}

// SupportedFieldSelectors advertises the additional field-selector keys the
// CompiledVolumeAttachment resource supports, so the apiserver accepts them
// during list-options conversion.
func (o *CompiledVolumeAttachment) SupportedFieldSelectors() []string {
	return []string{"spec.clusterName"}
}
