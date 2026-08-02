// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"go.opendefense.cloud/kit/apiserver/resource"
)

var (
	_ resource.Object                     = &ClusterPool{}
	_ resource.ObjectWithStatusSubResource = &ClusterPool{}
)

func (o *ClusterPool) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *ClusterPool) NamespaceScoped() bool {
	return false
}

func (o *ClusterPool) New() runtime.Object {
	return &ClusterPool{}
}

func (o *ClusterPool) NewList() runtime.Object {
	return &ClusterPoolList{}
}

func (o *ClusterPool) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("clusterpools").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *ClusterPool) CopyStatusTo(to runtime.Object) {
	to.(*ClusterPool).Status = *o.Status.DeepCopy()
}
