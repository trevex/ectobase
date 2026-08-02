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
	_ resource.Object                      = &LoadBalancer{}
	_ resource.ObjectWithStatusSubResource = &LoadBalancer{}
)

func (o *LoadBalancer) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *LoadBalancer) NamespaceScoped() bool {
	return true
}

func (o *LoadBalancer) New() runtime.Object {
	return &LoadBalancer{}
}

func (o *LoadBalancer) NewList() runtime.Object {
	return &LoadBalancerList{}
}

func (o *LoadBalancer) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("loadbalancers").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *LoadBalancer) CopyStatusTo(to runtime.Object) {
	to.(*LoadBalancer).Status = *o.Status.DeepCopy()
}
