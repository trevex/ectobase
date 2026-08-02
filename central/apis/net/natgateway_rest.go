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
	_ resource.Object                      = &NATGateway{}
	_ resource.ObjectWithStatusSubResource = &NATGateway{}
)

func (o *NATGateway) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *NATGateway) NamespaceScoped() bool {
	return true
}

func (o *NATGateway) New() runtime.Object {
	return &NATGateway{}
}

func (o *NATGateway) NewList() runtime.Object {
	return &NATGatewayList{}
}

func (o *NATGateway) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("natgateways").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *NATGateway) CopyStatusTo(to runtime.Object) {
	to.(*NATGateway).Status = *o.Status.DeepCopy()
}
