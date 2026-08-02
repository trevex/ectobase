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
	_ resource.Object                      = &FirewallPolicy{}
	_ resource.ObjectWithStatusSubResource = &FirewallPolicy{}
)

func (o *FirewallPolicy) GetObjectMeta() *metav1.ObjectMeta {
	return &o.ObjectMeta
}

func (o *FirewallPolicy) NamespaceScoped() bool {
	return true
}

func (o *FirewallPolicy) New() runtime.Object {
	return &FirewallPolicy{}
}

func (o *FirewallPolicy) NewList() runtime.Object {
	return &FirewallPolicyList{}
}

func (o *FirewallPolicy) GetGroupResource() schema.GroupResource {
	return SchemeGroupVersion.WithResource("firewallpolicies").GroupResource()
}

// CopyStatusTo copies the status of the receiver into the provided object.
func (o *FirewallPolicy) CopyStatusTo(to runtime.Object) {
	to.(*FirewallPolicy).Status = *o.Status.DeepCopy()
}
