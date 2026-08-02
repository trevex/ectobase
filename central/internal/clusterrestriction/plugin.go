// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package clusterrestriction

import (
	"context"
	"errors"
	"io"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
)

// PluginName is the admission plugin name registered with the apiserver.
const PluginName = "ClusterRestriction"

// Register wires the ClusterRestriction validating admission plugin into the
// given plugin registry. It is a no-config plugin.
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return &plugin{}, nil
	})
}

// plugin is the k8s admission adapter over the pure Review decision.
type plugin struct{}

var _ admission.ValidationInterface = (*plugin)(nil)

// Handles returns true for the operations this validating plugin cares about.
// spec.clusterName can be introduced on CREATE or changed on UPDATE, and pool
// status is written via UPDATE, so both are handled.
func (p *plugin) Handles(op admission.Operation) bool {
	return op == admission.Create || op == admission.Update
}

// Validate maps admission.Attributes -> Attr and applies the pure Review decision.
func (p *plugin) Validate(_ context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	attr := Attr{
		Resource:        a.GetResource().Resource,
		Name:            a.GetName(),
		Subresource:     a.GetSubresource(),
		SetsClusterName: setsClusterName(a),
	}
	if allow, msg := Review(a.GetUserInfo(), attr); !allow {
		return admission.NewForbidden(a, errors.New(msg))
	}
	return nil
}

// setsClusterName reports whether the write introduces or changes spec.clusterName.
// It reads spec.clusterName generically (works for typed or unstructured objects)
// so it is robust across VirtualMachine, CompiledNIC and CompiledWorkload. Objects
// without a spec.clusterName (e.g. VPC, ClusterPool) always report false.
//
// A ToUnstructured conversion error yields "" (fail open), which is safe here — NOT
// a bypass primitive: admission runs post-decode, so the object is already a valid,
// storable API type, and the same reflective JSON machinery serializes it to etcd.
// An object that fails ToUnstructured on spec therefore cannot persist a
// spec.clusterName either. Fail-closed would be strictly worse: it would deny every
// broker write of any (future) type that can't round-trip, breaking the broker's own
// pool-status heartbeat — a real availability regression against an unreachable risk.
func setsClusterName(a admission.Attributes) bool {
	newVal := clusterNameOf(a.GetObject())
	switch a.GetOperation() {
	case admission.Create:
		return newVal != ""
	case admission.Update:
		return newVal != clusterNameOf(a.GetOldObject())
	default:
		return false
	}
}

// clusterNameOf extracts spec.clusterName from an arbitrary runtime.Object,
// returning "" when absent or on any conversion error.
func clusterNameOf(obj runtime.Object) string {
	if obj == nil {
		return ""
	}
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return ""
	}
	v, _, err := unstructured.NestedString(m, "spec", "clusterName")
	if err != nil {
		return ""
	}
	return v
}
