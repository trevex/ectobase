// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package clusterrestriction

import (
	"context"
	"errors"
	"io"
	"reflect"

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
// It reads the Spec.ClusterName field generically so it is robust across
// VirtualMachine and CompiledNIC. Objects without such a field
// (e.g. VPC, ClusterPool) always report false.
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

// clusterNameOf extracts Spec.ClusterName from an arbitrary runtime.Object via
// reflection on the Go field, returning "" when the field is absent.
//
// Reflection (not ToUnstructured + json path) is deliberate and load-bearing for
// the security guarantee: the aggregated apiserver hands admission the INTERNAL
// object (api/net.VirtualMachine etc.), whose structs carry NO json tags,
// so ToUnstructured would key the map by Go field names ("Spec"/"ClusterName") and a
// "spec.clusterName" lookup would silently miss — failing the guard open. Reflecting
// on the Go field name works for both the internal and versioned representations.
func clusterNameOf(obj runtime.Object) string {
	if obj == nil {
		return ""
	}
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}
	spec := v.FieldByName("Spec")
	if !spec.IsValid() || spec.Kind() != reflect.Struct {
		return ""
	}
	cn := spec.FieldByName("ClusterName")
	if !cn.IsValid() || cn.Kind() != reflect.String {
		return ""
	}
	return cn.String()
}
