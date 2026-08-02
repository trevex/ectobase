// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

// The canonical versioned VPC structs live in the external api module. Re-export
// them here as aliases so the aggregated apiserver's codegen (conversion/openapi)
// can operate on the net.ectobase.dev/v1alpha1 view from within the central
// module while conversion-gen resolves the aliases back to api/v1alpha1's fields.
type (
	VPC       = netv1.VPC
	VPCList   = netv1.VPCList
	VPCSpec   = netv1.VPCSpec
	VPCStatus = netv1.VPCStatus
)

// GroupName is the API group name for these objects.
const GroupName = netv1.GroupName

// SchemeGroupVersion is the group-version used to register these objects.
var SchemeGroupVersion = netv1.SchemeGroupVersion

var (
	// SchemeBuilder collects this package's scheme init functions. Manually
	// written funcs are registered here; the generated conversion/defaults
	// funcs register themselves into localSchemeBuilder from their init().
	SchemeBuilder      runtime.SchemeBuilder
	localSchemeBuilder = &SchemeBuilder
	// AddToScheme registers the group/version, its known types, and the
	// generated conversion + defaulting funcs with a scheme.
	AddToScheme = localSchemeBuilder.AddToScheme
)

func init() {
	localSchemeBuilder.Register(addKnownTypes, addDefaultingFuncs)
}

// addKnownTypes registers the (aliased, external) versioned types with the scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&VPC{},
		&VPCList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// Resource takes an unqualified resource and returns a Group-qualified GroupResource.
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

// Kind takes an unqualified kind and returns a Group-qualified GroupKind.
func Kind(kind string) schema.GroupKind {
	return SchemeGroupVersion.WithKind(kind).GroupKind()
}
