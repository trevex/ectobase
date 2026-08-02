// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// +k8s:openapi-gen=true
// +k8s:deepcopy-gen=package
// +k8s:defaulter-gen=TypeMeta
// +k8s:prerelease-lifecycle-gen=true
// +groupName=net.ectobase.dev
// +k8s:openapi-model-package=dev.ectobase.net.v1alpha1

// Package v1alpha1 is the central-side versioned view of the net.ectobase.dev
// API group. The canonical versioned structs live in the external api module
// (github.com/trevex/ectobase/api/v1alpha1); this package re-exports them as
// aliases (aliases.go).
//
// NOTE (codegen spike, Task 2): conversion-gen CANNOT generate the
// internal<->versioned conversions for this group. Because the versioned
// structs are type ALIASES to api/v1alpha1, gengo attributes them to that
// external package, so conversion-gen finds zero package-local types to convert
// (verified: it emits an empty RegisterConversions; --extra-peer-dirs does not
// help — aliases are never conversion "subjects"). The +k8s:conversion-gen
// marker is therefore intentionally ABSENT and the conversions are HAND-WRITTEN
// in conversion.go as field-identity copies (registered via localSchemeBuilder).
// This is the established recipe for the remaining net types (Task 3).
package v1alpha1
