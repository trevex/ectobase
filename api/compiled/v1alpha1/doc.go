// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// +k8s:openapi-gen=true
// +k8s:deepcopy-gen=package
// +k8s:conversion-gen=github.com/trevex/ectobase/api/compiled
// +k8s:prerelease-lifecycle-gen=true
// +groupName=compiled.ectobase.dev
// +k8s:openapi-model-package=dev.ectobase.compiled.v1alpha1

// Package v1alpha1 is the v1alpha1 version of the compiled.ectobase.dev API group:
// the compiled objects (CompiledNIC, CompiledVM, CompiledContainer, CompiledVolumeAttachment)
// served by the aggregated apiserver and consumed as CRDs by the mesh control plane.
package v1alpha1
