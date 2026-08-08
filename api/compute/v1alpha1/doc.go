// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// +k8s:openapi-gen=true
// +k8s:deepcopy-gen=package
// +k8s:conversion-gen=github.com/trevex/ectobase/api/compute
// +k8s:prerelease-lifecycle-gen=true
// +groupName=compute.ectobase.dev
// +k8s:openapi-model-package=dev.ectobase.compute.v1alpha1

// Package v1alpha1 is the v1alpha1 version of the compute.ectobase.dev API group:
// the compute objects (VirtualMachine, Container) served by the aggregated apiserver
// and consumed as CRDs by the netplane control plane.
package v1alpha1
