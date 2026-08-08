// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// LocalObjectReference references an object by name within the same namespace.
type LocalObjectReference struct {
	// Name is the name of the referenced object.
	Name string `json:"name" protobuf:"bytes,1,opt,name=name"`
}
