// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compute

// LocalObjectReference references an object by name within the same namespace.
type LocalObjectReference struct {
	// Name is the name of the referenced object.
	Name string
}
