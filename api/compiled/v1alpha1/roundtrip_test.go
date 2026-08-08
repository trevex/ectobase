// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"
)

func TestCompiledPeerImportDeepCopyIsolation(t *testing.T) {
	orig := &CompiledNIC{
		Spec: CompiledNICSpec{
			PeerImports: []CompiledPeerImport{
				{PeerVNI: 200, ImportPrefixes: []string{"10.1.0.0/24"}},
			},
		},
	}

	out := orig.DeepCopy()

	// Mutate the copy's ImportPrefixes element.
	out.Spec.PeerImports[0].ImportPrefixes[0] = "99.99.99.0/24"

	// The original must be unchanged.
	if orig.Spec.PeerImports[0].ImportPrefixes[0] != "10.1.0.0/24" {
		t.Fatalf("deepcopy aliasing detected: original ImportPrefixes[0] mutated to %q",
			orig.Spec.PeerImports[0].ImportPrefixes[0])
	}
}
