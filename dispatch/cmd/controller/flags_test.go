// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"testing"
)

// --routebus-fleet-identities is what the signer trusts a spec for, so a stray blank or space must
// neither add an identity nor change a name.
func TestSplitList(t *testing.T) {
	for in, want := range map[string][]string{
		"":             nil,
		"edge":         {"edge"},
		" edge , wan ": {"edge", "wan"},
		"edge,,":       {"edge"},
	} {
		if got := splitList(in); !slices.Equal(got, want) {
			t.Errorf("splitList(%q) = %v, want %v", in, got, want)
		}
	}
}
