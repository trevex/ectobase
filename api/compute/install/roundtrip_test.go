// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/apitesting/roundtrip"

	"github.com/trevex/ectobase/api/compute/fuzzer"
)

// TestRoundTripTypes exercises the generated internal<->versioned conversions
// (api/compute/v1alpha1/zz_generated.conversion.go) via the standard apimachinery
// roundtrip harness: fuzz an internal object, convert to versioned and back, and
// assert equality. This is the guard that catches field drift between the
// internal (api/compute) and versioned (api/compute/v1alpha1) shapes.
func TestRoundTripTypes(t *testing.T) {
	roundtrip.RoundTripTestForAPIGroup(t, Install, fuzzer.Funcs)
}
