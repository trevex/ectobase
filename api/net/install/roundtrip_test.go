// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/apitesting/roundtrip"

	"github.com/trevex/ectobase/api/net/fuzzer"
)

// TestRoundTripTypes exercises the HAND-WRITTEN internal<->versioned conversions
// (see central/apis/net/v1alpha1/conversion.go) via the standard apimachinery
// roundtrip harness: fuzz an internal object, convert to versioned and back, and
// assert equality. This is the guard that catches field drift between the
// internal (central/apis/net) and versioned (api/v1alpha1) shapes.
func TestRoundTripTypes(t *testing.T) {
	roundtrip.RoundTripTestForAPIGroup(t, Install, fuzzer.Funcs)
}
