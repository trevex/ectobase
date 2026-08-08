// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package fuzzer

import (
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/randfill"

	"github.com/trevex/ectobase/api/compute"
)

// Funcs returns the fuzzer functions for the compute api group.
var Funcs = func(codecs runtimeserializer.CodecFactory) []any {
	return []any{
		func(s *compute.VirtualMachineSpec, c randfill.Continue) {
			c.FillNoCustom(s) // fuzz self without calling this function again
		},
		func(s *compute.ContainerSpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
	}
}
