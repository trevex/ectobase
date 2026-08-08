// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package fuzzer

import (
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/randfill"

	"github.com/trevex/ectobase/central/apis/net"
)

// Funcs returns the fuzzer functions for the net api group.
var Funcs = func(codecs runtimeserializer.CodecFactory) []any {
	return []any{
		func(s *net.VPCSpec, c randfill.Continue) {
			c.FillNoCustom(s) // fuzz self without calling this function again
		},
		func(s *net.NetworkInterfaceSpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
		func(s *net.FirewallPolicySpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
		func(s *net.LoadBalancerSpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
		func(s *net.NATGatewaySpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
		func(s *net.VPCPeeringSpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
		func(s *net.CompiledNICSpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
		func(s *net.CompiledVMSpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
		func(s *net.VolumeSpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
		func(s *net.CompiledVolumeAttachmentSpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
		func(s *net.VirtualMachineSpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
		func(s *net.ContainerSpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
		func(s *net.CompiledContainerSpec, c randfill.Continue) {
			c.FillNoCustom(s)
		},
	}
}
