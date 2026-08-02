// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Hand-written internal<->versioned conversions for the net.ectobase.dev group.
//
// conversion-gen cannot generate these: the versioned structs are type aliases
// to the external api/v1alpha1 module (see doc.go), which gengo attributes to
// that external package, leaving zero package-local conversion subjects. The
// conversions below are pure field-identity copies between the internal
// (central/apis/net) and versioned (aliased api/v1alpha1) shapes, which are
// guaranteed identical by construction (the internal type mirrors the versioned
// one verbatim). Register via localSchemeBuilder so they land in the scheme
// alongside deepcopy/defaults.
//
// TECH DEBT / Task 3 recipe: every net type gets a hand-written pair here. If a
// versioned field is ever added/renamed without mirroring it in the internal
// type, THIS FILE is the single place that must be updated (and the roundtrip
// fuzz test will catch the drift).

package v1alpha1

import (
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"

	net "github.com/trevex/ectobase/central/apis/net"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds the hand-written conversion functions to the scheme.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*VPC)(nil), (*net.VPC)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_VPC_To_net_VPC(a.(*VPC), b.(*net.VPC), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.VPC)(nil), (*VPC)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_VPC_To_v1alpha1_VPC(a.(*net.VPC), b.(*VPC), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*VPCList)(nil), (*net.VPCList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_VPCList_To_net_VPCList(a.(*VPCList), b.(*net.VPCList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.VPCList)(nil), (*VPCList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_VPCList_To_v1alpha1_VPCList(a.(*net.VPCList), b.(*VPCList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*VPCSpec)(nil), (*net.VPCSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_VPCSpec_To_net_VPCSpec(a.(*VPCSpec), b.(*net.VPCSpec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.VPCSpec)(nil), (*VPCSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_VPCSpec_To_v1alpha1_VPCSpec(a.(*net.VPCSpec), b.(*VPCSpec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*VPCStatus)(nil), (*net.VPCStatus)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_VPCStatus_To_net_VPCStatus(a.(*VPCStatus), b.(*net.VPCStatus), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.VPCStatus)(nil), (*VPCStatus)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_VPCStatus_To_v1alpha1_VPCStatus(a.(*net.VPCStatus), b.(*VPCStatus), scope)
	}); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_VPC_To_net_VPC converts a versioned VPC to its internal form.
func Convert_v1alpha1_VPC_To_net_VPC(in *VPC, out *net.VPC, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_VPCSpec_To_net_VPCSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_v1alpha1_VPCStatus_To_net_VPCStatus(&in.Status, &out.Status, s)
}

// Convert_net_VPC_To_v1alpha1_VPC converts an internal VPC to its versioned form.
func Convert_net_VPC_To_v1alpha1_VPC(in *net.VPC, out *VPC, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_net_VPCSpec_To_v1alpha1_VPCSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_net_VPCStatus_To_v1alpha1_VPCStatus(&in.Status, &out.Status, s)
}

// Convert_v1alpha1_VPCList_To_net_VPCList converts a versioned VPCList to internal.
func Convert_v1alpha1_VPCList_To_net_VPCList(in *VPCList, out *net.VPCList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]net.VPC, len(in.Items))
		for i := range in.Items {
			if err := Convert_v1alpha1_VPC_To_net_VPC(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_net_VPCList_To_v1alpha1_VPCList converts an internal VPCList to versioned.
func Convert_net_VPCList_To_v1alpha1_VPCList(in *net.VPCList, out *VPCList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]VPC, len(in.Items))
		for i := range in.Items {
			if err := Convert_net_VPC_To_v1alpha1_VPC(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_v1alpha1_VPCSpec_To_net_VPCSpec converts a versioned VPCSpec to internal.
func Convert_v1alpha1_VPCSpec_To_net_VPCSpec(in *VPCSpec, out *net.VPCSpec, _ conversion.Scope) error {
	out.VNI = (*int32)(in.VNI)
	out.DefaultPolicy = (*string)(in.DefaultPolicy)
	return nil
}

// Convert_net_VPCSpec_To_v1alpha1_VPCSpec converts an internal VPCSpec to versioned.
func Convert_net_VPCSpec_To_v1alpha1_VPCSpec(in *net.VPCSpec, out *VPCSpec, _ conversion.Scope) error {
	out.VNI = (*int32)(in.VNI)
	out.DefaultPolicy = (*string)(in.DefaultPolicy)
	return nil
}

// Convert_v1alpha1_VPCStatus_To_net_VPCStatus converts a versioned VPCStatus to internal.
func Convert_v1alpha1_VPCStatus_To_net_VPCStatus(in *VPCStatus, out *net.VPCStatus, _ conversion.Scope) error {
	out.VNI = in.VNI
	out.State = in.State
	return nil
}

// Convert_net_VPCStatus_To_v1alpha1_VPCStatus converts an internal VPCStatus to versioned.
func Convert_net_VPCStatus_To_v1alpha1_VPCStatus(in *net.VPCStatus, out *VPCStatus, _ conversion.Scope) error {
	out.VNI = in.VNI
	out.State = in.State
	return nil
}
