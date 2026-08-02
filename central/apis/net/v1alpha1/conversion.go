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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
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

	// --- NetworkInterface ---
	if err := s.AddGeneratedConversionFunc((*NetworkInterface)(nil), (*net.NetworkInterface)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_NetworkInterface_To_net_NetworkInterface(a.(*NetworkInterface), b.(*net.NetworkInterface), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.NetworkInterface)(nil), (*NetworkInterface)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_NetworkInterface_To_v1alpha1_NetworkInterface(a.(*net.NetworkInterface), b.(*NetworkInterface), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*NetworkInterfaceList)(nil), (*net.NetworkInterfaceList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_NetworkInterfaceList_To_net_NetworkInterfaceList(a.(*NetworkInterfaceList), b.(*net.NetworkInterfaceList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.NetworkInterfaceList)(nil), (*NetworkInterfaceList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_NetworkInterfaceList_To_v1alpha1_NetworkInterfaceList(a.(*net.NetworkInterfaceList), b.(*NetworkInterfaceList), scope)
	}); err != nil {
		return err
	}

	// --- FirewallPolicy ---
	if err := s.AddGeneratedConversionFunc((*FirewallPolicy)(nil), (*net.FirewallPolicy)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_FirewallPolicy_To_net_FirewallPolicy(a.(*FirewallPolicy), b.(*net.FirewallPolicy), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.FirewallPolicy)(nil), (*FirewallPolicy)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_FirewallPolicy_To_v1alpha1_FirewallPolicy(a.(*net.FirewallPolicy), b.(*FirewallPolicy), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*FirewallPolicyList)(nil), (*net.FirewallPolicyList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_FirewallPolicyList_To_net_FirewallPolicyList(a.(*FirewallPolicyList), b.(*net.FirewallPolicyList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.FirewallPolicyList)(nil), (*FirewallPolicyList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_FirewallPolicyList_To_v1alpha1_FirewallPolicyList(a.(*net.FirewallPolicyList), b.(*FirewallPolicyList), scope)
	}); err != nil {
		return err
	}

	// --- FloatingIP ---
	if err := s.AddGeneratedConversionFunc((*FloatingIP)(nil), (*net.FloatingIP)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_FloatingIP_To_net_FloatingIP(a.(*FloatingIP), b.(*net.FloatingIP), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.FloatingIP)(nil), (*FloatingIP)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_FloatingIP_To_v1alpha1_FloatingIP(a.(*net.FloatingIP), b.(*FloatingIP), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*FloatingIPList)(nil), (*net.FloatingIPList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_FloatingIPList_To_net_FloatingIPList(a.(*FloatingIPList), b.(*net.FloatingIPList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.FloatingIPList)(nil), (*FloatingIPList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_FloatingIPList_To_v1alpha1_FloatingIPList(a.(*net.FloatingIPList), b.(*FloatingIPList), scope)
	}); err != nil {
		return err
	}

	// --- LoadBalancer ---
	if err := s.AddGeneratedConversionFunc((*LoadBalancer)(nil), (*net.LoadBalancer)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_LoadBalancer_To_net_LoadBalancer(a.(*LoadBalancer), b.(*net.LoadBalancer), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.LoadBalancer)(nil), (*LoadBalancer)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_LoadBalancer_To_v1alpha1_LoadBalancer(a.(*net.LoadBalancer), b.(*LoadBalancer), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*LoadBalancerList)(nil), (*net.LoadBalancerList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_LoadBalancerList_To_net_LoadBalancerList(a.(*LoadBalancerList), b.(*net.LoadBalancerList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.LoadBalancerList)(nil), (*LoadBalancerList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_LoadBalancerList_To_v1alpha1_LoadBalancerList(a.(*net.LoadBalancerList), b.(*LoadBalancerList), scope)
	}); err != nil {
		return err
	}

	// --- NATGateway ---
	if err := s.AddGeneratedConversionFunc((*NATGateway)(nil), (*net.NATGateway)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_NATGateway_To_net_NATGateway(a.(*NATGateway), b.(*net.NATGateway), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.NATGateway)(nil), (*NATGateway)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_NATGateway_To_v1alpha1_NATGateway(a.(*net.NATGateway), b.(*NATGateway), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*NATGatewayList)(nil), (*net.NATGatewayList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_NATGatewayList_To_net_NATGatewayList(a.(*NATGatewayList), b.(*net.NATGatewayList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.NATGatewayList)(nil), (*NATGatewayList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_NATGatewayList_To_v1alpha1_NATGatewayList(a.(*net.NATGatewayList), b.(*NATGatewayList), scope)
	}); err != nil {
		return err
	}

	// --- VPCPeering ---
	if err := s.AddGeneratedConversionFunc((*VPCPeering)(nil), (*net.VPCPeering)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_VPCPeering_To_net_VPCPeering(a.(*VPCPeering), b.(*net.VPCPeering), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.VPCPeering)(nil), (*VPCPeering)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_VPCPeering_To_v1alpha1_VPCPeering(a.(*net.VPCPeering), b.(*VPCPeering), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*VPCPeeringList)(nil), (*net.VPCPeeringList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_VPCPeeringList_To_net_VPCPeeringList(a.(*VPCPeeringList), b.(*net.VPCPeeringList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.VPCPeeringList)(nil), (*VPCPeeringList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_VPCPeeringList_To_v1alpha1_VPCPeeringList(a.(*net.VPCPeeringList), b.(*VPCPeeringList), scope)
	}); err != nil {
		return err
	}

	// --- CompiledNIC ---
	if err := s.AddGeneratedConversionFunc((*CompiledNIC)(nil), (*net.CompiledNIC)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_CompiledNIC_To_net_CompiledNIC(a.(*CompiledNIC), b.(*net.CompiledNIC), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.CompiledNIC)(nil), (*CompiledNIC)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_CompiledNIC_To_v1alpha1_CompiledNIC(a.(*net.CompiledNIC), b.(*CompiledNIC), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*CompiledNICList)(nil), (*net.CompiledNICList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_CompiledNICList_To_net_CompiledNICList(a.(*CompiledNICList), b.(*net.CompiledNICList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.CompiledNICList)(nil), (*CompiledNICList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_CompiledNICList_To_v1alpha1_CompiledNICList(a.(*net.CompiledNICList), b.(*CompiledNICList), scope)
	}); err != nil {
		return err
	}

	// --- CompiledVM ---
	if err := s.AddGeneratedConversionFunc((*CompiledVM)(nil), (*net.CompiledVM)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_CompiledVM_To_net_CompiledVM(a.(*CompiledVM), b.(*net.CompiledVM), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.CompiledVM)(nil), (*CompiledVM)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_CompiledVM_To_v1alpha1_CompiledVM(a.(*net.CompiledVM), b.(*CompiledVM), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*CompiledVMList)(nil), (*net.CompiledVMList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_CompiledVMList_To_net_CompiledVMList(a.(*CompiledVMList), b.(*net.CompiledVMList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.CompiledVMList)(nil), (*CompiledVMList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_CompiledVMList_To_v1alpha1_CompiledVMList(a.(*net.CompiledVMList), b.(*CompiledVMList), scope)
	}); err != nil {
		return err
	}

	// --- VirtualMachine ---
	if err := s.AddGeneratedConversionFunc((*VirtualMachine)(nil), (*net.VirtualMachine)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_VirtualMachine_To_net_VirtualMachine(a.(*VirtualMachine), b.(*net.VirtualMachine), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.VirtualMachine)(nil), (*VirtualMachine)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_VirtualMachine_To_v1alpha1_VirtualMachine(a.(*net.VirtualMachine), b.(*VirtualMachine), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*VirtualMachineList)(nil), (*net.VirtualMachineList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_VirtualMachineList_To_net_VirtualMachineList(a.(*VirtualMachineList), b.(*net.VirtualMachineList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*net.VirtualMachineList)(nil), (*VirtualMachineList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_net_VirtualMachineList_To_v1alpha1_VirtualMachineList(a.(*net.VirtualMachineList), b.(*VirtualMachineList), scope)
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
	out.VNI = in.VNI
	out.DefaultPolicy = in.DefaultPolicy
	return nil
}

// Convert_net_VPCSpec_To_v1alpha1_VPCSpec converts an internal VPCSpec to versioned.
func Convert_net_VPCSpec_To_v1alpha1_VPCSpec(in *net.VPCSpec, out *VPCSpec, _ conversion.Scope) error {
	out.VNI = in.VNI
	out.DefaultPolicy = in.DefaultPolicy
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

// ============================ shared nested ============================

// Convert_v1alpha1_LocalObjectReference_To_net_LocalObjectReference converts a versioned ref to internal.
func Convert_v1alpha1_LocalObjectReference_To_net_LocalObjectReference(in *LocalObjectReference, out *net.LocalObjectReference, _ conversion.Scope) error {
	out.Name = in.Name
	return nil
}

// Convert_net_LocalObjectReference_To_v1alpha1_LocalObjectReference converts an internal ref to versioned.
func Convert_net_LocalObjectReference_To_v1alpha1_LocalObjectReference(in *net.LocalObjectReference, out *LocalObjectReference, _ conversion.Scope) error {
	out.Name = in.Name
	return nil
}

// Convert_v1alpha1_PortStatus_To_net_PortStatus converts a versioned PortStatus to internal.
func Convert_v1alpha1_PortStatus_To_net_PortStatus(in *PortStatus, out *net.PortStatus, _ conversion.Scope) error {
	out.Type = string(in.Type)
	out.Name = in.Name
	out.PCIAddress = in.PCIAddress
	return nil
}

// Convert_net_PortStatus_To_v1alpha1_PortStatus converts an internal PortStatus to versioned.
func Convert_net_PortStatus_To_v1alpha1_PortStatus(in *net.PortStatus, out *PortStatus, _ conversion.Scope) error {
	out.Type = netv1.PortType(in.Type)
	out.Name = in.Name
	out.PCIAddress = in.PCIAddress
	return nil
}

// ============================ NetworkInterface ============================

// Convert_v1alpha1_NetworkInterface_To_net_NetworkInterface converts a versioned NetworkInterface to internal.
func Convert_v1alpha1_NetworkInterface_To_net_NetworkInterface(in *NetworkInterface, out *net.NetworkInterface, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_NetworkInterfaceSpec_To_net_NetworkInterfaceSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_v1alpha1_NetworkInterfaceStatus_To_net_NetworkInterfaceStatus(&in.Status, &out.Status, s)
}

// Convert_net_NetworkInterface_To_v1alpha1_NetworkInterface converts an internal NetworkInterface to versioned.
func Convert_net_NetworkInterface_To_v1alpha1_NetworkInterface(in *net.NetworkInterface, out *NetworkInterface, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_net_NetworkInterfaceSpec_To_v1alpha1_NetworkInterfaceSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_net_NetworkInterfaceStatus_To_v1alpha1_NetworkInterfaceStatus(&in.Status, &out.Status, s)
}

// Convert_v1alpha1_NetworkInterfaceList_To_net_NetworkInterfaceList converts a versioned list to internal.
func Convert_v1alpha1_NetworkInterfaceList_To_net_NetworkInterfaceList(in *NetworkInterfaceList, out *net.NetworkInterfaceList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]net.NetworkInterface, len(in.Items))
		for i := range in.Items {
			if err := Convert_v1alpha1_NetworkInterface_To_net_NetworkInterface(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_net_NetworkInterfaceList_To_v1alpha1_NetworkInterfaceList converts an internal list to versioned.
func Convert_net_NetworkInterfaceList_To_v1alpha1_NetworkInterfaceList(in *net.NetworkInterfaceList, out *NetworkInterfaceList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]NetworkInterface, len(in.Items))
		for i := range in.Items {
			if err := Convert_net_NetworkInterface_To_v1alpha1_NetworkInterface(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_v1alpha1_NetworkInterfaceSpec_To_net_NetworkInterfaceSpec converts a versioned spec to internal.
func Convert_v1alpha1_NetworkInterfaceSpec_To_net_NetworkInterfaceSpec(in *NetworkInterfaceSpec, out *net.NetworkInterfaceSpec, s conversion.Scope) error {
	if err := Convert_v1alpha1_LocalObjectReference_To_net_LocalObjectReference(&in.VPCRef, &out.VPCRef, s); err != nil {
		return err
	}
	out.IPs = in.IPs
	out.MAC = in.MAC
	out.NodeName = in.NodeName
	if in.QoS != nil {
		out.QoS = &net.InterfaceQoS{}
		if err := Convert_v1alpha1_InterfaceQoS_To_net_InterfaceQoS(in.QoS, out.QoS, s); err != nil {
			return err
		}
	} else {
		out.QoS = nil
	}
	return nil
}

// Convert_net_NetworkInterfaceSpec_To_v1alpha1_NetworkInterfaceSpec converts an internal spec to versioned.
func Convert_net_NetworkInterfaceSpec_To_v1alpha1_NetworkInterfaceSpec(in *net.NetworkInterfaceSpec, out *NetworkInterfaceSpec, s conversion.Scope) error {
	if err := Convert_net_LocalObjectReference_To_v1alpha1_LocalObjectReference(&in.VPCRef, &out.VPCRef, s); err != nil {
		return err
	}
	out.IPs = in.IPs
	out.MAC = in.MAC
	out.NodeName = in.NodeName
	if in.QoS != nil {
		out.QoS = &InterfaceQoS{}
		if err := Convert_net_InterfaceQoS_To_v1alpha1_InterfaceQoS(in.QoS, out.QoS, s); err != nil {
			return err
		}
	} else {
		out.QoS = nil
	}
	return nil
}

// Convert_v1alpha1_InterfaceQoS_To_net_InterfaceQoS converts a versioned InterfaceQoS to internal.
func Convert_v1alpha1_InterfaceQoS_To_net_InterfaceQoS(in *InterfaceQoS, out *net.InterfaceQoS, s conversion.Scope) error {
	if in.Egress != nil {
		out.Egress = &net.EgressQoS{}
		if err := Convert_v1alpha1_EgressQoS_To_net_EgressQoS(in.Egress, out.Egress, s); err != nil {
			return err
		}
	} else {
		out.Egress = nil
	}
	if in.Ingress != nil {
		out.Ingress = &net.RateLimit{}
		if err := Convert_v1alpha1_RateLimit_To_net_RateLimit(in.Ingress, out.Ingress, s); err != nil {
			return err
		}
	} else {
		out.Ingress = nil
	}
	return nil
}

// Convert_net_InterfaceQoS_To_v1alpha1_InterfaceQoS converts an internal InterfaceQoS to versioned.
func Convert_net_InterfaceQoS_To_v1alpha1_InterfaceQoS(in *net.InterfaceQoS, out *InterfaceQoS, s conversion.Scope) error {
	if in.Egress != nil {
		out.Egress = &EgressQoS{}
		if err := Convert_net_EgressQoS_To_v1alpha1_EgressQoS(in.Egress, out.Egress, s); err != nil {
			return err
		}
	} else {
		out.Egress = nil
	}
	if in.Ingress != nil {
		out.Ingress = &RateLimit{}
		if err := Convert_net_RateLimit_To_v1alpha1_RateLimit(in.Ingress, out.Ingress, s); err != nil {
			return err
		}
	} else {
		out.Ingress = nil
	}
	return nil
}

// Convert_v1alpha1_EgressQoS_To_net_EgressQoS converts a versioned EgressQoS to internal.
func Convert_v1alpha1_EgressQoS_To_net_EgressQoS(in *EgressQoS, out *net.EgressQoS, _ conversion.Scope) error {
	out.RateMbps = in.RateMbps
	out.BurstKB = in.BurstKB
	out.PublicMbps = in.PublicMbps
	return nil
}

// Convert_net_EgressQoS_To_v1alpha1_EgressQoS converts an internal EgressQoS to versioned.
func Convert_net_EgressQoS_To_v1alpha1_EgressQoS(in *net.EgressQoS, out *EgressQoS, _ conversion.Scope) error {
	out.RateMbps = in.RateMbps
	out.BurstKB = in.BurstKB
	out.PublicMbps = in.PublicMbps
	return nil
}

// Convert_v1alpha1_RateLimit_To_net_RateLimit converts a versioned RateLimit to internal.
func Convert_v1alpha1_RateLimit_To_net_RateLimit(in *RateLimit, out *net.RateLimit, _ conversion.Scope) error {
	out.RateMbps = in.RateMbps
	out.BurstKB = in.BurstKB
	return nil
}

// Convert_net_RateLimit_To_v1alpha1_RateLimit converts an internal RateLimit to versioned.
func Convert_net_RateLimit_To_v1alpha1_RateLimit(in *net.RateLimit, out *RateLimit, _ conversion.Scope) error {
	out.RateMbps = in.RateMbps
	out.BurstKB = in.BurstKB
	return nil
}

// Convert_v1alpha1_NetworkInterfaceStatus_To_net_NetworkInterfaceStatus converts a versioned status to internal.
func Convert_v1alpha1_NetworkInterfaceStatus_To_net_NetworkInterfaceStatus(in *NetworkInterfaceStatus, out *net.NetworkInterfaceStatus, s conversion.Scope) error {
	out.VNI = in.VNI
	out.UnderlayRoute = in.UnderlayRoute
	if in.Port != nil {
		out.Port = &net.PortStatus{}
		if err := Convert_v1alpha1_PortStatus_To_net_PortStatus(in.Port, out.Port, s); err != nil {
			return err
		}
	} else {
		out.Port = nil
	}
	out.State = in.State
	return nil
}

// Convert_net_NetworkInterfaceStatus_To_v1alpha1_NetworkInterfaceStatus converts an internal status to versioned.
func Convert_net_NetworkInterfaceStatus_To_v1alpha1_NetworkInterfaceStatus(in *net.NetworkInterfaceStatus, out *NetworkInterfaceStatus, s conversion.Scope) error {
	out.VNI = in.VNI
	out.UnderlayRoute = in.UnderlayRoute
	if in.Port != nil {
		out.Port = &PortStatus{}
		if err := Convert_net_PortStatus_To_v1alpha1_PortStatus(in.Port, out.Port, s); err != nil {
			return err
		}
	} else {
		out.Port = nil
	}
	out.State = in.State
	return nil
}

// ============================ FirewallPolicy ============================

// Convert_v1alpha1_FirewallPolicy_To_net_FirewallPolicy converts a versioned FirewallPolicy to internal.
func Convert_v1alpha1_FirewallPolicy_To_net_FirewallPolicy(in *FirewallPolicy, out *net.FirewallPolicy, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_FirewallPolicySpec_To_net_FirewallPolicySpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	out.Status = net.FirewallPolicyStatus{}
	return nil
}

// Convert_net_FirewallPolicy_To_v1alpha1_FirewallPolicy converts an internal FirewallPolicy to versioned.
func Convert_net_FirewallPolicy_To_v1alpha1_FirewallPolicy(in *net.FirewallPolicy, out *FirewallPolicy, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_net_FirewallPolicySpec_To_v1alpha1_FirewallPolicySpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	out.Status = FirewallPolicyStatus{}
	return nil
}

// Convert_v1alpha1_FirewallPolicyList_To_net_FirewallPolicyList converts a versioned list to internal.
func Convert_v1alpha1_FirewallPolicyList_To_net_FirewallPolicyList(in *FirewallPolicyList, out *net.FirewallPolicyList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]net.FirewallPolicy, len(in.Items))
		for i := range in.Items {
			if err := Convert_v1alpha1_FirewallPolicy_To_net_FirewallPolicy(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_net_FirewallPolicyList_To_v1alpha1_FirewallPolicyList converts an internal list to versioned.
func Convert_net_FirewallPolicyList_To_v1alpha1_FirewallPolicyList(in *net.FirewallPolicyList, out *FirewallPolicyList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]FirewallPolicy, len(in.Items))
		for i := range in.Items {
			if err := Convert_net_FirewallPolicy_To_v1alpha1_FirewallPolicy(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_v1alpha1_FirewallPolicySpec_To_net_FirewallPolicySpec converts a versioned spec to internal.
func Convert_v1alpha1_FirewallPolicySpec_To_net_FirewallPolicySpec(in *FirewallPolicySpec, out *net.FirewallPolicySpec, s conversion.Scope) error {
	out.InterfaceSelector = in.InterfaceSelector.DeepCopy()
	if in.Ingress != nil {
		out.Ingress = make([]net.FirewallPolicyRule, len(in.Ingress))
		for i := range in.Ingress {
			if err := Convert_v1alpha1_FirewallPolicyRule_To_net_FirewallPolicyRule(&in.Ingress[i], &out.Ingress[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Ingress = nil
	}
	if in.Egress != nil {
		out.Egress = make([]net.FirewallPolicyRule, len(in.Egress))
		for i := range in.Egress {
			if err := Convert_v1alpha1_FirewallPolicyRule_To_net_FirewallPolicyRule(&in.Egress[i], &out.Egress[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Egress = nil
	}
	return nil
}

// Convert_net_FirewallPolicySpec_To_v1alpha1_FirewallPolicySpec converts an internal spec to versioned.
func Convert_net_FirewallPolicySpec_To_v1alpha1_FirewallPolicySpec(in *net.FirewallPolicySpec, out *FirewallPolicySpec, s conversion.Scope) error {
	out.InterfaceSelector = in.InterfaceSelector.DeepCopy()
	if in.Ingress != nil {
		out.Ingress = make([]FirewallPolicyRule, len(in.Ingress))
		for i := range in.Ingress {
			if err := Convert_net_FirewallPolicyRule_To_v1alpha1_FirewallPolicyRule(&in.Ingress[i], &out.Ingress[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Ingress = nil
	}
	if in.Egress != nil {
		out.Egress = make([]FirewallPolicyRule, len(in.Egress))
		for i := range in.Egress {
			if err := Convert_net_FirewallPolicyRule_To_v1alpha1_FirewallPolicyRule(&in.Egress[i], &out.Egress[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Egress = nil
	}
	return nil
}

// Convert_v1alpha1_FirewallPolicyRule_To_net_FirewallPolicyRule converts a versioned rule to internal.
func Convert_v1alpha1_FirewallPolicyRule_To_net_FirewallPolicyRule(in *FirewallPolicyRule, out *net.FirewallPolicyRule, _ conversion.Scope) error {
	out.CIDR = in.CIDR
	out.Proto = in.Proto
	out.Port = in.Port
	out.Action = in.Action
	return nil
}

// Convert_net_FirewallPolicyRule_To_v1alpha1_FirewallPolicyRule converts an internal rule to versioned.
func Convert_net_FirewallPolicyRule_To_v1alpha1_FirewallPolicyRule(in *net.FirewallPolicyRule, out *FirewallPolicyRule, _ conversion.Scope) error {
	out.CIDR = in.CIDR
	out.Proto = in.Proto
	out.Port = in.Port
	out.Action = in.Action
	return nil
}

// ============================ FloatingIP ============================

// Convert_v1alpha1_FloatingIP_To_net_FloatingIP converts a versioned FloatingIP to internal.
func Convert_v1alpha1_FloatingIP_To_net_FloatingIP(in *FloatingIP, out *net.FloatingIP, _ conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.Spec = net.FloatingIPSpec{}
	out.Status = net.FloatingIPStatus{}
	return nil
}

// Convert_net_FloatingIP_To_v1alpha1_FloatingIP converts an internal FloatingIP to versioned.
func Convert_net_FloatingIP_To_v1alpha1_FloatingIP(in *net.FloatingIP, out *FloatingIP, _ conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.Spec = FloatingIPSpec{}
	out.Status = FloatingIPStatus{}
	return nil
}

// Convert_v1alpha1_FloatingIPList_To_net_FloatingIPList converts a versioned list to internal.
func Convert_v1alpha1_FloatingIPList_To_net_FloatingIPList(in *FloatingIPList, out *net.FloatingIPList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]net.FloatingIP, len(in.Items))
		for i := range in.Items {
			if err := Convert_v1alpha1_FloatingIP_To_net_FloatingIP(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_net_FloatingIPList_To_v1alpha1_FloatingIPList converts an internal list to versioned.
func Convert_net_FloatingIPList_To_v1alpha1_FloatingIPList(in *net.FloatingIPList, out *FloatingIPList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]FloatingIP, len(in.Items))
		for i := range in.Items {
			if err := Convert_net_FloatingIP_To_v1alpha1_FloatingIP(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// ============================ LoadBalancer ============================

// Convert_v1alpha1_LoadBalancer_To_net_LoadBalancer converts a versioned LoadBalancer to internal.
func Convert_v1alpha1_LoadBalancer_To_net_LoadBalancer(in *LoadBalancer, out *net.LoadBalancer, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_LoadBalancerSpec_To_net_LoadBalancerSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_v1alpha1_LoadBalancerStatus_To_net_LoadBalancerStatus(&in.Status, &out.Status, s)
}

// Convert_net_LoadBalancer_To_v1alpha1_LoadBalancer converts an internal LoadBalancer to versioned.
func Convert_net_LoadBalancer_To_v1alpha1_LoadBalancer(in *net.LoadBalancer, out *LoadBalancer, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_net_LoadBalancerSpec_To_v1alpha1_LoadBalancerSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_net_LoadBalancerStatus_To_v1alpha1_LoadBalancerStatus(&in.Status, &out.Status, s)
}

// Convert_v1alpha1_LoadBalancerList_To_net_LoadBalancerList converts a versioned list to internal.
func Convert_v1alpha1_LoadBalancerList_To_net_LoadBalancerList(in *LoadBalancerList, out *net.LoadBalancerList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]net.LoadBalancer, len(in.Items))
		for i := range in.Items {
			if err := Convert_v1alpha1_LoadBalancer_To_net_LoadBalancer(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_net_LoadBalancerList_To_v1alpha1_LoadBalancerList converts an internal list to versioned.
func Convert_net_LoadBalancerList_To_v1alpha1_LoadBalancerList(in *net.LoadBalancerList, out *LoadBalancerList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]LoadBalancer, len(in.Items))
		for i := range in.Items {
			if err := Convert_net_LoadBalancer_To_v1alpha1_LoadBalancer(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_v1alpha1_LoadBalancerSpec_To_net_LoadBalancerSpec converts a versioned spec to internal.
func Convert_v1alpha1_LoadBalancerSpec_To_net_LoadBalancerSpec(in *LoadBalancerSpec, out *net.LoadBalancerSpec, s conversion.Scope) error {
	out.VIP = in.VIP
	if in.Ports != nil {
		out.Ports = make([]net.LoadBalancerPort, len(in.Ports))
		for i := range in.Ports {
			if err := Convert_v1alpha1_LoadBalancerPort_To_net_LoadBalancerPort(&in.Ports[i], &out.Ports[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Ports = nil
	}
	out.TargetSelector = in.TargetSelector.DeepCopy()
	if in.TargetRefs != nil {
		out.TargetRefs = make([]net.LocalObjectReference, len(in.TargetRefs))
		for i := range in.TargetRefs {
			if err := Convert_v1alpha1_LocalObjectReference_To_net_LocalObjectReference(&in.TargetRefs[i], &out.TargetRefs[i], s); err != nil {
				return err
			}
		}
	} else {
		out.TargetRefs = nil
	}
	return nil
}

// Convert_net_LoadBalancerSpec_To_v1alpha1_LoadBalancerSpec converts an internal spec to versioned.
func Convert_net_LoadBalancerSpec_To_v1alpha1_LoadBalancerSpec(in *net.LoadBalancerSpec, out *LoadBalancerSpec, s conversion.Scope) error {
	out.VIP = in.VIP
	if in.Ports != nil {
		out.Ports = make([]LoadBalancerPort, len(in.Ports))
		for i := range in.Ports {
			if err := Convert_net_LoadBalancerPort_To_v1alpha1_LoadBalancerPort(&in.Ports[i], &out.Ports[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Ports = nil
	}
	out.TargetSelector = in.TargetSelector.DeepCopy()
	if in.TargetRefs != nil {
		out.TargetRefs = make([]LocalObjectReference, len(in.TargetRefs))
		for i := range in.TargetRefs {
			if err := Convert_net_LocalObjectReference_To_v1alpha1_LocalObjectReference(&in.TargetRefs[i], &out.TargetRefs[i], s); err != nil {
				return err
			}
		}
	} else {
		out.TargetRefs = nil
	}
	return nil
}

// Convert_v1alpha1_LoadBalancerPort_To_net_LoadBalancerPort converts a versioned port to internal.
func Convert_v1alpha1_LoadBalancerPort_To_net_LoadBalancerPort(in *LoadBalancerPort, out *net.LoadBalancerPort, _ conversion.Scope) error {
	out.Port = in.Port
	out.Proto = in.Proto
	return nil
}

// Convert_net_LoadBalancerPort_To_v1alpha1_LoadBalancerPort converts an internal port to versioned.
func Convert_net_LoadBalancerPort_To_v1alpha1_LoadBalancerPort(in *net.LoadBalancerPort, out *LoadBalancerPort, _ conversion.Scope) error {
	out.Port = in.Port
	out.Proto = in.Proto
	return nil
}

// Convert_v1alpha1_LoadBalancerStatus_To_net_LoadBalancerStatus converts a versioned status to internal.
func Convert_v1alpha1_LoadBalancerStatus_To_net_LoadBalancerStatus(in *LoadBalancerStatus, out *net.LoadBalancerStatus, _ conversion.Scope) error {
	out.State = in.State
	return nil
}

// Convert_net_LoadBalancerStatus_To_v1alpha1_LoadBalancerStatus converts an internal status to versioned.
func Convert_net_LoadBalancerStatus_To_v1alpha1_LoadBalancerStatus(in *net.LoadBalancerStatus, out *LoadBalancerStatus, _ conversion.Scope) error {
	out.State = in.State
	return nil
}

// ============================ NATGateway ============================

// Convert_v1alpha1_NATGateway_To_net_NATGateway converts a versioned NATGateway to internal.
func Convert_v1alpha1_NATGateway_To_net_NATGateway(in *NATGateway, out *net.NATGateway, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_NATGatewaySpec_To_net_NATGatewaySpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_v1alpha1_NATGatewayStatus_To_net_NATGatewayStatus(&in.Status, &out.Status, s)
}

// Convert_net_NATGateway_To_v1alpha1_NATGateway converts an internal NATGateway to versioned.
func Convert_net_NATGateway_To_v1alpha1_NATGateway(in *net.NATGateway, out *NATGateway, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_net_NATGatewaySpec_To_v1alpha1_NATGatewaySpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_net_NATGatewayStatus_To_v1alpha1_NATGatewayStatus(&in.Status, &out.Status, s)
}

// Convert_v1alpha1_NATGatewayList_To_net_NATGatewayList converts a versioned list to internal.
func Convert_v1alpha1_NATGatewayList_To_net_NATGatewayList(in *NATGatewayList, out *net.NATGatewayList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]net.NATGateway, len(in.Items))
		for i := range in.Items {
			if err := Convert_v1alpha1_NATGateway_To_net_NATGateway(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_net_NATGatewayList_To_v1alpha1_NATGatewayList converts an internal list to versioned.
func Convert_net_NATGatewayList_To_v1alpha1_NATGatewayList(in *net.NATGatewayList, out *NATGatewayList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]NATGateway, len(in.Items))
		for i := range in.Items {
			if err := Convert_net_NATGateway_To_v1alpha1_NATGateway(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_v1alpha1_NATGatewaySpec_To_net_NATGatewaySpec converts a versioned spec to internal.
func Convert_v1alpha1_NATGatewaySpec_To_net_NATGatewaySpec(in *NATGatewaySpec, out *net.NATGatewaySpec, s conversion.Scope) error {
	if err := Convert_v1alpha1_LocalObjectReference_To_net_LocalObjectReference(&in.VPCRef, &out.VPCRef, s); err != nil {
		return err
	}
	out.PublicIPs = in.PublicIPs
	out.PortsPerSource = in.PortsPerSource
	out.EdgeUnderlay = in.EdgeUnderlay
	return nil
}

// Convert_net_NATGatewaySpec_To_v1alpha1_NATGatewaySpec converts an internal spec to versioned.
func Convert_net_NATGatewaySpec_To_v1alpha1_NATGatewaySpec(in *net.NATGatewaySpec, out *NATGatewaySpec, s conversion.Scope) error {
	if err := Convert_net_LocalObjectReference_To_v1alpha1_LocalObjectReference(&in.VPCRef, &out.VPCRef, s); err != nil {
		return err
	}
	out.PublicIPs = in.PublicIPs
	out.PortsPerSource = in.PortsPerSource
	out.EdgeUnderlay = in.EdgeUnderlay
	return nil
}

// Convert_v1alpha1_NATGatewayStatus_To_net_NATGatewayStatus converts a versioned status to internal.
func Convert_v1alpha1_NATGatewayStatus_To_net_NATGatewayStatus(in *NATGatewayStatus, out *net.NATGatewayStatus, s conversion.Scope) error {
	if in.Allocations != nil {
		out.Allocations = make([]net.NATAllocation, len(in.Allocations))
		for i := range in.Allocations {
			if err := Convert_v1alpha1_NATAllocation_To_net_NATAllocation(&in.Allocations[i], &out.Allocations[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Allocations = nil
	}
	out.State = in.State
	return nil
}

// Convert_net_NATGatewayStatus_To_v1alpha1_NATGatewayStatus converts an internal status to versioned.
func Convert_net_NATGatewayStatus_To_v1alpha1_NATGatewayStatus(in *net.NATGatewayStatus, out *NATGatewayStatus, s conversion.Scope) error {
	if in.Allocations != nil {
		out.Allocations = make([]NATAllocation, len(in.Allocations))
		for i := range in.Allocations {
			if err := Convert_net_NATAllocation_To_v1alpha1_NATAllocation(&in.Allocations[i], &out.Allocations[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Allocations = nil
	}
	out.State = in.State
	return nil
}

// Convert_v1alpha1_NATAllocation_To_net_NATAllocation converts a versioned allocation to internal.
func Convert_v1alpha1_NATAllocation_To_net_NATAllocation(in *NATAllocation, out *net.NATAllocation, _ conversion.Scope) error {
	out.Source = in.Source
	out.PublicIP = in.PublicIP
	out.PortMin = in.PortMin
	out.PortMax = in.PortMax
	return nil
}

// Convert_net_NATAllocation_To_v1alpha1_NATAllocation converts an internal allocation to versioned.
func Convert_net_NATAllocation_To_v1alpha1_NATAllocation(in *net.NATAllocation, out *NATAllocation, _ conversion.Scope) error {
	out.Source = in.Source
	out.PublicIP = in.PublicIP
	out.PortMin = in.PortMin
	out.PortMax = in.PortMax
	return nil
}

// ============================ VPCPeering ============================

// Convert_v1alpha1_VPCPeering_To_net_VPCPeering converts a versioned VPCPeering to internal.
func Convert_v1alpha1_VPCPeering_To_net_VPCPeering(in *VPCPeering, out *net.VPCPeering, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_VPCPeeringSpec_To_net_VPCPeeringSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_v1alpha1_VPCPeeringStatus_To_net_VPCPeeringStatus(&in.Status, &out.Status, s)
}

// Convert_net_VPCPeering_To_v1alpha1_VPCPeering converts an internal VPCPeering to versioned.
func Convert_net_VPCPeering_To_v1alpha1_VPCPeering(in *net.VPCPeering, out *VPCPeering, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_net_VPCPeeringSpec_To_v1alpha1_VPCPeeringSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_net_VPCPeeringStatus_To_v1alpha1_VPCPeeringStatus(&in.Status, &out.Status, s)
}

// Convert_v1alpha1_VPCPeeringList_To_net_VPCPeeringList converts a versioned list to internal.
func Convert_v1alpha1_VPCPeeringList_To_net_VPCPeeringList(in *VPCPeeringList, out *net.VPCPeeringList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]net.VPCPeering, len(in.Items))
		for i := range in.Items {
			if err := Convert_v1alpha1_VPCPeering_To_net_VPCPeering(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_net_VPCPeeringList_To_v1alpha1_VPCPeeringList converts an internal list to versioned.
func Convert_net_VPCPeeringList_To_v1alpha1_VPCPeeringList(in *net.VPCPeeringList, out *VPCPeeringList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]VPCPeering, len(in.Items))
		for i := range in.Items {
			if err := Convert_net_VPCPeering_To_v1alpha1_VPCPeering(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_v1alpha1_VPCPeeringSpec_To_net_VPCPeeringSpec converts a versioned spec to internal.
func Convert_v1alpha1_VPCPeeringSpec_To_net_VPCPeeringSpec(in *VPCPeeringSpec, out *net.VPCPeeringSpec, s conversion.Scope) error {
	if err := Convert_v1alpha1_LocalObjectReference_To_net_LocalObjectReference(&in.VPCRef, &out.VPCRef, s); err != nil {
		return err
	}
	if err := Convert_v1alpha1_VPCReference_To_net_VPCReference(&in.PeerVPCRef, &out.PeerVPCRef, s); err != nil {
		return err
	}
	out.ExposedPrefixes = in.ExposedPrefixes
	return nil
}

// Convert_net_VPCPeeringSpec_To_v1alpha1_VPCPeeringSpec converts an internal spec to versioned.
func Convert_net_VPCPeeringSpec_To_v1alpha1_VPCPeeringSpec(in *net.VPCPeeringSpec, out *VPCPeeringSpec, s conversion.Scope) error {
	if err := Convert_net_LocalObjectReference_To_v1alpha1_LocalObjectReference(&in.VPCRef, &out.VPCRef, s); err != nil {
		return err
	}
	if err := Convert_net_VPCReference_To_v1alpha1_VPCReference(&in.PeerVPCRef, &out.PeerVPCRef, s); err != nil {
		return err
	}
	out.ExposedPrefixes = in.ExposedPrefixes
	return nil
}

// Convert_v1alpha1_VPCReference_To_net_VPCReference converts a versioned reference to internal.
func Convert_v1alpha1_VPCReference_To_net_VPCReference(in *VPCReference, out *net.VPCReference, _ conversion.Scope) error {
	out.Namespace = in.Namespace
	out.Name = in.Name
	return nil
}

// Convert_net_VPCReference_To_v1alpha1_VPCReference converts an internal reference to versioned.
func Convert_net_VPCReference_To_v1alpha1_VPCReference(in *net.VPCReference, out *VPCReference, _ conversion.Scope) error {
	out.Namespace = in.Namespace
	out.Name = in.Name
	return nil
}

// Convert_v1alpha1_VPCPeeringStatus_To_net_VPCPeeringStatus converts a versioned status to internal.
func Convert_v1alpha1_VPCPeeringStatus_To_net_VPCPeeringStatus(in *VPCPeeringStatus, out *net.VPCPeeringStatus, _ conversion.Scope) error {
	out.State = in.State
	out.Message = in.Message
	return nil
}

// Convert_net_VPCPeeringStatus_To_v1alpha1_VPCPeeringStatus converts an internal status to versioned.
func Convert_net_VPCPeeringStatus_To_v1alpha1_VPCPeeringStatus(in *net.VPCPeeringStatus, out *VPCPeeringStatus, _ conversion.Scope) error {
	out.State = in.State
	out.Message = in.Message
	return nil
}

// ============================ CompiledNIC ============================

// Convert_v1alpha1_CompiledNIC_To_net_CompiledNIC converts a versioned CompiledNIC to internal.
func Convert_v1alpha1_CompiledNIC_To_net_CompiledNIC(in *CompiledNIC, out *net.CompiledNIC, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_CompiledNICSpec_To_net_CompiledNICSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_v1alpha1_CompiledNICStatus_To_net_CompiledNICStatus(&in.Status, &out.Status, s)
}

// Convert_net_CompiledNIC_To_v1alpha1_CompiledNIC converts an internal CompiledNIC to versioned.
func Convert_net_CompiledNIC_To_v1alpha1_CompiledNIC(in *net.CompiledNIC, out *CompiledNIC, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_net_CompiledNICSpec_To_v1alpha1_CompiledNICSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_net_CompiledNICStatus_To_v1alpha1_CompiledNICStatus(&in.Status, &out.Status, s)
}

// Convert_v1alpha1_CompiledNICList_To_net_CompiledNICList converts a versioned list to internal.
func Convert_v1alpha1_CompiledNICList_To_net_CompiledNICList(in *CompiledNICList, out *net.CompiledNICList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]net.CompiledNIC, len(in.Items))
		for i := range in.Items {
			if err := Convert_v1alpha1_CompiledNIC_To_net_CompiledNIC(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_net_CompiledNICList_To_v1alpha1_CompiledNICList converts an internal list to versioned.
func Convert_net_CompiledNICList_To_v1alpha1_CompiledNICList(in *net.CompiledNICList, out *CompiledNICList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]CompiledNIC, len(in.Items))
		for i := range in.Items {
			if err := Convert_net_CompiledNIC_To_v1alpha1_CompiledNIC(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_v1alpha1_CompiledNICSpec_To_net_CompiledNICSpec converts a versioned spec to internal.
func Convert_v1alpha1_CompiledNICSpec_To_net_CompiledNICSpec(in *CompiledNICSpec, out *net.CompiledNICSpec, s conversion.Scope) error {
	out.ClusterName = in.ClusterName
	out.NodeName = in.NodeName
	out.VNI = in.VNI
	if err := Convert_v1alpha1_PortStatus_To_net_PortStatus(&in.Port, &out.Port, s); err != nil {
		return err
	}
	out.OverlayIPs = in.OverlayIPs
	if err := Convert_v1alpha1_CompiledFirewall_To_net_CompiledFirewall(&in.Firewall, &out.Firewall, s); err != nil {
		return err
	}
	if in.NAT != nil {
		out.NAT = make([]net.CompiledNATSource, len(in.NAT))
		for i := range in.NAT {
			if err := Convert_v1alpha1_CompiledNATSource_To_net_CompiledNATSource(&in.NAT[i], &out.NAT[i], s); err != nil {
				return err
			}
		}
	} else {
		out.NAT = nil
	}
	if in.LB != nil {
		out.LB = make([]net.CompiledLB, len(in.LB))
		for i := range in.LB {
			if err := Convert_v1alpha1_CompiledLB_To_net_CompiledLB(&in.LB[i], &out.LB[i], s); err != nil {
				return err
			}
		}
	} else {
		out.LB = nil
	}
	if in.PeerImports != nil {
		out.PeerImports = make([]net.CompiledPeerImport, len(in.PeerImports))
		for i := range in.PeerImports {
			if err := Convert_v1alpha1_CompiledPeerImport_To_net_CompiledPeerImport(&in.PeerImports[i], &out.PeerImports[i], s); err != nil {
				return err
			}
		}
	} else {
		out.PeerImports = nil
	}
	return nil
}

// Convert_net_CompiledNICSpec_To_v1alpha1_CompiledNICSpec converts an internal spec to versioned.
func Convert_net_CompiledNICSpec_To_v1alpha1_CompiledNICSpec(in *net.CompiledNICSpec, out *CompiledNICSpec, s conversion.Scope) error {
	out.ClusterName = in.ClusterName
	out.NodeName = in.NodeName
	out.VNI = in.VNI
	if err := Convert_net_PortStatus_To_v1alpha1_PortStatus(&in.Port, &out.Port, s); err != nil {
		return err
	}
	out.OverlayIPs = in.OverlayIPs
	if err := Convert_net_CompiledFirewall_To_v1alpha1_CompiledFirewall(&in.Firewall, &out.Firewall, s); err != nil {
		return err
	}
	if in.NAT != nil {
		out.NAT = make([]CompiledNATSource, len(in.NAT))
		for i := range in.NAT {
			if err := Convert_net_CompiledNATSource_To_v1alpha1_CompiledNATSource(&in.NAT[i], &out.NAT[i], s); err != nil {
				return err
			}
		}
	} else {
		out.NAT = nil
	}
	if in.LB != nil {
		out.LB = make([]CompiledLB, len(in.LB))
		for i := range in.LB {
			if err := Convert_net_CompiledLB_To_v1alpha1_CompiledLB(&in.LB[i], &out.LB[i], s); err != nil {
				return err
			}
		}
	} else {
		out.LB = nil
	}
	if in.PeerImports != nil {
		out.PeerImports = make([]CompiledPeerImport, len(in.PeerImports))
		for i := range in.PeerImports {
			if err := Convert_net_CompiledPeerImport_To_v1alpha1_CompiledPeerImport(&in.PeerImports[i], &out.PeerImports[i], s); err != nil {
				return err
			}
		}
	} else {
		out.PeerImports = nil
	}
	return nil
}

// Convert_v1alpha1_CompiledFirewall_To_net_CompiledFirewall converts a versioned firewall to internal.
func Convert_v1alpha1_CompiledFirewall_To_net_CompiledFirewall(in *CompiledFirewall, out *net.CompiledFirewall, s conversion.Scope) error {
	if in.Ingress != nil {
		out.Ingress = make([]net.CompiledFwRule, len(in.Ingress))
		for i := range in.Ingress {
			if err := Convert_v1alpha1_CompiledFwRule_To_net_CompiledFwRule(&in.Ingress[i], &out.Ingress[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Ingress = nil
	}
	if in.Egress != nil {
		out.Egress = make([]net.CompiledFwRule, len(in.Egress))
		for i := range in.Egress {
			if err := Convert_v1alpha1_CompiledFwRule_To_net_CompiledFwRule(&in.Egress[i], &out.Egress[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Egress = nil
	}
	return nil
}

// Convert_net_CompiledFirewall_To_v1alpha1_CompiledFirewall converts an internal firewall to versioned.
func Convert_net_CompiledFirewall_To_v1alpha1_CompiledFirewall(in *net.CompiledFirewall, out *CompiledFirewall, s conversion.Scope) error {
	if in.Ingress != nil {
		out.Ingress = make([]CompiledFwRule, len(in.Ingress))
		for i := range in.Ingress {
			if err := Convert_net_CompiledFwRule_To_v1alpha1_CompiledFwRule(&in.Ingress[i], &out.Ingress[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Ingress = nil
	}
	if in.Egress != nil {
		out.Egress = make([]CompiledFwRule, len(in.Egress))
		for i := range in.Egress {
			if err := Convert_net_CompiledFwRule_To_v1alpha1_CompiledFwRule(&in.Egress[i], &out.Egress[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Egress = nil
	}
	return nil
}

// Convert_v1alpha1_CompiledFwRule_To_net_CompiledFwRule converts a versioned rule to internal.
func Convert_v1alpha1_CompiledFwRule_To_net_CompiledFwRule(in *CompiledFwRule, out *net.CompiledFwRule, _ conversion.Scope) error {
	out.CIDR = in.CIDR
	out.Proto = in.Proto
	out.Port = in.Port
	out.Action = in.Action
	return nil
}

// Convert_net_CompiledFwRule_To_v1alpha1_CompiledFwRule converts an internal rule to versioned.
func Convert_net_CompiledFwRule_To_v1alpha1_CompiledFwRule(in *net.CompiledFwRule, out *CompiledFwRule, _ conversion.Scope) error {
	out.CIDR = in.CIDR
	out.Proto = in.Proto
	out.Port = in.Port
	out.Action = in.Action
	return nil
}

// Convert_v1alpha1_CompiledNATSource_To_net_CompiledNATSource converts a versioned NAT source to internal.
func Convert_v1alpha1_CompiledNATSource_To_net_CompiledNATSource(in *CompiledNATSource, out *net.CompiledNATSource, _ conversion.Scope) error {
	out.SourceIP = in.SourceIP
	out.NATIP = in.NATIP
	out.PortMin = in.PortMin
	out.PortMax = in.PortMax
	return nil
}

// Convert_net_CompiledNATSource_To_v1alpha1_CompiledNATSource converts an internal NAT source to versioned.
func Convert_net_CompiledNATSource_To_v1alpha1_CompiledNATSource(in *net.CompiledNATSource, out *CompiledNATSource, _ conversion.Scope) error {
	out.SourceIP = in.SourceIP
	out.NATIP = in.NATIP
	out.PortMin = in.PortMin
	out.PortMax = in.PortMax
	return nil
}

// Convert_v1alpha1_CompiledLB_To_net_CompiledLB converts a versioned CompiledLB to internal.
func Convert_v1alpha1_CompiledLB_To_net_CompiledLB(in *CompiledLB, out *net.CompiledLB, s conversion.Scope) error {
	out.VIP = in.VIP
	if in.Ports != nil {
		out.Ports = make([]net.CompiledLBPort, len(in.Ports))
		for i := range in.Ports {
			if err := Convert_v1alpha1_CompiledLBPort_To_net_CompiledLBPort(&in.Ports[i], &out.Ports[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Ports = nil
	}
	return nil
}

// Convert_net_CompiledLB_To_v1alpha1_CompiledLB converts an internal CompiledLB to versioned.
func Convert_net_CompiledLB_To_v1alpha1_CompiledLB(in *net.CompiledLB, out *CompiledLB, s conversion.Scope) error {
	out.VIP = in.VIP
	if in.Ports != nil {
		out.Ports = make([]CompiledLBPort, len(in.Ports))
		for i := range in.Ports {
			if err := Convert_net_CompiledLBPort_To_v1alpha1_CompiledLBPort(&in.Ports[i], &out.Ports[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Ports = nil
	}
	return nil
}

// Convert_v1alpha1_CompiledLBPort_To_net_CompiledLBPort converts a versioned LB port to internal.
func Convert_v1alpha1_CompiledLBPort_To_net_CompiledLBPort(in *CompiledLBPort, out *net.CompiledLBPort, _ conversion.Scope) error {
	out.Port = in.Port
	out.Proto = in.Proto
	return nil
}

// Convert_net_CompiledLBPort_To_v1alpha1_CompiledLBPort converts an internal LB port to versioned.
func Convert_net_CompiledLBPort_To_v1alpha1_CompiledLBPort(in *net.CompiledLBPort, out *CompiledLBPort, _ conversion.Scope) error {
	out.Port = in.Port
	out.Proto = in.Proto
	return nil
}

// Convert_v1alpha1_CompiledPeerImport_To_net_CompiledPeerImport converts a versioned peer import to internal.
func Convert_v1alpha1_CompiledPeerImport_To_net_CompiledPeerImport(in *CompiledPeerImport, out *net.CompiledPeerImport, _ conversion.Scope) error {
	out.PeerVNI = in.PeerVNI
	out.ImportPrefixes = in.ImportPrefixes
	return nil
}

// Convert_net_CompiledPeerImport_To_v1alpha1_CompiledPeerImport converts an internal peer import to versioned.
func Convert_net_CompiledPeerImport_To_v1alpha1_CompiledPeerImport(in *net.CompiledPeerImport, out *CompiledPeerImport, _ conversion.Scope) error {
	out.PeerVNI = in.PeerVNI
	out.ImportPrefixes = in.ImportPrefixes
	return nil
}

// Convert_v1alpha1_CompiledNICStatus_To_net_CompiledNICStatus converts a versioned status to internal.
func Convert_v1alpha1_CompiledNICStatus_To_net_CompiledNICStatus(in *CompiledNICStatus, out *net.CompiledNICStatus, _ conversion.Scope) error {
	out.State = in.State
	out.GenerationApplied = in.GenerationApplied
	return nil
}

// Convert_net_CompiledNICStatus_To_v1alpha1_CompiledNICStatus converts an internal status to versioned.
func Convert_net_CompiledNICStatus_To_v1alpha1_CompiledNICStatus(in *net.CompiledNICStatus, out *CompiledNICStatus, _ conversion.Scope) error {
	out.State = in.State
	out.GenerationApplied = in.GenerationApplied
	return nil
}

// ============================ CompiledVM ============================

// Convert_v1alpha1_CompiledVM_To_net_CompiledVM converts a versioned CompiledVM to internal.
func Convert_v1alpha1_CompiledVM_To_net_CompiledVM(in *CompiledVM, out *net.CompiledVM, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_CompiledVMSpec_To_net_CompiledVMSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_v1alpha1_CompiledVMStatus_To_net_CompiledVMStatus(&in.Status, &out.Status, s)
}

// Convert_net_CompiledVM_To_v1alpha1_CompiledVM converts an internal CompiledVM to versioned.
func Convert_net_CompiledVM_To_v1alpha1_CompiledVM(in *net.CompiledVM, out *CompiledVM, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_net_CompiledVMSpec_To_v1alpha1_CompiledVMSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_net_CompiledVMStatus_To_v1alpha1_CompiledVMStatus(&in.Status, &out.Status, s)
}

// Convert_v1alpha1_CompiledVMList_To_net_CompiledVMList converts a versioned list to internal.
func Convert_v1alpha1_CompiledVMList_To_net_CompiledVMList(in *CompiledVMList, out *net.CompiledVMList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]net.CompiledVM, len(in.Items))
		for i := range in.Items {
			if err := Convert_v1alpha1_CompiledVM_To_net_CompiledVM(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_net_CompiledVMList_To_v1alpha1_CompiledVMList converts an internal list to versioned.
func Convert_net_CompiledVMList_To_v1alpha1_CompiledVMList(in *net.CompiledVMList, out *CompiledVMList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]CompiledVM, len(in.Items))
		for i := range in.Items {
			if err := Convert_net_CompiledVM_To_v1alpha1_CompiledVM(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_v1alpha1_CompiledVMSpec_To_net_CompiledVMSpec converts a versioned spec to internal.
func Convert_v1alpha1_CompiledVMSpec_To_net_CompiledVMSpec(in *CompiledVMSpec, out *net.CompiledVMSpec, s conversion.Scope) error {
	out.ClusterName = in.ClusterName
	out.Image = in.Image
	out.Resources = *in.Resources.DeepCopy()
	out.RunStrategy = in.RunStrategy
	if in.Interfaces != nil {
		out.Interfaces = make([]net.CompiledVMInterface, len(in.Interfaces))
		for i := range in.Interfaces {
			if err := Convert_v1alpha1_CompiledVMInterface_To_net_CompiledVMInterface(&in.Interfaces[i], &out.Interfaces[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Interfaces = nil
	}
	return nil
}

// Convert_net_CompiledVMSpec_To_v1alpha1_CompiledVMSpec converts an internal spec to versioned.
func Convert_net_CompiledVMSpec_To_v1alpha1_CompiledVMSpec(in *net.CompiledVMSpec, out *CompiledVMSpec, s conversion.Scope) error {
	out.ClusterName = in.ClusterName
	out.Image = in.Image
	out.Resources = *in.Resources.DeepCopy()
	out.RunStrategy = in.RunStrategy
	if in.Interfaces != nil {
		out.Interfaces = make([]CompiledVMInterface, len(in.Interfaces))
		for i := range in.Interfaces {
			if err := Convert_net_CompiledVMInterface_To_v1alpha1_CompiledVMInterface(&in.Interfaces[i], &out.Interfaces[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Interfaces = nil
	}
	return nil
}

// Convert_v1alpha1_CompiledVMInterface_To_net_CompiledVMInterface converts a versioned interface to internal.
func Convert_v1alpha1_CompiledVMInterface_To_net_CompiledVMInterface(in *CompiledVMInterface, out *net.CompiledVMInterface, _ conversion.Scope) error {
	out.MAC = in.MAC
	out.NetworkName = in.NetworkName
	return nil
}

// Convert_net_CompiledVMInterface_To_v1alpha1_CompiledVMInterface converts an internal interface to versioned.
func Convert_net_CompiledVMInterface_To_v1alpha1_CompiledVMInterface(in *net.CompiledVMInterface, out *CompiledVMInterface, _ conversion.Scope) error {
	out.MAC = in.MAC
	out.NetworkName = in.NetworkName
	return nil
}

// Convert_v1alpha1_CompiledVMStatus_To_net_CompiledVMStatus converts a versioned status to internal.
func Convert_v1alpha1_CompiledVMStatus_To_net_CompiledVMStatus(in *CompiledVMStatus, out *net.CompiledVMStatus, _ conversion.Scope) error {
	out.State = in.State
	return nil
}

// Convert_net_CompiledVMStatus_To_v1alpha1_CompiledVMStatus converts an internal status to versioned.
func Convert_net_CompiledVMStatus_To_v1alpha1_CompiledVMStatus(in *net.CompiledVMStatus, out *CompiledVMStatus, _ conversion.Scope) error {
	out.State = in.State
	return nil
}

// ============================ VirtualMachine ============================

// Convert_v1alpha1_VirtualMachine_To_net_VirtualMachine converts a versioned VirtualMachine to internal.
func Convert_v1alpha1_VirtualMachine_To_net_VirtualMachine(in *VirtualMachine, out *net.VirtualMachine, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_VirtualMachineSpec_To_net_VirtualMachineSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_v1alpha1_VirtualMachineStatus_To_net_VirtualMachineStatus(&in.Status, &out.Status, s)
}

// Convert_net_VirtualMachine_To_v1alpha1_VirtualMachine converts an internal VirtualMachine to versioned.
func Convert_net_VirtualMachine_To_v1alpha1_VirtualMachine(in *net.VirtualMachine, out *VirtualMachine, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_net_VirtualMachineSpec_To_v1alpha1_VirtualMachineSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return Convert_net_VirtualMachineStatus_To_v1alpha1_VirtualMachineStatus(&in.Status, &out.Status, s)
}

// Convert_v1alpha1_VirtualMachineList_To_net_VirtualMachineList converts a versioned list to internal.
func Convert_v1alpha1_VirtualMachineList_To_net_VirtualMachineList(in *VirtualMachineList, out *net.VirtualMachineList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]net.VirtualMachine, len(in.Items))
		for i := range in.Items {
			if err := Convert_v1alpha1_VirtualMachine_To_net_VirtualMachine(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_net_VirtualMachineList_To_v1alpha1_VirtualMachineList converts an internal list to versioned.
func Convert_net_VirtualMachineList_To_v1alpha1_VirtualMachineList(in *net.VirtualMachineList, out *VirtualMachineList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]VirtualMachine, len(in.Items))
		for i := range in.Items {
			if err := Convert_net_VirtualMachine_To_v1alpha1_VirtualMachine(&in.Items[i], &out.Items[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_v1alpha1_VirtualMachineSpec_To_net_VirtualMachineSpec converts a versioned spec to internal.
func Convert_v1alpha1_VirtualMachineSpec_To_net_VirtualMachineSpec(in *VirtualMachineSpec, out *net.VirtualMachineSpec, s conversion.Scope) error {
	out.ClusterName = in.ClusterName
	if in.InterfaceRefs != nil {
		out.InterfaceRefs = make([]net.LocalObjectReference, len(in.InterfaceRefs))
		for i := range in.InterfaceRefs {
			if err := Convert_v1alpha1_LocalObjectReference_To_net_LocalObjectReference(&in.InterfaceRefs[i], &out.InterfaceRefs[i], s); err != nil {
				return err
			}
		}
	} else {
		out.InterfaceRefs = nil
	}
	out.Resources = *in.Resources.DeepCopy()
	out.Image = in.Image
	out.RunStrategy = in.RunStrategy
	if in.PoolSelector != nil {
		out.PoolSelector = in.PoolSelector.DeepCopy()
	} else {
		out.PoolSelector = nil
	}
	return nil
}

// Convert_net_VirtualMachineSpec_To_v1alpha1_VirtualMachineSpec converts an internal spec to versioned.
func Convert_net_VirtualMachineSpec_To_v1alpha1_VirtualMachineSpec(in *net.VirtualMachineSpec, out *VirtualMachineSpec, s conversion.Scope) error {
	out.ClusterName = in.ClusterName
	if in.InterfaceRefs != nil {
		out.InterfaceRefs = make([]LocalObjectReference, len(in.InterfaceRefs))
		for i := range in.InterfaceRefs {
			if err := Convert_net_LocalObjectReference_To_v1alpha1_LocalObjectReference(&in.InterfaceRefs[i], &out.InterfaceRefs[i], s); err != nil {
				return err
			}
		}
	} else {
		out.InterfaceRefs = nil
	}
	out.Resources = *in.Resources.DeepCopy()
	out.Image = in.Image
	out.RunStrategy = in.RunStrategy
	if in.PoolSelector != nil {
		out.PoolSelector = in.PoolSelector.DeepCopy()
	} else {
		out.PoolSelector = nil
	}
	return nil
}

// Convert_v1alpha1_VirtualMachineStatus_To_net_VirtualMachineStatus converts a versioned status to internal.
func Convert_v1alpha1_VirtualMachineStatus_To_net_VirtualMachineStatus(in *VirtualMachineStatus, out *net.VirtualMachineStatus, _ conversion.Scope) error {
	out.Phase = in.Phase
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		copy(out.Conditions, in.Conditions)
	} else {
		out.Conditions = nil
	}
	return nil
}

// Convert_net_VirtualMachineStatus_To_v1alpha1_VirtualMachineStatus converts an internal status to versioned.
func Convert_net_VirtualMachineStatus_To_v1alpha1_VirtualMachineStatus(in *net.VirtualMachineStatus, out *VirtualMachineStatus, _ conversion.Scope) error {
	out.Phase = in.Phase
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		copy(out.Conditions, in.Conditions)
	} else {
		out.Conditions = nil
	}
	return nil
}
