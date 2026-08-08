// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

// The canonical versioned VPC structs live in the external api module. Re-export
// them here as aliases so the aggregated apiserver's codegen (conversion/openapi)
// can operate on the net.ectobase.dev/v1alpha1 view from within the central
// module while conversion-gen resolves the aliases back to api/v1alpha1's fields.
type (
	VPC       = netv1.VPC
	VPCList   = netv1.VPCList
	VPCSpec   = netv1.VPCSpec
	VPCStatus = netv1.VPCStatus

	NetworkInterface       = netv1.NetworkInterface
	NetworkInterfaceList   = netv1.NetworkInterfaceList
	NetworkInterfaceSpec   = netv1.NetworkInterfaceSpec
	NetworkInterfaceStatus = netv1.NetworkInterfaceStatus
	InterfaceQoS           = netv1.InterfaceQoS
	EgressQoS              = netv1.EgressQoS
	RateLimit              = netv1.RateLimit
	PortStatus             = netv1.PortStatus
	LocalObjectReference   = netv1.LocalObjectReference

	FirewallPolicy       = netv1.FirewallPolicy
	FirewallPolicyList   = netv1.FirewallPolicyList
	FirewallPolicySpec   = netv1.FirewallPolicySpec
	FirewallPolicyStatus = netv1.FirewallPolicyStatus
	FirewallPolicyRule   = netv1.FirewallPolicyRule

	FloatingIP       = netv1.FloatingIP
	FloatingIPList   = netv1.FloatingIPList
	FloatingIPSpec   = netv1.FloatingIPSpec
	FloatingIPStatus = netv1.FloatingIPStatus

	LoadBalancer       = netv1.LoadBalancer
	LoadBalancerList   = netv1.LoadBalancerList
	LoadBalancerSpec   = netv1.LoadBalancerSpec
	LoadBalancerStatus = netv1.LoadBalancerStatus
	LoadBalancerPort   = netv1.LoadBalancerPort

	NATGateway       = netv1.NATGateway
	NATGatewayList   = netv1.NATGatewayList
	NATGatewaySpec   = netv1.NATGatewaySpec
	NATGatewayStatus = netv1.NATGatewayStatus
	NATAllocation    = netv1.NATAllocation

	VPCPeering       = netv1.VPCPeering
	VPCPeeringList   = netv1.VPCPeeringList
	VPCPeeringSpec   = netv1.VPCPeeringSpec
	VPCPeeringStatus = netv1.VPCPeeringStatus
	VPCReference     = netv1.VPCReference

	CompiledNIC        = netv1.CompiledNIC
	CompiledNICList    = netv1.CompiledNICList
	CompiledNICSpec    = netv1.CompiledNICSpec
	CompiledNICStatus  = netv1.CompiledNICStatus
	CompiledFirewall   = netv1.CompiledFirewall
	CompiledFwRule     = netv1.CompiledFwRule
	CompiledNATSource  = netv1.CompiledNATSource
	CompiledLB         = netv1.CompiledLB
	CompiledLBPort     = netv1.CompiledLBPort
	CompiledPeerImport = netv1.CompiledPeerImport

	CompiledVM          = netv1.CompiledVM
	CompiledVMList      = netv1.CompiledVMList
	CompiledVMSpec      = netv1.CompiledVMSpec
	CompiledVMInterface = netv1.CompiledVMInterface
	CompiledVMStatus    = netv1.CompiledVMStatus

	Volume       = netv1.Volume
	VolumeList   = netv1.VolumeList
	VolumeSpec   = netv1.VolumeSpec
	VolumeStatus = netv1.VolumeStatus

	CompiledVolumeAttachment       = netv1.CompiledVolumeAttachment
	CompiledVolumeAttachmentList   = netv1.CompiledVolumeAttachmentList
	CompiledVolumeAttachmentSpec   = netv1.CompiledVolumeAttachmentSpec
	CompiledVolumeAttachmentStatus = netv1.CompiledVolumeAttachmentStatus

	VirtualMachine       = netv1.VirtualMachine
	VirtualMachineList   = netv1.VirtualMachineList
	VirtualMachineSpec   = netv1.VirtualMachineSpec
	VirtualMachineStatus = netv1.VirtualMachineStatus

	Container                  = netv1.Container
	ContainerList              = netv1.ContainerList
	ContainerSpec              = netv1.ContainerSpec
	ContainerStatus            = netv1.ContainerStatus
	CompiledContainer          = netv1.CompiledContainer
	CompiledContainerList      = netv1.CompiledContainerList
	CompiledContainerSpec      = netv1.CompiledContainerSpec
	CompiledContainerInterface = netv1.CompiledContainerInterface
	CompiledContainerStatus    = netv1.CompiledContainerStatus
)

// GroupName is the API group name for these objects.
const GroupName = netv1.GroupName

// SchemeGroupVersion is the group-version used to register these objects.
var SchemeGroupVersion = netv1.SchemeGroupVersion

var (
	// SchemeBuilder collects this package's scheme init functions. Manually
	// written funcs are registered here; the generated conversion/defaults
	// funcs register themselves into localSchemeBuilder from their init().
	SchemeBuilder      runtime.SchemeBuilder
	localSchemeBuilder = &SchemeBuilder
	// AddToScheme registers the group/version, its known types, and the
	// generated conversion + defaulting funcs with a scheme.
	AddToScheme = localSchemeBuilder.AddToScheme
)

func init() {
	localSchemeBuilder.Register(addKnownTypes, addDefaultingFuncs)
}

// addKnownTypes registers the (aliased, external) versioned types with the scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&VPC{},
		&VPCList{},
		&NetworkInterface{},
		&NetworkInterfaceList{},
		&FirewallPolicy{},
		&FirewallPolicyList{},
		&FloatingIP{},
		&FloatingIPList{},
		&LoadBalancer{},
		&LoadBalancerList{},
		&NATGateway{},
		&NATGatewayList{},
		&VPCPeering{},
		&VPCPeeringList{},
		&CompiledNIC{},
		&CompiledNICList{},
		&CompiledVM{},
		&CompiledVMList{},
		&Volume{},
		&VolumeList{},
		&CompiledVolumeAttachment{},
		&CompiledVolumeAttachmentList{},
		&VirtualMachine{},
		&VirtualMachineList{},
		&Container{},
		&ContainerList{},
		&CompiledContainer{},
		&CompiledContainerList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// Resource takes an unqualified resource and returns a Group-qualified GroupResource.
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

// Kind takes an unqualified kind and returns a Group-qualified GroupKind.
func Kind(kind string) schema.GroupKind {
	return SchemeGroupVersion.WithKind(kind).GroupKind()
}
