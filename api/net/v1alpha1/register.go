// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupName is the API group name for these objects.
const GroupName = "net.ectobase.dev"

// SchemeGroupVersion is the group-version used to register these objects.
var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

var (
	// SchemeBuilder collects scheme init functions (known types + generated
	// conversion/defaults registered from the zz_generated files).
	SchemeBuilder      runtime.SchemeBuilder
	localSchemeBuilder = &SchemeBuilder
	// AddToScheme registers the group/version and its known types with a scheme.
	AddToScheme = localSchemeBuilder.AddToScheme
)

func init() {
	localSchemeBuilder.Register(addKnownTypes)
}

// Resource takes an unqualified resource and returns a Group-qualified GroupResource.
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

// Kind takes an unqualified kind and returns a Group-qualified GroupKind.
func Kind(kind string) schema.GroupKind {
	return SchemeGroupVersion.WithKind(kind).GroupKind()
}

// addKnownTypes registers this package's types with the given scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&VPC{},
		&VPCList{},
		&NetworkInterface{},
		&NetworkInterfaceList{},
		&VPCPeering{},
		&VPCPeeringList{},
		&FirewallPolicy{},
		&FirewallPolicyList{},
		&LoadBalancer{},
		&LoadBalancerList{},
		&NATGateway{},
		&NATGatewayList{},
		&FloatingIP{},
		&FloatingIPList{},
		&CompiledNIC{},
		&CompiledNICList{},
		&CompiledVM{},
		&CompiledVMList{},
		&CompiledContainer{},
		&CompiledContainerList{},
		&Volume{},
		&VolumeList{},
		&CompiledVolumeAttachment{},
		&CompiledVolumeAttachmentList{},
		&VirtualMachine{},
		&VirtualMachineList{},
		&Container{},
		&ContainerList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
