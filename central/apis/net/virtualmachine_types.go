// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VirtualMachineSpec defines the desired state of a VirtualMachine.
type VirtualMachineSpec struct {
	// ClusterName is the cluster this workload is bound to.
	ClusterName string
	// InterfaceRefs names the NetworkInterfaces (same namespace) this VM owns.
	InterfaceRefs []LocalObjectReference
}

// VirtualMachineStatus defines the observed state of a VirtualMachine.
type VirtualMachineStatus struct {
	// Phase is the current lifecycle phase of the VirtualMachine.
	Phase string
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VirtualMachine is the placement anchor for a workload.
type VirtualMachine struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   VirtualMachineSpec
	Status VirtualMachineStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VirtualMachineList is a list of VirtualMachine objects.
type VirtualMachineList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []VirtualMachine
}
