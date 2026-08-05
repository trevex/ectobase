// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VirtualMachineSpec defines the desired state of a VirtualMachine.
type VirtualMachineSpec struct {
	// ClusterName is the cluster this workload is bound to.
	ClusterName string
	// InterfaceRefs names the NetworkInterfaces (same namespace) this VM owns.
	InterfaceRefs []LocalObjectReference
	// VolumeRefs names the Volumes (same namespace) this VM attaches.
	VolumeRefs []LocalObjectReference
	// Resources is the compute resource request/limit for this workload.
	Resources corev1.ResourceRequirements
	// Image is the containerDisk image the VM boots from.
	Image string
	// RunStrategy is the KubeVirt run strategy.
	RunStrategy string
	// PoolSelector, if set, restricts scheduling to ClusterPools whose labels match.
	PoolSelector *metav1.LabelSelector
	// AntiAffinity, if set, spreads VMs sharing a Group across ClusterPools.
	AntiAffinity *VMAntiAffinity
}

// VirtualMachineStatus defines the observed state of a VirtualMachine.
type VirtualMachineStatus struct {
	// Phase is the current lifecycle phase of the VirtualMachine.
	Phase string
	// Conditions capture scheduling/failover observations.
	Conditions []metav1.Condition
	// Placement is the VM's actual running location, stamped by the broker.
	Placement *VMPlacement
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

// VMAntiAffinity is the hub mirror of the anti-affinity group key.
type VMAntiAffinity struct {
	Group string
}

// VMPlacement is the hub mirror of the VM's actual running location.
type VMPlacement struct {
	ClusterName string
	NodeName    string
	NodePrefix  string
}
