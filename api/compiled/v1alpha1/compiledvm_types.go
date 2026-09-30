// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompiledVMSpec is the fully lowered, ready-to-materialize boot intent for a VM:
// the containerDisk image, compute resources, run strategy, the cluster binding,
// and the per-interface MAC + overlay network name. A downstream materializer
// turns this into a kubevirt.io/v1.VirtualMachine.
type CompiledVMSpec struct {
	// ClusterName is the cluster this compiled VM is bound to (the pod->node binding).
	// The per-cluster broker selects on this field.
	// +optional
	ClusterName string `json:"clusterName,omitempty"`
	// Image is the containerDisk image to boot from.
	// +optional
	Image string `json:"image,omitempty"`
	// Resources is the compute request/limit; maps to the KubeVirt domain resources.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// RunStrategy is the KubeVirt run strategy (defaulted upstream by the compiler).
	// +optional
	RunStrategy string `json:"runStrategy,omitempty"`
	// Interfaces are the VM's overlay interfaces (one per owned NetworkInterface).
	// +optional
	Interfaces []CompiledVMInterface `json:"interfaces,omitempty"`
	// CloudInit, if set, is guest bootstrap delivered as a cloud-init NoCloud datasource.
	// +optional
	CloudInit *CloudInit `json:"cloudInit,omitempty"`
	// Volumes are the names of the CompiledVolumeAttachments this VM attaches. Their order here does
	// not set the guest's disk order: the VM lists the boot disk first, then the rest by name. The
	// materializer does not create the VM until every one of them exists on the pool: a VM created
	// before its disks would start from a template without them, and KubeVirt does not re-read the
	// template for an already-created VMI.
	// +optional
	Volumes []string `json:"volumes,omitempty" protobuf:"bytes,7,rep,name=volumes"`
}

// CloudInit is guest bootstrap config for a compiled VM, delivered by the materializer
// as a cloud-init NoCloud datasource.
type CloudInit struct {
	// UserData is the cloud-init user-data (commonly a #cloud-config document).
	// +optional
	UserData string `json:"userData,omitempty"`
}

// CompiledVMInterface is a resolved overlay interface for a VM: the allocated MAC
// and the multus network (NetworkAttachmentDefinition) name for the flowplane binding.
type CompiledVMInterface struct {
	// MAC is the NetworkInterface's allocated L2 address (status.allocatedMAC, or a pinned spec.mac).
	// +optional
	MAC string `json:"mac,omitempty"`
	// NetworkName is the multus NetworkAttachmentDefinition name for the overlay binding.
	// +optional
	NetworkName string `json:"networkName,omitempty"`
}

// CompiledVMStatus is the observed state of a CompiledVM. It is intentionally
// minimal (State only): the downstream materializer reconciles CompiledVM into a
// KubeVirt VirtualMachine via declarative set-reconcile, so — unlike CompiledNIC,
// whose node agent tracks an applied generation — no GenerationApplied is needed here.
type CompiledVMStatus struct {
	// State is the materialization state (e.g. Applied, Pending).
	// +optional
	State string `json:"state,omitempty"`
	// Placement is where this VM actually runs, reported upward by the pool's broker. It lands
	// here rather than directly on the source VirtualMachine because the broker's writes are
	// scoped to its own pool namespace; a mesh controller mirrors it onto the VirtualMachine.
	// +optional
	Placement *VMPlacement `json:"placement,omitempty" protobuf:"bytes,2,opt,name=placement"`
	// Released is set once the pool this twin was compiled for has let go of the VM — no KubeVirt
	// VM, VMI or virt-launcher left, and no claim on its disks — or, for a lost pool, once failover
	// has fenced it. A retired twin is held on the dispatch until this is true, and nothing is
	// compiled into another pool for the same VM until the retired twin is gone.
	// +optional
	Released bool `json:"released,omitempty" protobuf:"varint,3,opt,name=released"`
}

// VMPlacement is a VM's actual running location, as observed by the pool that runs it.
//
// Deliberately redeclared here rather than reusing compute.VMPlacement: the compiled group is
// self-contained by design — a pool consumes only compiled.ectobase.dev and never needs the source
// API — and an import the other way would break that.
type VMPlacement struct {
	// ClusterName is the pool the VM is running on.
	// +optional
	ClusterName string `json:"clusterName,omitempty" protobuf:"bytes,1,opt,name=clusterName"`
	// NodeName is the node running the VM.
	// +optional
	NodeName string `json:"nodeName,omitempty" protobuf:"bytes,2,opt,name=nodeName"`
	// NodePrefix is that node's /64 underlay prefix (the fence coordinate).
	// +optional
	NodePrefix string `json:"nodePrefix,omitempty" protobuf:"bytes,3,opt,name=nodePrefix"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// CompiledVM is the lowered boot intent for a scheduled VirtualMachine.
type CompiledVM struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CompiledVMSpec   `json:"spec,omitempty"`
	Status CompiledVMStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// CompiledVMList is a list of CompiledVM objects.
type CompiledVMList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CompiledVM `json:"items"`
}
