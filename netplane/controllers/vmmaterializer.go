// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// containerDiskName is the shared name pairing the boot Disk to its Volume.
	containerDiskName = "containerdisk"
	// flowplaneBindingName is the KubeVirt network-binding plugin (registered in the
	// downstream KubeVirt CR) that attaches the flowplane overlay via a tap device.
	flowplaneBindingName = "flowplane"
	// vmFieldOwner is this controller's server-side-apply field manager name.
	vmFieldOwner = "vm-materializer"
)

// vmRunStrategy maps our string to the KubeVirt enum (unknown -> RerunOnFailure).
func vmRunStrategy(s string) kubevirtv1.VirtualMachineRunStrategy {
	switch kubevirtv1.VirtualMachineRunStrategy(s) {
	case kubevirtv1.RunStrategyAlways, kubevirtv1.RunStrategyManual, kubevirtv1.RunStrategyHalted, kubevirtv1.RunStrategyRerunOnFailure:
		return kubevirtv1.VirtualMachineRunStrategy(s)
	default:
		return kubevirtv1.RunStrategyRerunOnFailure
	}
}

// buildVM turns a CompiledVM into a kubevirt.io/v1.VirtualMachine (containerDisk boot,
// pinned-MAC overlay interfaces on the flowplane multus network). Pure: no I/O. TypeMeta
// is set so the object is self-describing for a server-side-apply patch.
func buildVM(cvm *netv1.CompiledVM) *kubevirtv1.VirtualMachine {
	rs := vmRunStrategy(cvm.Spec.RunStrategy)
	disks := []kubevirtv1.Disk{{
		Name:       containerDiskName,
		DiskDevice: kubevirtv1.DiskDevice{Disk: &kubevirtv1.DiskTarget{Bus: kubevirtv1.DiskBusVirtio}},
	}}
	volumes := []kubevirtv1.Volume{{
		Name:         containerDiskName,
		VolumeSource: kubevirtv1.VolumeSource{ContainerDisk: &kubevirtv1.ContainerDiskSource{Image: cvm.Spec.Image}},
	}}
	var ifaces []kubevirtv1.Interface
	var networks []kubevirtv1.Network
	for i, in := range cvm.Spec.Interfaces {
		name := fmt.Sprintf("net%d", i)
		ifaces = append(ifaces, kubevirtv1.Interface{
			Name:       name,
			MacAddress: in.MAC,
			// The flowplane overlay is attached via a KubeVirt network binding plugin
			// (domainAttachmentType=tap); see the KubeVirt-VM-primary-network-via-tap design.
			Binding: &kubevirtv1.PluginBinding{Name: flowplaneBindingName},
		})
		networks = append(networks, kubevirtv1.Network{
			Name:          name,
			NetworkSource: kubevirtv1.NetworkSource{Multus: &kubevirtv1.MultusNetwork{NetworkName: in.NetworkName}},
		})
	}
	labels := map[string]string{}
	if w := cvm.Labels["workload"]; w != "" {
		labels["workload"] = w
	}
	vm := &kubevirtv1.VirtualMachine{
		TypeMeta:   metav1.TypeMeta{APIVersion: kubevirtv1.GroupVersion.String(), Kind: "VirtualMachine"},
		ObjectMeta: metav1.ObjectMeta{Namespace: cvm.Namespace, Name: cvm.Name, Labels: labels},
		Spec: kubevirtv1.VirtualMachineSpec{
			RunStrategy: &rs,
			Template: &kubevirtv1.VirtualMachineInstanceTemplateSpec{
				Spec: kubevirtv1.VirtualMachineInstanceSpec{
					Domain: kubevirtv1.DomainSpec{
						Resources: kubevirtv1.ResourceRequirements{Requests: cvm.Spec.Resources.Requests},
						Devices:   kubevirtv1.Devices{Disks: disks, Interfaces: ifaces},
					},
					Volumes:  volumes,
					Networks: networks,
				},
			},
		},
	}
	return vm
}

// VMMaterializerReconciler turns local CompiledVMs into KubeVirt VirtualMachines. It runs on the
// DOWNSTREAM cluster (a plain k8s cluster with KubeVirt installed), not against the central
// aggregated apiserver.
type VMMaterializerReconciler struct{ Client client.Client }

func (r *VMMaterializerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cvm netv1.CompiledVM
	if err := r.Client.Get(ctx, req.NamespacedName, &cvm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	desired := buildVM(&cvm)
	if err := ctrl.SetControllerReference(&cvm, desired, r.Client.Scheme()); err != nil {
		return ctrl.Result{}, err
	}
	// Server-side apply, NOT get-then-update-on-DeepEqual: the KubeVirt mutating webhook
	// defaults many fields inside .spec.template.spec (machine type, firmware UUID, disk/
	// feature defaults). A full-spec DeepEqual would always differ from our sparse intent
	// and re-write those defaults on every reconcile — a churn loop hammering the webhook.
	// With SSA the materializer owns ONLY the fields buildVM sets; kubevirt's field manager
	// keeps its defaults, so re-applying the same intent is a genuine no-op.
	if err := r.Client.Patch(ctx, desired, client.Apply, client.FieldOwner(vmFieldOwner), client.ForceOwnership); err != nil {
		return ctrl.Result{}, fmt.Errorf("apply vm: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *VMMaterializerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.CompiledVM{}).
		Owns(&kubevirtv1.VirtualMachine{}).
		Complete(r)
}
