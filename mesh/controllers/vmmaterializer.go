// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	// containerDiskName is the shared name pairing the boot Disk to its Volume.
	containerDiskName = "containerdisk"
	// cloudInitDiskName pairs the cloud-init NoCloud Disk to its Volume (KubeVirt convention).
	cloudInitDiskName = "cloudinitdisk"
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

// buildVM turns a CompiledVM into a kubevirt.io/v1.VirtualMachine with pinned-MAC overlay
// interfaces on the flowplane multus network. The boot volume depends on attachments: when
// any CompiledVolumeAttachments are given it boots from persistent CDI DataVolume disks (boot
// attachment first, then the rest by name); otherwise it falls back to an ephemeral
// containerDisk from cvm.Spec.Image (the Phase-4 behavior). Pure: no I/O. TypeMeta is set so
// the object is self-describing for a server-side-apply patch.
func buildVM(cvm *compiledv1.CompiledVM, attachments []compiledv1.CompiledVolumeAttachment) *kubevirtv1.VirtualMachine {
	rs := vmRunStrategy(cvm.Spec.RunStrategy)
	var disks []kubevirtv1.Disk
	var volumes []kubevirtv1.Volume
	if len(attachments) > 0 {
		// Persistent RBD disks: boot attachment first, then the rest by name (deterministic).
		ordered := append([]compiledv1.CompiledVolumeAttachment(nil), attachments...)
		sort.SliceStable(ordered, func(i, j int) bool {
			if ordered[i].Spec.Boot != ordered[j].Spec.Boot {
				return ordered[i].Spec.Boot // boot first
			}
			return ordered[i].Name < ordered[j].Name
		})
		for _, a := range ordered {
			disks = append(disks, kubevirtv1.Disk{Name: a.Name, DiskDevice: kubevirtv1.DiskDevice{Disk: &kubevirtv1.DiskTarget{Bus: kubevirtv1.DiskBusVirtio}}})
			// An ADOPTED disk has no DataVolume — it was provisioned in another cluster and is bound
			// here by a static PV — so it is referenced by its claim. A DataVolume source would wait
			// forever for an object nothing is going to create. The volume NAME is the attachment's
			// either way, so guest-visible disk order does not shift when a VM moves.
			src := kubevirtv1.VolumeSource{DataVolume: &kubevirtv1.DataVolumeSource{Name: a.Name}}
			if a.Spec.DiskIdentity != nil && a.Spec.DiskIdentity.CSI != nil {
				src = kubevirtv1.VolumeSource{PersistentVolumeClaim: &kubevirtv1.PersistentVolumeClaimVolumeSource{
					PersistentVolumeClaimVolumeSource: corev1.PersistentVolumeClaimVolumeSource{ClaimName: a.Name},
				}}
			}
			volumes = append(volumes, kubevirtv1.Volume{Name: a.Name, VolumeSource: src})
		}
	} else {
		// Ephemeral fallback: containerDisk from Image (Phase-4 behavior).
		disks = []kubevirtv1.Disk{{Name: containerDiskName, DiskDevice: kubevirtv1.DiskDevice{Disk: &kubevirtv1.DiskTarget{Bus: kubevirtv1.DiskBusVirtio}}}}
		volumes = []kubevirtv1.Volume{{Name: containerDiskName, VolumeSource: kubevirtv1.VolumeSource{ContainerDisk: &kubevirtv1.ContainerDiskSource{Image: cvm.Spec.Image}}}}
	}
	// Guest bootstrap: a cloud-init NoCloud disk (users, SSH keys) so a stock cloud image is
	// loginable. Added alongside the boot disk regardless of ephemeral-vs-persistent boot.
	if ci := cvm.Spec.CloudInit; ci != nil && ci.UserData != "" {
		disks = append(disks, kubevirtv1.Disk{Name: cloudInitDiskName, DiskDevice: kubevirtv1.DiskDevice{Disk: &kubevirtv1.DiskTarget{Bus: kubevirtv1.DiskBusVirtio}}})
		volumes = append(volumes, kubevirtv1.Volume{Name: cloudInitDiskName, VolumeSource: kubevirtv1.VolumeSource{CloudInitNoCloud: &kubevirtv1.CloudInitNoCloudSource{UserData: ci.UserData}}})
	}
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

// namedAttachments narrows the attachments carrying a CompiledVM's workload label to the ones it
// names. A label match alone is not enough: an attachment whose volumeRef was removed keeps its
// label until the dispatch collects it, and must not go back into the template meanwhile. A twin
// compiled before spec.volumes existed names nothing and keeps all of them, as before. Pure.
func namedAttachments(cvm *compiledv1.CompiledVM, atts []compiledv1.CompiledVolumeAttachment) []compiledv1.CompiledVolumeAttachment {
	if len(cvm.Spec.Volumes) == 0 {
		return atts
	}
	var out []compiledv1.CompiledVolumeAttachment
	for _, a := range atts {
		if slices.Contains(cvm.Spec.Volumes, a.Name) {
			out = append(out, a)
		}
	}
	return out
}

// readyToMaterialize says whether a CompiledVM can become a KubeVirt VM yet, and if not, why. atts
// are all the attachments carrying its workload label; only the ones it names count.
//
// The broker delivers a CompiledVM and its attachments independently, so either may arrive first.
// A VM created ahead of its disks starts from a template without them — for a disk-booted VM, an
// empty containerDisk — and KubeVirt keeps that VMI (and its invalid launcher pod) even after the
// template is fixed. So the VM waits until every disk it names is here. Without an image it also
// waits for a boot disk: a template of data disks alone starts a VMI that runs without ever
// booting, and is never recreated. A twin compiled before spec.volumes existed names nothing; the
// attachments present are then taken as its disks, as before. Pure.
func readyToMaterialize(cvm *compiledv1.CompiledVM, atts []compiledv1.CompiledVolumeAttachment) (bool, string) {
	atts = namedAttachments(cvm, atts)
	have := make(map[string]bool, len(atts))
	boot := false
	for _, a := range atts {
		have[a.Name] = true
		boot = boot || a.Spec.Boot
	}
	var missing []string
	for _, v := range cvm.Spec.Volumes {
		if !have[v] {
			missing = append(missing, v)
		}
	}
	switch {
	case len(missing) > 0:
		return false, "waiting for volume attachment(s) " + strings.Join(missing, ", ")
	case cvm.Spec.Image == "" && len(atts) == 0:
		return false, "no image and no volume attachments: nothing to boot from"
	case cvm.Spec.Image == "" && !boot:
		return false, "waiting for a boot disk: no image, and none of the attachments is marked boot"
	}
	return true, ""
}

// VMMaterializerReconciler turns local CompiledVMs into KubeVirt VirtualMachines. It runs on the
// DOWNSTREAM cluster (a plain k8s cluster with KubeVirt installed), not against the central
// aggregated apiserver.
type VMMaterializerReconciler struct{ Client client.Client }

func (r *VMMaterializerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cvm compiledv1.CompiledVM
	if err := r.Client.Get(ctx, req.NamespacedName, &cvm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	var atts compiledv1.CompiledVolumeAttachmentList
	if w := cvm.Labels["workload"]; w != "" {
		if err := r.Client.List(ctx, &atts, client.InNamespace(cvm.Namespace), client.MatchingLabels{"workload": w}); err != nil {
			return ctrl.Result{}, fmt.Errorf("list attachments: %w", err)
		}
	}
	// Not ready: create nothing, and leave alone a VM that already exists. An attachment arriving
	// re-enqueues this CompiledVM (cvmsForAttachment).
	if ok, why := readyToMaterialize(&cvm, atts.Items); !ok {
		log.FromContext(ctx).Info("not materializing VM yet", "reason", why)
		return ctrl.Result{}, nil
	}
	desired := buildVM(&cvm, namedAttachments(&cvm, atts.Items))
	if err := ctrl.SetControllerReference(&cvm, desired, r.Client.Scheme()); err != nil {
		return ctrl.Result{}, err
	}
	// Server-side apply, NOT get-then-update-on-DeepEqual: the KubeVirt mutating webhook
	// defaults many fields inside .spec.template.spec (machine type, firmware UUID, disk/
	// feature defaults). A full-spec DeepEqual would always differ from our sparse intent
	// and re-write those defaults on every reconcile — a churn loop hammering the webhook.
	// With SSA the materializer owns ONLY the fields buildVM sets; kubevirt's field manager
	// keeps its defaults, so re-applying the same intent is a genuine no-op.
	if err := r.Client.Patch(ctx, desired, client.Apply, client.FieldOwner(vmFieldOwner), client.ForceOwnership); err != nil { //nolint:staticcheck // SA1019: server-side-apply migration tracked (engineering review Go follow-up)
		return ctrl.Result{}, fmt.Errorf("apply vm: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *VMMaterializerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&compiledv1.CompiledVM{}).
		Owns(&kubevirtv1.VirtualMachine{}).
		Watches(&compiledv1.CompiledVolumeAttachment{}, handler.EnqueueRequestsFromMapFunc(r.cvmsForAttachment)).
		Complete(r)
}

// cvmsForAttachment maps a CompiledVolumeAttachment event to its owning CompiledVM
// (named "{namespace}-{workload}"), so a new/changed DataVolume-backing attachment
// re-materializes the VM's disk list.
func (r *VMMaterializerReconciler) cvmsForAttachment(ctx context.Context, obj client.Object) []reconcile.Request {
	cva, ok := obj.(*compiledv1.CompiledVolumeAttachment)
	if !ok {
		return nil
	}
	w := cva.Labels["workload"]
	if w == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: cva.Namespace, Name: cva.Namespace + "-" + w}}}
}
