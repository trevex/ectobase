// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// dvFieldOwner is the VolumeMaterializer's server-side-apply field manager.
const dvFieldOwner = "volume-materializer"

// buildDataVolume turns a CompiledVolumeAttachment into a CDI DataVolume: an RBD PVC
// (via the ceph-csi StorageClass) whose source is a registry import of BootImage
// (bootable) or a blank disk of Size. Pure; TypeMeta set for server-side apply.
func buildDataVolume(cva *netv1.CompiledVolumeAttachment) *cdiv1.DataVolume {
	// Block volumeMode: the correct mode for a KubeVirt VM disk (raw block device — better perf and
	// clean cross-node reschedule/migration semantics vs a disk.img on a Filesystem PVC).
	blockMode := corev1.PersistentVolumeBlock
	storage := &cdiv1.StorageSpec{
		AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		VolumeMode:  &blockMode,
		Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: cva.Spec.Size}},
	}
	if cva.Spec.StorageClass != "" {
		sc := cva.Spec.StorageClass
		storage.StorageClassName = &sc
	}
	var source *cdiv1.DataVolumeSource
	if cva.Spec.BootImage != "" {
		url := "docker://" + cva.Spec.BootImage
		// Default (pod) pull method: the importer pod pulls the containerdisk over the pod network.
		// This needs the pod network to have registry egress — on the IPv6-only clab overlay that
		// comes from the edge's Tayga NAT64/DNS64. (pullMethod=node was tried but CDI's node-pull
		// importer mis-handles the RBD block device on kind: Block -> GetAvailableSpaceBlock panic,
		// Filesystem -> 'unable to convert source data to target format'.)
		source = &cdiv1.DataVolumeSource{Registry: &cdiv1.DataVolumeSourceRegistry{URL: &url}}
	} else {
		source = &cdiv1.DataVolumeSource{Blank: &cdiv1.DataVolumeBlankImage{}}
	}
	labels := map[string]string{}
	if w := cva.Labels["workload"]; w != "" {
		labels["workload"] = w
	}
	return &cdiv1.DataVolume{
		TypeMeta:   metav1.TypeMeta{APIVersion: cdiv1.SchemeGroupVersion.String(), Kind: "DataVolume"},
		ObjectMeta: metav1.ObjectMeta{Namespace: cva.Namespace, Name: cva.Name, Labels: labels},
		Spec:       cdiv1.DataVolumeSpec{Source: source, Storage: storage},
	}
}

// VolumeMaterializerReconciler turns CompiledVolumeAttachments into CDI DataVolumes.
// It runs on the DOWNSTREAM cluster (plain k8s + CDI/ceph-csi), not against central.
type VolumeMaterializerReconciler struct{ Client client.Client }

func (r *VolumeMaterializerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cva netv1.CompiledVolumeAttachment
	if err := r.Client.Get(ctx, req.NamespacedName, &cva); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	desired := buildDataVolume(&cva)
	if err := ctrl.SetControllerReference(&cva, desired, r.Client.Scheme()); err != nil {
		return ctrl.Result{}, err
	}
	// Server-side apply: CDI's webhook/controller defaults many DataVolume fields;
	// the materializer owns only its intent, so re-applying is a no-op (no churn).
	if err := r.Client.Patch(ctx, desired, client.Apply, client.FieldOwner(dvFieldOwner), client.ForceOwnership); err != nil {
		return ctrl.Result{}, fmt.Errorf("apply datavolume: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *VolumeMaterializerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.CompiledVolumeAttachment{}).
		Owns(&cdiv1.DataVolume{}).
		Complete(r)
}
