// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// adoptedPVName is the name of the static PersistentVolume that binds an already-existing disk in a
// cluster that did not provision it.
//
// Derived from the attachment rather than from the volume handle: one attachment is one disk, so it
// cannot collide within a cluster, and it stays readable in `kubectl get pv`. Handles are ~90
// characters of hex and would make every PV in the fleet look alike.
func adoptedPVName(cva *compiledv1.CompiledVolumeAttachment) string {
	return "ectobase-" + cva.Namespace + "-" + cva.Name
}

// buildAdoptedPV replays a recorded disk identity as a PersistentVolume, so a cluster that never
// provisioned the disk can still bind the image that holds its data. Pure.
func buildAdoptedPV(cva *compiledv1.CompiledVolumeAttachment) *corev1.PersistentVolume {
	id := cva.Spec.DiskIdentity
	block := corev1.PersistentVolumeBlock
	capacity := id.Capacity
	if capacity.IsZero() {
		// An identity recorded before capacity was observed: the requested size is the best
		// available statement, and a PV must declare one.
		capacity = cva.Spec.Size
	}
	return &corev1.PersistentVolume{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolume"},
		ObjectMeta: metav1.ObjectMeta{Name: adoptedPVName(cva)},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Capacity:    corev1.ResourceList{corev1.ResourceStorage: capacity},
			VolumeMode:  &block,
			// Retain from birth. This PV did not create the image and must never be the thing that
			// deletes it — least of all when this VM moves on again and the claim is released.
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
			StorageClassName:              cva.Spec.StorageClass,
			// Pre-bound to the claim it exists for, so no other pending claim in the cluster can
			// win it in the window before the PVC is created.
			ClaimRef: &corev1.ObjectReference{
				APIVersion: "v1", Kind: "PersistentVolumeClaim",
				Namespace: cva.Namespace, Name: cva.Name,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: id.CSI.DeepCopy()},
		},
	}
}

// buildAdoptedPVC is the claim for an adopted PV, named after the attachment so the VM references
// the disk by the same name whether it was provisioned or adopted. Pure.
func buildAdoptedPVC(cva *compiledv1.CompiledVolumeAttachment) *corev1.PersistentVolumeClaim {
	pv := buildAdoptedPV(cva)
	block := corev1.PersistentVolumeBlock
	sc := cva.Spec.StorageClass
	return &corev1.PersistentVolumeClaim{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"},
		ObjectMeta: metav1.ObjectMeta{Namespace: cva.Namespace, Name: cva.Name, Labels: cva.Labels},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			VolumeMode:  &block,
			// Named explicitly rather than left to the binder: with both sides pointing at each
			// other the pair binds directly and cannot be matched against anything else.
			VolumeName:       pv.Name,
			StorageClassName: &sc,
			Resources:        corev1.VolumeResourceRequirements{Requests: pv.Spec.Capacity},
		},
	}
}

// adoptDisk binds an attachment's recorded disk in this cluster: a static PV replaying the CSI
// source the driver originally produced, and the claim for it.
//
// Creates only what is missing, so it is safe to run on every reconcile. It does NOT take ownership
// of either object: a PVC owned by the attachment would be deleted with it on the next move, and
// deleting the claim is precisely what has to happen WITHOUT the disk going too.
func (r *VolumeMaterializerReconciler) adoptDisk(ctx context.Context, cva *compiledv1.CompiledVolumeAttachment) error {
	pv := buildAdoptedPV(cva)
	if err := r.Client.Create(ctx, pv); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("adopt pv %s: %w", pv.Name, err)
	}
	pvc := buildAdoptedPVC(cva)
	if err := r.Client.Create(ctx, pvc); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("adopt pvc %s/%s: %w", pvc.Namespace, pvc.Name, err)
	}
	return nil
}

// shouldAdopt decides whether this cluster binds an existing disk or provisions a new one.
//
// An identity alone is not enough. Once a disk is provisioned its identity is recorded, mirrored
// onto the Volume, and stamped into EVERY attachment of it — including the one in the cluster that
// provisioned it and is still running the VM. That cluster already has the disk through its
// DataVolume and must keep it; only a cluster with no DataVolume for this attachment is one the disk
// has moved to.
func (r *VolumeMaterializerReconciler) shouldAdopt(ctx context.Context, cva *compiledv1.CompiledVolumeAttachment) (bool, error) {
	if cva.Spec.DiskIdentity == nil || cva.Spec.DiskIdentity.CSI == nil {
		return false, nil
	}
	var dv cdiv1.DataVolume
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: cva.Namespace, Name: cva.Name}, &dv)
	switch {
	case err == nil:
		return false, nil // provisioned here already
	case apierrors.IsNotFound(err):
		return true, nil
	default:
		return false, fmt.Errorf("look for an existing datavolume for %s/%s: %w", cva.Namespace, cva.Name, err)
	}
}
