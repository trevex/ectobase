// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"time"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// finalizerVolumeDisk holds a Volume open until the RBD image behind it has been deleted.
//
// It is the counterweight to Retain. Making a disk survive a cluster rebind means its image
// deliberately outlives every PersistentVolumeClaim that ever referenced it, so nothing reclaims it
// by cascade any more and deleting a Volume would otherwise leak its image forever.
const finalizerVolumeDisk = "storage.ectobase.dev/disk"

// reclaimReadyRequeue is how often a reclaim in progress is re-checked: the steps in between are
// performed by the PersistentVolume controller and the CSI driver, which this only observes.
const reclaimReadyRequeue = 5 * time.Second

// reclaimPVName is the PersistentVolume used to hand an image back to its driver for deletion. It is
// distinct from an adopted PV's name so a reclaim can never be mistaken for, or collide with, a
// PersistentVolume that is attaching the disk to a running VM.
func reclaimPVName(vol *storagev1.Volume) string {
	return "ectobase-reclaim-" + vol.Namespace + "-" + vol.Name
}

// VolumeReclaimReconciler deletes the RBD image behind a Volume when the Volume is deleted.
//
// This exists because Phase 0 took the disk out of the ownership cascade that used to reclaim it:
// a provisioned PersistentVolume is flipped to Retain so that pruning an attachment — which is what
// a clusterName change does — detaches the disk instead of destroying it. Nothing then reclaims the
// image by cascade, so something has to do it on purpose.
//
// An image is deleted by its CSI driver, never directly: the driver runs its deleter when a
// PersistentVolume it owns goes Bound -> Released under a Delete policy. So the reclaim replays the
// recorded identity as a Delete-policy PV, binds a claim to it, and drops the claim.
//
// It runs on the DISPATCH, which is deliberate and is what makes this simple. The dispatch already
// runs ceph-csi and the ceph-rbd StorageClass — it is the Tier-2 storage-fence executor — and one
// Ceph cluster backs every pool, with the same clusterID and a handle->image journal that lives in
// RADOS rather than in any Kubernetes cluster. So the dispatch can reach an image whichever pool
// last held it, and reclaim needs no cross-cluster handshake and no cooperation from a pool that may
// by then be gone.
type VolumeReclaimReconciler struct{ Client client.Client }

func (r *VolumeReclaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vol storagev1.Volume
	if err := r.Client.Get(ctx, req.NamespacedName, &vol); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	hasDisk := vol.Status.DiskIdentity != nil && vol.Status.DiskIdentity.CSI != nil

	if vol.DeletionTimestamp.IsZero() {
		// Only worth holding open once there is actually an image to reclaim.
		if !hasDisk {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, ensureFinalizer(ctx, r.Client, &vol, finalizerVolumeDisk)
	}

	if !hasDisk {
		return ctrl.Result{}, releaseFinalizer(ctx, r.Client, &vol, finalizerVolumeDisk)
	}

	// Never pull a disk out from under something using it. A Volume deleted while a VM still
	// attaches it waits here until the attachments are gone, rather than destroying live data.
	attached, err := r.stillAttached(ctx, &vol)
	if err != nil {
		return ctrl.Result{}, err
	}
	if attached {
		return ctrl.Result{RequeueAfter: reclaimReadyRequeue}, nil
	}

	return r.reclaim(ctx, &vol)
}

// stillAttached reports whether any compiled attachment still references this Volume.
func (r *VolumeReclaimReconciler) stillAttached(ctx context.Context, vol *storagev1.Volume) (bool, error) {
	var atts compiledv1.CompiledVolumeAttachmentList
	if err := r.Client.List(ctx, &atts); err != nil {
		return false, fmt.Errorf("list attachments of volume %s/%s: %w", vol.Namespace, vol.Name, err)
	}
	for i := range atts.Items {
		att := &atts.Items[i]
		if att.Spec.VolumeRef != vol.Name {
			continue
		}
		if ns, _, ok := sourceOf(att); ok && ns == vol.Namespace {
			return true, nil
		}
	}
	return false, nil
}

// reclaim advances the hand-the-image-back sequence by one step, and is safe to re-enter: each step
// is conditioned on what exists rather than on where it thinks it is.
func (r *VolumeReclaimReconciler) reclaim(ctx context.Context, vol *storagev1.Volume) (ctrl.Result, error) {
	name := reclaimPVName(vol)

	var pv corev1.PersistentVolume
	pvErr := r.Client.Get(ctx, client.ObjectKey{Name: name}, &pv)
	if pvErr != nil && !apierrors.IsNotFound(pvErr) {
		return ctrl.Result{}, fmt.Errorf("get reclaim pv %s: %w", name, pvErr)
	}
	pvGone := apierrors.IsNotFound(pvErr)

	var pvc corev1.PersistentVolumeClaim
	pvcErr := r.Client.Get(ctx, client.ObjectKey{Namespace: vol.Namespace, Name: name}, &pvc)
	if pvcErr != nil && !apierrors.IsNotFound(pvcErr) {
		return ctrl.Result{}, fmt.Errorf("get reclaim claim %s: %w", name, pvcErr)
	}
	pvcGone := apierrors.IsNotFound(pvcErr)

	switch {
	case pvGone && pvcGone && vol.Status.DiskReclaimStarted:
		// The driver deleted the volume and removed the PV. The image is gone; let the Volume go.
		return ctrl.Result{}, releaseFinalizer(ctx, r.Client, vol, finalizerVolumeDisk)

	case pvGone:
		// Create the pair. The PV is pre-bound with a claimRef so nothing else can take it, and it
		// carries Delete so that releasing the claim is what destroys the image.
		if err := r.Client.Create(ctx, buildReclaimPV(vol)); err != nil && !apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("create reclaim pv %s: %w", name, err)
		}
		if err := r.Client.Create(ctx, buildReclaimPVC(vol)); err != nil && !apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("create reclaim claim %s: %w", name, err)
		}
		if err := r.markReclaimStarted(ctx, vol); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: reclaimReadyRequeue}, nil

	case !pvcGone && pvc.Status.Phase == corev1.ClaimBound:
		// Bound: dropping the claim releases the PV, and the driver deletes the image behind it.
		if err := r.Client.Delete(ctx, &pvc); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("release reclaim claim %s: %w", name, err)
		}
		return ctrl.Result{RequeueAfter: reclaimReadyRequeue}, nil

	default:
		// Waiting on the PV controller to bind, or on the driver to finish deleting.
		return ctrl.Result{RequeueAfter: reclaimReadyRequeue}, nil
	}
}

// markReclaimStarted records that the pair has been created, so a later pass can tell "the driver
// finished and removed the PV" apart from "nothing has been created yet" — both of which look like
// an absent PV.
func (r *VolumeReclaimReconciler) markReclaimStarted(ctx context.Context, vol *storagev1.Volume) error {
	if vol.Status.DiskReclaimStarted {
		return nil
	}
	orig := vol.DeepCopy()
	vol.Status.DiskReclaimStarted = true
	if err := r.Client.Status().Patch(ctx, vol, client.MergeFrom(orig)); err != nil {
		return fmt.Errorf("mark reclaim started on volume %s/%s: %w", vol.Namespace, vol.Name, err)
	}
	return nil
}

// buildReclaimPV replays the recorded identity under a Delete policy, so releasing its claim hands
// the image to the driver for deletion. Pure.
func buildReclaimPV(vol *storagev1.Volume) *corev1.PersistentVolume {
	id := vol.Status.DiskIdentity
	block := corev1.PersistentVolumeBlock
	capacity := id.Capacity
	if capacity.IsZero() {
		capacity = vol.Spec.Size
	}
	name := reclaimPVName(vol)
	return &corev1.PersistentVolume{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolume"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes:                   []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Capacity:                      corev1.ResourceList{corev1.ResourceStorage: capacity},
			VolumeMode:                    &block,
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimDelete,
			StorageClassName:              vol.Spec.StorageClass,
			ClaimRef: &corev1.ObjectReference{
				APIVersion: "v1", Kind: "PersistentVolumeClaim",
				Namespace: vol.Namespace, Name: name,
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: id.CSI.DeepCopy()},
		},
	}
}

// buildReclaimPVC is the throwaway claim whose release triggers the deletion. Pure.
func buildReclaimPVC(vol *storagev1.Volume) *corev1.PersistentVolumeClaim {
	pv := buildReclaimPV(vol)
	block := corev1.PersistentVolumeBlock
	sc := vol.Spec.StorageClass
	return &corev1.PersistentVolumeClaim{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"},
		ObjectMeta: metav1.ObjectMeta{Namespace: vol.Namespace, Name: pv.Name},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			VolumeMode:       &block,
			VolumeName:       pv.Name,
			StorageClassName: &sc,
			Resources:        corev1.VolumeResourceRequirements{Requests: pv.Spec.Capacity},
		},
	}
}

func (r *VolumeReclaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("volumereclaim").
		For(&storagev1.Volume{}).
		Complete(r)
}
