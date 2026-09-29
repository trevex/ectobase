// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"strings"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// provisionerAttrPrefix and provisionerIdentityAttr are the volumeAttributes an external provisioner
// adds about the claim it happened to provision for, as opposed to the driver's own facts about the
// volume. They name objects and a provisioner instance in ONE cluster, so replaying them into another
// points the driver at names that do not exist there.
const (
	provisionerAttrPrefix   = "csi.storage.k8s.io/"
	provisionerIdentityAttr = "storage.kubernetes.io/csiProvisionerIdentity"
)

// finalizerDisk holds a downstream attachment open long enough to let go of its disk.
//
// Without it a prune deletes the attachment outright: the DataVolume it owns cascades into the
// claim, the Retain PV is left Released forever, and — for an adopted disk, whose claim this
// controller owns nothing of — the claim itself is left behind holding a ReadWriteOnce reference to
// an image the target cluster is about to adopt.
const finalizerDisk = "compiled.ectobase.dev/disk"

// diskIdentityFromPV captures a provisioned PersistentVolume's CSI source as a portable identity,
// or nil if the PV is not CSI-backed and therefore has nothing that names it from another cluster.
//
// The source is deep-copied before the provisioner's bookkeeping is stripped: the attribute map is
// shared with the live object, so stripping in place would silently edit the PV being read.
func diskIdentityFromPV(pv *corev1.PersistentVolume) *compiledv1.DiskIdentity {
	if pv == nil || pv.Spec.CSI == nil {
		return nil
	}
	csi := pv.Spec.CSI.DeepCopy()
	for k := range csi.VolumeAttributes {
		if k == provisionerIdentityAttr || strings.HasPrefix(k, provisionerAttrPrefix) {
			delete(csi.VolumeAttributes, k)
		}
	}
	return &compiledv1.DiskIdentity{CSI: csi, Capacity: pv.Spec.Capacity[corev1.ResourceStorage]}
}

// DiskIdentityReconciler makes an attachment's disk outlive the attachment, and records what it is.
//
// It runs on the DOWNSTREAM cluster, beside the VolumeMaterializer, because a PersistentVolume only
// exists there. It does two things to each disk once it is bound:
//
//  1. flips the PV's reclaimPolicy to Retain. A dynamically provisioned PV inherits the
//     StorageClass's policy — Delete, in the lab — so the RBD image dies with its PVC. A clusterName
//     change prunes the CompiledVolumeAttachment, which cascades through the DataVolume it owns into
//     the PVC, and the image is destroyed. Retain turns that from destruction into a detach.
//
//  2. records the PV's CSI identity on the attachment's status, from where the broker carries it up
//     to the dispatch and a mesh controller mirrors it onto the Volume. That is what a later
//     attachment in another cluster is stamped with, so it adopts this disk instead of a blank one.
//
// Retain creates an obligation in return: the image now outlives its PVC by construction, so
// deleting a Volume has to reclaim it explicitly or every deleted volume leaks an image.
type DiskIdentityReconciler struct{ Client client.Client }

func (r *DiskIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cva compiledv1.CompiledVolumeAttachment
	if err := r.Client.Get(ctx, req.NamespacedName, &cva); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// On the way out the disk is detached rather than captured.
	if !cva.DeletionTimestamp.IsZero() {
		if err := r.releaseDisk(ctx, &cva); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, releaseFinalizer(ctx, r.Client, &cva, finalizerDisk)
	}
	if err := ensureFinalizer(ctx, r.Client, &cva, finalizerDisk); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure disk finalizer: %w", err)
	}

	// The PVC the VolumeMaterializer's DataVolume produces carries the attachment's name.
	var pvc corev1.PersistentVolumeClaim
	if err := r.Client.Get(ctx, req.NamespacedName, &pvc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Bound is the readiness rule, and it is deliberately about this PVC rather than about any
	// importer: CDI populates a block DataVolume through a separate "prime" PVC and only rebinds
	// that PV onto this one when the import finishes. So Bound here means the disk is fully written,
	// and capturing earlier would publish the identity of a half-imported disk that a move would
	// then adopt as if it were complete.
	if pvc.Status.Phase != corev1.ClaimBound || pvc.Spec.VolumeName == "" {
		return ctrl.Result{}, nil
	}

	var pv corev1.PersistentVolume
	if err := r.Client.Get(ctx, client.ObjectKey{Name: pvc.Spec.VolumeName}, &pv); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.ensureRetain(ctx, &pv); err != nil {
		return ctrl.Result{}, err
	}

	id := diskIdentityFromPV(&pv)
	if id == nil || equality.Semantic.DeepEqual(cva.Status.DiskIdentity, id) {
		return ctrl.Result{}, nil
	}
	orig := cva.DeepCopy()
	cva.Status.DiskIdentity = id
	if err := r.Client.Status().Patch(ctx, &cva, client.MergeFrom(orig)); err != nil {
		return ctrl.Result{}, fmt.Errorf("record disk identity on %s/%s: %w", cva.Namespace, cva.Name, err)
	}
	return ctrl.Result{}, nil
}

// ensureRetain makes a PersistentVolume outlive its claim, so deleting the claim detaches the disk
// instead of destroying it. A no-op when the PV already says Retain, so it is safe to call on every
// pass.
func (r *DiskIdentityReconciler) ensureRetain(ctx context.Context, pv *corev1.PersistentVolume) error {
	if pv.Spec.PersistentVolumeReclaimPolicy == corev1.PersistentVolumeReclaimRetain {
		return nil
	}
	orig := pv.DeepCopy()
	pv.Spec.PersistentVolumeReclaimPolicy = corev1.PersistentVolumeReclaimRetain
	if err := r.Client.Patch(ctx, pv, client.MergeFrom(orig)); err != nil {
		return fmt.Errorf("retain pv %s: %w", pv.Name, err)
	}
	return nil
}

// pvClaiming finds the PersistentVolume that names claim, for the case where the claim itself is
// already gone. A PV keeps its claimRef after release, so this still identifies the disk when the
// usual route — the claim's spec.volumeName — is no longer available.
func (r *DiskIdentityReconciler) pvClaiming(ctx context.Context, claim client.ObjectKey) (string, error) {
	var pvs corev1.PersistentVolumeList
	if err := r.Client.List(ctx, &pvs); err != nil {
		return "", fmt.Errorf("list persistentvolumes to find the one claimed by %s: %w", claim, err)
	}
	for i := range pvs.Items {
		ref := pvs.Items[i].Spec.ClaimRef
		if ref != nil && ref.Namespace == claim.Namespace && ref.Name == claim.Name {
			return pvs.Items[i].Name, nil
		}
	}
	return "", nil
}

// releaseDisk lets this cluster go of an attachment's disk WITHOUT destroying it, and is where the
// last data-loss window in this design is closed.
//
// A disk is normally protected by the reconcile that follows its claim binding. Between the image
// existing and that reconcile the PV still carries the StorageClass's reclaimPolicy — Delete, in the
// lab — so a clusterName change landing in that gap would prune the attachment, the cascade would
// take the claim, and the image would be gone. The gap cannot be closed by reacting sooner: the PV is
// only nameable once the claim binds, which is the same moment.
//
// It is closed HERE instead. This runs under the attachment's finalizer, and Kubernetes collects
// dependents only once their owner is actually gone — which the finalizer prevents — so the
// DataVolume and claim still exist at this point. Flipping the PV to Retain before dropping the claim
// therefore makes every detach non-destructive, whether or not anything protected the disk earlier.
// Order matters and is asserted by a test: after the claim is released the driver may already be
// deleting the volume.
//
// Retaining here never leaks, because reclaiming the image is the Volume's job: VolumeReclaim
// replays the identity as a Delete-policy PV when the Volume itself is deleted.
func (r *DiskIdentityReconciler) releaseDisk(ctx context.Context, cva *compiledv1.CompiledVolumeAttachment) error {
	key := client.ObjectKey{Namespace: cva.Namespace, Name: cva.Name}

	var pvc corev1.PersistentVolumeClaim
	pvcErr := r.Client.Get(ctx, key, &pvc)
	if pvcErr != nil && !apierrors.IsNotFound(pvcErr) {
		return fmt.Errorf("get claim %s: %w", key, pvcErr)
	}
	havePVC := pvcErr == nil

	pvName := ""
	if havePVC {
		pvName = pvc.Spec.VolumeName
	}
	if pvName == "" {
		// The claim is gone, or bound to nothing yet. A released PV still names it, so look there
		// rather than give up on protecting the disk.
		found, err := r.pvClaiming(ctx, key)
		if err != nil {
			return err
		}
		pvName = found
	}

	if pvName != "" {
		var pv corev1.PersistentVolume
		switch err := r.Client.Get(ctx, client.ObjectKey{Name: pvName}, &pv); {
		case apierrors.IsNotFound(err):
			pvName = "" // already gone; nothing to retain and nothing to delete
		case err != nil:
			return fmt.Errorf("get persistentvolume %s: %w", pvName, err)
		default:
			// THE GUARANTEE. Before anything releases the claim.
			if err := r.ensureRetain(ctx, &pv); err != nil {
				return err
			}
		}
	}

	if havePVC {
		if err := r.Client.Delete(ctx, &pvc); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("release claim %s: %w", key, err)
		}
	}
	if pvName == "" {
		return nil
	}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: pvName}}
	if err := r.Client.Delete(ctx, pv); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("release persistentvolume %s: %w", pvName, err)
	}
	return nil
}

// requestForPVCOfAttachment maps a PVC to the attachment of the same name, so the identity is
// captured the moment the disk binds rather than on the next resync. A PVC that belongs to no
// attachment resolves to a request that finds nothing and is dropped.
func requestForPVCOfAttachment(_ context.Context, obj client.Object) []reconcile.Request {
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}}}
}

func (r *DiskIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Distinct name: VolumeMaterializerReconciler runs in this same manager and also roots on
		// this kind, and controller-runtime derives the default name from the watched kind — so
		// without this the second registration fails and the whole vm-materializer never starts.
		Named("diskidentity").
		For(&compiledv1.CompiledVolumeAttachment{}).
		Watches(&corev1.PersistentVolumeClaim{}, handler.EnqueueRequestsFromMapFunc(requestForPVCOfAttachment)).
		Complete(r)
}
