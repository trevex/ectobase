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

// diskClaims returns every claim that may be holding this attachment's disk: its own, plus any
// claim OWNED by that one.
//
// The second part is not incidental. CDI populates a block DataVolume through a "prime" claim that
// it owns-references to the named one, and until the import finishes it is the PRIME claim that is
// bound to the image while the attachment's own claim sits Pending with no volumeName. Looking only
// at the attachment's claim therefore finds nothing to protect during exactly the window where
// protection matters — which is how the first version of this fix still lost the image.
func (r *DiskIdentityReconciler) diskClaims(ctx context.Context, att client.ObjectKey) ([]corev1.PersistentVolumeClaim, error) {
	var all corev1.PersistentVolumeClaimList
	if err := r.Client.List(ctx, &all, client.InNamespace(att.Namespace)); err != nil {
		return nil, fmt.Errorf("list claims in %s: %w", att.Namespace, err)
	}
	var out []corev1.PersistentVolumeClaim
	for i := range all.Items {
		c := all.Items[i]
		if c.Name == att.Name {
			out = append(out, c)
			continue
		}
		for _, ref := range c.OwnerReferences {
			if ref.Kind == "PersistentVolumeClaim" && ref.Name == att.Name {
				out = append(out, c)
				break
			}
		}
	}
	return out, nil
}

// pvHolding names the PersistentVolume a claim holds: its spec.volumeName when bound, else a PV
// whose claimRef still points at it (a released PV keeps that reference).
func (r *DiskIdentityReconciler) pvHolding(ctx context.Context, claim corev1.PersistentVolumeClaim) (string, error) {
	if claim.Spec.VolumeName != "" {
		return claim.Spec.VolumeName, nil
	}
	var pvs corev1.PersistentVolumeList
	if err := r.Client.List(ctx, &pvs); err != nil {
		return "", fmt.Errorf("list persistentvolumes to find the one claimed by %s/%s: %w", claim.Namespace, claim.Name, err)
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
// take the claims, and the image would be gone. The gap cannot be closed by reacting sooner: the PV
// is only nameable once a claim binds.
//
// It is closed HERE instead. This runs under the attachment's finalizer, and Kubernetes collects
// dependents only once their owner is actually gone — which the finalizer prevents — so the
// DataVolume and claims still exist at this point. Retaining every PV they hold before dropping
// anything makes each detach non-destructive, whether or not the disk was protected earlier.
//
// Order matters and is asserted by a test: after a claim is released its driver may already be
// deleting the volume. So is the claim TREE — during a CDI import the image is held by the prime
// claim, not the attachment's own, and an earlier version of this that looked only at the
// attachment's claim was verified on the live fabric to still destroy the image.
//
// Retaining here never leaks, because reclaiming the image is the Volume's job: VolumeReclaim
// replays the identity as a Delete-policy PV when the Volume itself is deleted.
func (r *DiskIdentityReconciler) releaseDisk(ctx context.Context, cva *compiledv1.CompiledVolumeAttachment) error {
	key := client.ObjectKey{Namespace: cva.Namespace, Name: cva.Name}
	claims, err := r.diskClaims(ctx, key)
	if err != nil {
		return err
	}

	// 1. Protect first, everything, before releasing anything.
	var pvNames []string
	for _, c := range claims {
		name, err := r.pvHolding(ctx, c)
		if err != nil {
			return err
		}
		if name == "" {
			continue
		}
		var pv corev1.PersistentVolume
		switch err := r.Client.Get(ctx, client.ObjectKey{Name: name}, &pv); {
		case apierrors.IsNotFound(err):
			continue
		case err != nil:
			return fmt.Errorf("get persistentvolume %s: %w", name, err)
		}
		if err := r.ensureRetain(ctx, &pv); err != nil {
			return err
		}
		pvNames = append(pvNames, name)
	}

	// 2. Only now let go. Deleting the attachment's own claim cascades to the prime one through its
	//    ownerReference; both their volumes are Retain by this point, so the images outlive it.
	for i := range claims {
		if claims[i].Name != key.Name {
			continue // owned by the one below; let the cascade take it
		}
		if err := r.Client.Delete(ctx, &claims[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("release claim %s: %w", key, err)
		}
	}
	for _, name := range pvNames {
		pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: name}}
		if err := r.Client.Delete(ctx, pv); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("release persistentvolume %s: %w", name, err)
		}
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
