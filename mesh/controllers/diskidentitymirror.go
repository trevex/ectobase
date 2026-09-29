// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// DiskIdentityMirrorReconciler copies a reported disk identity from the CompiledVolumeAttachment it
// arrived on onto the Volume that owns the disk.
//
// This is the hop that makes the identity durable, and it is the whole point of the chain. The
// attachment is placement-scoped: a clusterName change deletes it and compiles a new one in another
// pool's namespace. The Volume is not — it has no cluster — so a record that must survive the move
// has to live there.
//
// It exists as a separate controller for the same reason VMPlacementMirrorReconciler does: a pool's
// broker may only write inside its own pool namespace, which is what per-pool RBAC scopes, while the
// Volume sits in a tenant namespace shared with other pools' workloads. Granting a pool that write
// would let any pool stamp any tenant's Volume. Doing the last hop here keeps the cross-namespace
// write with the fleet-scoped dispatch controller.
//
// It only ever writes status, only when it differs, and — critically — it never CLEARS an identity.
type DiskIdentityMirrorReconciler struct {
	Client client.Client
}

func (r *DiskIdentityMirrorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cva compiledv1.CompiledVolumeAttachment
	if err := r.Client.Get(ctx, req.NamespacedName, &cva); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Nothing reported. This is the ordinary state of a freshly compiled attachment, including the
	// one a rebind creates in the target pool before it has adopted anything — so it must be a
	// no-op rather than a clear. Mirroring "no identity" would erase the Volume's record at exactly
	// the moment the next stamp needs to read it, and the disk would be unreachable.
	if cva.Status.DiskIdentity == nil {
		return ctrl.Result{}, nil
	}
	// The twin does not live in its source's namespace, so the stamped back-reference is the only
	// way to find the namespace the Volume is in. spec.volumeRef then names the Volume itself: the
	// stamp points at the VirtualMachine, because attachments are 1:N per VM.
	ns, _, ok := sourceOf(&cva)
	if !ok || cva.Spec.VolumeRef == "" {
		return ctrl.Result{}, nil
	}
	var vol storagev1.Volume
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: cva.Spec.VolumeRef}, &vol); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	want := &storagev1.DiskIdentity{CSI: cva.Status.DiskIdentity.CSI.DeepCopy(), Capacity: cva.Status.DiskIdentity.Capacity}
	if equality.Semantic.DeepEqual(vol.Status.DiskIdentity, want) {
		return ctrl.Result{}, nil // no write, no resourceVersion churn
	}
	orig := vol.DeepCopy()
	vol.Status.DiskIdentity = want
	// Merge patch, not Update: other writers touch other fields of this same status subresource.
	if err := r.Client.Status().Patch(ctx, &vol, client.MergeFrom(orig)); err != nil {
		return ctrl.Result{}, fmt.Errorf("mirror disk identity onto volume %s/%s: %w", ns, cva.Spec.VolumeRef, err)
	}
	return ctrl.Result{}, nil
}

func (r *DiskIdentityMirrorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Distinct name: CompiledVolumeAttachmentReconciler already registers a controller that
		// watches this kind, and controller-runtime derives the default name from the watched kind.
		Named("diskidentitymirror").
		For(&compiledv1.CompiledVolumeAttachment{}).
		// Also re-mirror when the Volume changes, so a status wipe converges without waiting for the
		// pool's next report. No GenerationChangedPredicate here, unlike the compiler's Volume watch:
		// what needs re-converging IS a status change, which does not bump generation.
		Watches(&storagev1.Volume{}, handler.EnqueueRequestsFromMapFunc(r.attachmentsForVolume)).
		Complete(r)
}

// attachmentsForVolume maps a Volume back to the attachments of it.
//
// It scans by (source namespace, spec.volumeRef) rather than computing a name, because an
// attachment's name and namespace both depend on placement, and the point of this controller is to
// work across a change of placement.
func (r *DiskIdentityMirrorReconciler) attachmentsForVolume(ctx context.Context, obj client.Object) []reconcile.Request {
	vol, ok := obj.(*storagev1.Volume)
	if !ok {
		return nil
	}
	var atts compiledv1.CompiledVolumeAttachmentList
	if err := r.Client.List(ctx, &atts); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range atts.Items {
		att := &atts.Items[i]
		if att.Spec.VolumeRef != vol.Name {
			continue
		}
		if ns, _, ok := sourceOf(att); !ok || ns != vol.Namespace {
			continue
		}
		reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: att.Namespace, Name: att.Name}})
	}
	return reqs
}
