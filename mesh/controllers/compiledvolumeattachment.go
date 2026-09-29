// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// CompileVolumeAttachments lowers a VirtualMachine + its referenced Volumes into one
// CompiledVolumeAttachment per VolumeRef, each cluster-bound (from placement) and
// workload-labelled. A Volume with a BootImage yields Boot=true. Pure.
func CompileVolumeAttachments(vm *computev1.VirtualMachine, volumes []storagev1.Volume, placement Placement) []compiledv1.CompiledVolumeAttachment {
	byName := map[string]*storagev1.Volume{}
	for i := range volumes {
		byName[volumes[i].Name] = &volumes[i]
	}
	var out []compiledv1.CompiledVolumeAttachment
	for _, ref := range vm.Spec.VolumeRefs {
		vol, ok := byName[ref.Name]
		if !ok {
			continue // volume not found yet; the Volume watch re-triggers
		}
		att := compiledv1.CompiledVolumeAttachment{
			TypeMeta: metav1.TypeMeta{APIVersion: "compiled.ectobase.dev/v1alpha1", Kind: "CompiledVolumeAttachment"},
			// Namespace-qualified: two VMs of the same name in different tenant namespaces would
			// otherwise collide on this name once they share one pool namespace.
			ObjectMeta: metav1.ObjectMeta{
				Name:      compiledTwinName(vm.Namespace, vm.Name) + "-" + ref.Name,
				Namespace: validate.PoolNamespace(placement.ClusterName),
			},
			Spec: compiledv1.CompiledVolumeAttachmentSpec{
				ClusterName:  placement.ClusterName,
				Size:         vol.Spec.Size,
				StorageClass: vol.Spec.StorageClass,
				BootImage:    vol.Spec.BootImage,
				Boot:         vol.Spec.BootImage != "",
				VolumeRef:    ref.Name,
				// If the Volume already has a disk, hand its identity to whichever cluster this
				// compiles into, so the attachment ADOPTS that disk rather than provisioning a blank
				// one. This is what makes a clusterName change a move: the identity is stamped from
				// the Volume, which has no cluster, so it survives being re-compiled elsewhere.
				DiskIdentity: diskIdentityForAttachment(vol),
			},
		}
		if placement.WorkloadID != "" {
			att.Labels = map[string]string{"workload": placement.WorkloadID}
		}
		out = append(out, att)
	}
	return out
}

// diskIdentityForAttachment converts a Volume's observed disk identity into the compiled group's
// declaration of it, or nil when the Volume has no disk yet and there is nothing to adopt.
//
// The two types are deliberately separate — a pool consumes only compiled.ectobase.dev and never
// imports the source API — so this crossing is where one becomes the other.
func diskIdentityForAttachment(vol *storagev1.Volume) *compiledv1.DiskIdentity {
	if vol.Status.DiskIdentity == nil || vol.Status.DiskIdentity.CSI == nil {
		return nil
	}
	return &compiledv1.DiskIdentity{
		CSI:      vol.Status.DiskIdentity.CSI.DeepCopy(),
		Capacity: vol.Status.DiskIdentity.Capacity,
	}
}

// unprotectedRebindsOf adapts the reconciler's []client.Object twin list to the pure check below.
func unprotectedRebindsOf(desired []compiledv1.CompiledVolumeAttachment, have []client.Object, volumes []storagev1.Volume) []unprotectedRebind {
	typed := make([]compiledv1.CompiledVolumeAttachment, 0, len(have))
	for _, o := range have {
		if cur, ok := o.(*compiledv1.CompiledVolumeAttachment); ok {
			typed = append(typed, *cur)
		}
	}
	return unprotectedRebinds(desired, typed, volumes)
}

// unprotectedRebind names a disk about to move pools while nothing is protecting it.
type unprotectedRebind struct {
	Volume string // the source Volume's name
	From   string // the pool namespace the attachment is leaving
	To     string // the pool namespace it is compiled into
}

// unprotectedRebinds reports the disks being moved to another pool before their identity has been
// recorded — the one window in which a rebind still DESTROYS data rather than moving it.
//
// A disk is protected once the pool that provisioned it observes the bound claim: that is when its
// PersistentVolume becomes Retain and its CSI identity is captured. Until then the PV still carries
// the StorageClass's reclaimPolicy (Delete), so pruning the old attachment takes the image with it
// while the target provisions a blank one. Nothing can protect a disk that has not been observed
// yet, so the window is inherent — but it is narrow, knowable here, and worth saying out loud
// instead of losing data quietly.
//
// Twins are matched by NAME rather than by spec.volumeRef so this still works for attachments
// compiled before volumeRef existed: the name is identical across pools and only the namespace
// differs, which is exactly what makes a move recognisable. The volumeRef is then taken from the
// DESIRED attachment, which the current compiler always sets, to find the Volume.
//
// Pure, so the judgement is unit-tested rather than inferred from a reconcile.
func unprotectedRebinds(desired, have []compiledv1.CompiledVolumeAttachment, volumes []storagev1.Volume) []unprotectedRebind {
	protected := make(map[string]bool, len(volumes))
	for i := range volumes {
		id := volumes[i].Status.DiskIdentity
		protected[volumes[i].Name] = id != nil && id.CSI != nil
	}
	byName := make(map[string]compiledv1.CompiledVolumeAttachment, len(desired))
	for _, d := range desired {
		byName[d.Name] = d
	}
	var out []unprotectedRebind
	for _, cur := range have {
		d, ok := byName[cur.Name]
		if !ok || d.Namespace == cur.Namespace {
			continue // gone entirely, or staying put: neither is a move
		}
		if d.Spec.VolumeRef == "" || protected[d.Spec.VolumeRef] {
			continue
		}
		out = append(out, unprotectedRebind{Volume: d.Spec.VolumeRef, From: cur.Namespace, To: d.Namespace})
	}
	return out
}

// CompiledVolumeAttachmentReconciler upserts a VM's CompiledVolumeAttachments (one per
// VolumeRef) and GCs attachments for VolumeRefs that were removed.
type CompiledVolumeAttachmentReconciler struct {
	Client client.Client
	// APIReader is an UNCACHED reader for the move gate: a twin the informer has not seen yet must
	// still close it.
	APIReader client.Reader
}

func (r *CompiledVolumeAttachmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vm computev1.VirtualMachine
	if err := r.Client.Get(ctx, req.NamespacedName, &vm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// 1:N teardown: delete every attachment stamped with this VM. Its own finalizer, not
	// CompiledVMReconciler's — both source from VirtualMachine, and a shared one would let the VM
	// vanish after whichever reconciler ran first released it.
	if !vm.DeletionTimestamp.IsZero() {
		if err := deleteTwinsOfSource(ctx, r.Client, &compiledv1.CompiledVolumeAttachmentList{}, vm.Namespace, vm.Name); err != nil {
			return ctrl.Result{}, fmt.Errorf("teardown attachments: %w", err)
		}
		return ctrl.Result{}, releaseFinalizer(ctx, r.Client, &vm, finalizerCompiledVolumeAttachment)
	}
	if err := ensureFinalizer(ctx, r.Client, &vm, finalizerCompiledVolumeAttachment); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure compiledvolumeattachment finalizer: %w", err)
	}
	// No pool, no namespace to compile into — and nothing downstream could consume the twins.
	if vm.Spec.ClusterName == "" {
		return ctrl.Result{}, nil
	}
	var volList storagev1.VolumeList
	if err := r.Client.List(ctx, &volList, client.InNamespace(vm.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list volumes: %w", err)
	}
	placement := Placement{ClusterName: vm.Spec.ClusterName, WorkloadID: vm.Name}
	desired := CompileVolumeAttachments(&vm, volList.Items, placement)
	// The same gate as the CompiledVM compiler (movegate.go): while any other CompiledVM twin of
	// this VM exists, its pool may still be running the VM, so no disk is compiled into this pool.
	// Stale attachments elsewhere are still removed below — a disk leaves at once; only arriving
	// waits.
	vmTwins, err := gateTwins(ctx, r.APIReader, vm.Namespace, vm.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	gateOpen := len(awaitingRelease(validate.PoolNamespace(vm.Spec.ClusterName), vmTwins)) == 0
	want := map[types.NamespacedName]compiledv1.CompiledVolumeAttachment{}
	keep := map[types.NamespacedName]bool{}
	for _, a := range desired {
		key := types.NamespacedName{Namespace: a.Namespace, Name: a.Name}
		want[key] = a
		keep[key] = true
	}
	// Found by stamp rather than by namespace+label: the twins live in the pool namespace now, and
	// this also catches any stranded in a namespace the compiler no longer writes to.
	haveTwins, err := twinsOfSource(ctx, r.Client, &compiledv1.CompiledVolumeAttachmentList{}, vm.Namespace, vm.Name)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list attachments: %w", err)
	}
	// Warn before the diff below acts on it: a disk moving pools with no recorded identity is
	// about to be destroyed rather than moved, and this is the last point at which anything knows.
	if rebinds := unprotectedRebindsOf(desired, haveTwins, volList.Items); len(rebinds) > 0 {
		lg := log.FromContext(ctx)
		for _, rb := range rebinds {
			lg.Error(nil, "moving a VM whose disk has no recorded identity yet — the image will be "+
				"DESTROYED rather than moved; the disk becomes safe to move only once its pool has "+
				"observed the bound claim (PersistentVolume flipped to Retain, identity captured)",
				"vm", vm.Namespace+"/"+vm.Name, "volume", vm.Namespace+"/"+rb.Volume,
				"from", rb.From, "to", rb.To)
		}
	}

	haveKeys := map[types.NamespacedName]bool{}
	for _, obj := range haveTwins {
		cur, ok := obj.(*compiledv1.CompiledVolumeAttachment)
		if !ok {
			continue
		}
		curKey := types.NamespacedName{Namespace: cur.Namespace, Name: cur.Name}
		haveKeys[curKey] = true
		w, ok := want[curKey]
		if !ok {
			// A VolumeRef was removed, or the twin is in a namespace we no longer write to.
			if err := r.Client.Delete(ctx, cur); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("gc attachment %s/%s: %w", cur.Namespace, cur.Name, err)
			}
			continue
		}
		// Spec carries a resource.Quantity (Size), so compare semantically (10Gi ==
		// 10737418240) rather than reflect.DeepEqual — else equal sizes with different
		// literals would churn Updates. Also refresh the workload label defensively
		// (immutable in practice — it's vm.Name, the list key — but keeps parity with
		// the 1:1 CompiledNIC/CompiledVM compilers).
		if gateOpen && (!equality.Semantic.DeepEqual(cur.Spec, w.Spec) || cur.Labels["workload"] != w.Labels["workload"]) {
			cur.Spec = w.Spec
			if cur.Labels == nil {
				cur.Labels = map[string]string{}
			}
			cur.Labels["workload"] = w.Labels["workload"]
			if err := r.Client.Update(ctx, cur); err != nil {
				return ctrl.Result{}, fmt.Errorf("update attachment %s: %w", cur.Name, err)
			}
		}
	}
	for key, w := range want {
		if !gateOpen {
			break
		}
		if haveKeys[key] {
			continue
		}
		att := w
		stampSource(&att, vm.Namespace, vm.Name)
		if err := r.Client.Create(ctx, &att); err != nil {
			return ctrl.Result{}, fmt.Errorf("create attachment %s/%s: %w", key.Namespace, key.Name, err)
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager watches VirtualMachines (Owns their attachments) + re-enqueues a VM
// when a referenced Volume changes.
func (r *CompiledVolumeAttachmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Distinct name: CompiledVMReconciler also For(VirtualMachine) (both default to
		// "virtualmachine" otherwise -> duplicate-controller-name panic at manager start).
		Named("compiledvolumeattachment").
		For(&computev1.VirtualMachine{}).
		// Not Owns(): the twin lives in the pool namespace, and EnqueueRequestForOwner derives the
		// request from the DEPENDENT's namespace, which would enqueue a VM key that does not exist.
		Watches(&compiledv1.CompiledVolumeAttachment{}, handler.EnqueueRequestsFromMapFunc(requestForSource)).
		// The gate opens when a retired CompiledVM twin disappears, which is not an attachment
		// event — so watch the VM twins too, or the target's disks wait for an unrelated resync.
		Watches(&compiledv1.CompiledVM{}, handler.EnqueueRequestsFromMapFunc(requestForSource)).
		// Only Volume spec changes (Size/StorageClass/BootImage) affect the compiled
		// attachment; GenerationChangedPredicate skips re-compiling on Volume status writes.
		Watches(&storagev1.Volume{}, handler.EnqueueRequestsFromMapFunc(r.vmsForVolume),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// vmsForVolume maps a Volume event to reconcile requests for VMs (same namespace) that reference it.
func (r *CompiledVolumeAttachmentReconciler) vmsForVolume(ctx context.Context, obj client.Object) []reconcile.Request {
	vol, ok := obj.(*storagev1.Volume)
	if !ok {
		return nil
	}
	var vms computev1.VirtualMachineList
	if err := r.Client.List(ctx, &vms, client.InNamespace(vol.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range vms.Items {
		for _, ref := range vms.Items[i].Spec.VolumeRefs {
			if ref.Name == vol.Name {
				reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: vms.Items[i].Namespace, Name: vms.Items[i].Name}})
				break
			}
		}
	}
	return reqs
}
