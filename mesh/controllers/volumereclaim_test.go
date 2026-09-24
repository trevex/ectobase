// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func provisionedVolume(name string, deleting bool) *storagev1.Volume {
	vol := &storagev1.Volume{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
		Spec:       storagev1.VolumeSpec{Size: resource.MustParse("1Gi"), StorageClass: "ceph-rbd"},
		Status: storagev1.VolumeStatus{DiskIdentity: &storagev1.DiskIdentity{
			CSI: &corev1.CSIPersistentVolumeSource{
				Driver:           "rbd.csi.ceph.com",
				VolumeHandle:     "0001-0024-fsid-0000000000000002-aaaa",
				VolumeAttributes: map[string]string{"imageName": "csi-vol-aaaa", "pool": "replicapool"},
			},
			Capacity: resource.MustParse("1Gi"),
		}},
	}
	if deleting {
		now := metav1.Now()
		vol.DeletionTimestamp = &now
		vol.Finalizers = []string{finalizerVolumeDisk}
	}
	return vol
}

func reclaimClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(mirrorScheme(t)).WithObjects(objs...).
		WithStatusSubresource(objs...).Build()
}

// TestVolumeReclaim_TakesAFinalizerOnceThereIsADiskToReclaim: the finalizer is what buys the chance
// to delete the image at all, and it is only warranted once an image exists.
func TestVolumeReclaim_TakesAFinalizerOnceThereIsADiskToReclaim(t *testing.T) {
	vol := provisionedVolume("disk", false)
	c := reclaimClient(t, vol)
	r := &VolumeReclaimReconciler{Client: c}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vol)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got storagev1.Volume
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(vol), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("no finalizer: deleting this Volume would leak its RBD image forever")
	}
}

// TestVolumeReclaim_ReleasesAVolumeThatNeverHadADisk keeps the finalizer from wedging deletion of a
// Volume nothing ever provisioned.
func TestVolumeReclaim_ReleasesAVolumeThatNeverHadADisk(t *testing.T) {
	now := metav1.Now()
	vol := &storagev1.Volume{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "never", DeletionTimestamp: &now,
			Finalizers: []string{finalizerVolumeDisk},
		},
	}
	c := reclaimClient(t, vol)
	r := &VolumeReclaimReconciler{Client: c}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vol)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got storagev1.Volume
	err := c.Get(context.Background(), client.ObjectKeyFromObject(vol), &got)
	if err == nil && len(got.Finalizers) > 0 {
		t.Fatalf("finalizer held on a Volume with no disk: %v", got.Finalizers)
	}
}

// TestVolumeReclaim_WaitsWhileSomethingStillAttachesTheDisk is the guard against destroying a disk
// out from under a running VM. A Volume deleted while still attached must not have its image
// removed until nothing references it.
func TestVolumeReclaim_WaitsWhileSomethingStillAttachesTheDisk(t *testing.T) {
	vol := provisionedVolume("disk", true)
	att := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: validate.PoolNamespace("c1"), Name: "default-vm1-disk"},
		Spec:       compiledv1.CompiledVolumeAttachmentSpec{ClusterName: "c1", Size: resource.MustParse("1Gi"), VolumeRef: "disk"},
	}
	stampSource(att, "default", "vm1")

	c := reclaimClient(t, vol, att)
	r := &VolumeReclaimReconciler{Client: c}
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vol)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("returned done while an attachment still holds the disk; it must keep waiting")
	}
	var pv corev1.PersistentVolume
	if err := c.Get(context.Background(), client.ObjectKey{Name: reclaimPVName(vol)}, &pv); !apierrors.IsNotFound(err) {
		t.Fatalf("started reclaiming a disk that is still attached: %v", err)
	}
	var got storagev1.Volume
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(vol), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Error("released the finalizer while the disk was still attached")
	}
}

// TestVolumeReclaim_BindsTheImageThenReleasesItToBeDeleted drives the actual deletion.
//
// An RBD image is deleted by its CSI driver, not by us, and the driver only runs its deleter when a
// PersistentVolume it owns goes Bound -> Released under a Delete policy. So the reclaim replays the
// recorded identity as a Delete-policy PV on the dispatch — which runs ceph-csi as the Tier-2 fence
// executor and can therefore reach the same Ceph cluster — binds a claim to it, and drops the claim.
// Nothing here talks to Ceph directly, and nothing needs the pool that used to hold the disk.
func TestVolumeReclaim_BindsTheImageThenReleasesItToBeDeleted(t *testing.T) {
	vol := provisionedVolume("disk", true)
	c := reclaimClient(t, vol)
	r := &VolumeReclaimReconciler{Client: c}
	ctx := context.Background()
	key := client.ObjectKeyFromObject(vol)

	// Pass 1: the pair is created, pre-bound to each other.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	var pv corev1.PersistentVolume
	if err := c.Get(ctx, client.ObjectKey{Name: reclaimPVName(vol)}, &pv); err != nil {
		t.Fatalf("reclaim PV not created: %v", err)
	}
	if pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimDelete {
		t.Fatalf("reclaimPolicy = %q, want Delete — nothing would delete the image otherwise",
			pv.Spec.PersistentVolumeReclaimPolicy)
	}
	if pv.Spec.CSI == nil || pv.Spec.CSI.VolumeAttributes["imageName"] != "csi-vol-aaaa" {
		t.Fatalf("the reclaim PV points at the wrong image: %+v", pv.Spec.CSI)
	}
	var pvc corev1.PersistentVolumeClaim
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: reclaimPVName(vol)}, &pvc); err != nil {
		t.Fatalf("reclaim PVC not created: %v", err)
	}

	// Pass 2: once bound, the claim is dropped. That release is what makes the driver delete.
	pvc.Status.Phase = corev1.ClaimBound
	if err := c.Status().Update(ctx, &pvc); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: reclaimPVName(vol)}, &pvc); !apierrors.IsNotFound(err) {
		t.Fatalf("the claim was not released, so the image is never deleted: %v", err)
	}

	// The finalizer is still held: the image is not gone until the PV is.
	var got storagev1.Volume
	if err := c.Get(ctx, key, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Error("released the Volume before the driver had deleted the image")
	}

	// Pass 3: the driver has deleted the volume and removed the PV. Now the Volume may go.
	if err := c.Delete(ctx, &pv); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("pass 3: %v", err)
	}
	err := c.Get(ctx, key, &got)
	if err == nil && len(got.Finalizers) > 0 {
		t.Fatalf("finalizer never released: %v", got.Finalizers)
	}
}
