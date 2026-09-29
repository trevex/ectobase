// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// adoptable is an attachment carrying a recorded disk: what the compiler stamps when the Volume it
// attaches already has an image somewhere in the fleet.
func adoptable(name string) *compiledv1.CompiledVolumeAttachment {
	return &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
		Spec: compiledv1.CompiledVolumeAttachmentSpec{
			ClusterName:  "c2",
			Size:         resource.MustParse("1Gi"),
			StorageClass: "ceph-rbd",
			VolumeRef:    "disk",
			DiskIdentity: &compiledv1.DiskIdentity{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "rbd.csi.ceph.com",
					VolumeHandle: "0001-0024-fsid-0000000000000002-aaaa",
					VolumeAttributes: map[string]string{
						"clusterID": "fsid", "pool": "replicapool",
						"imageName": "csi-vol-aaaa", "imageFeatures": "layering",
					},
					NodeStageSecretRef: &corev1.SecretReference{Name: "csi-rbd-secret", Namespace: "ceph-csi"},
				},
				Capacity: resource.MustParse("1Gi"),
			},
		},
	}
}

// TestBuildAdoptedPV_ReplaysTheRecordedSourceAndPreBindsIt is the adoption itself: a PV in a cluster
// that never provisioned this disk, pointing at the image that already holds the data.
func TestBuildAdoptedPV_ReplaysTheRecordedSourceAndPreBindsIt(t *testing.T) {
	cva := adoptable("vm1-disk")
	pv := buildAdoptedPV(cva)

	if pv.Spec.CSI == nil || pv.Spec.CSI.VolumeHandle != "0001-0024-fsid-0000000000000002-aaaa" {
		t.Fatalf("csi source not replayed: %+v", pv.Spec.CSI)
	}
	if pv.Spec.CSI.VolumeAttributes["imageName"] != "csi-vol-aaaa" {
		t.Errorf("imageName: %q", pv.Spec.CSI.VolumeAttributes["imageName"])
	}
	if pv.Spec.CSI.NodeStageSecretRef == nil {
		t.Error("nodeStageSecretRef dropped; the volume would bind and then fail to mount")
	}
	// Retain from birth: an adopted PV must never be the thing that deletes a disk it did not
	// create, and it will be released again the next time this VM moves on.
	if pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain {
		t.Errorf("reclaimPolicy = %q, want Retain", pv.Spec.PersistentVolumeReclaimPolicy)
	}
	// Pre-bound to the claim it is for, so no other pending claim in the cluster can win it.
	if pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.Name != "vm1-disk" || pv.Spec.ClaimRef.Namespace != "default" {
		t.Errorf("claimRef = %+v, want default/vm1-disk", pv.Spec.ClaimRef)
	}
	if pv.Spec.VolumeMode == nil || *pv.Spec.VolumeMode != corev1.PersistentVolumeBlock {
		t.Error("volumeMode must be Block, matching how the disk was provisioned")
	}
	if pv.Spec.Capacity[corev1.ResourceStorage] != resource.MustParse("1Gi") {
		t.Errorf("capacity = %v", pv.Spec.Capacity[corev1.ResourceStorage])
	}

	pvc := buildAdoptedPVC(cva)
	if pvc.Name != "vm1-disk" || pvc.Namespace != "default" {
		t.Errorf("pvc meta: %s/%s", pvc.Namespace, pvc.Name)
	}
	if pvc.Spec.VolumeName != pv.Name {
		t.Errorf("pvc.volumeName = %q, want the adopted PV %q", pvc.Spec.VolumeName, pv.Name)
	}
	// Both sides must name the same class or the binder refuses the pair. (The PV's field is a
	// plain string, the PVC's a pointer.)
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != pv.Spec.StorageClassName {
		t.Errorf("storageClass mismatch: pvc=%v pv=%q", pvc.Spec.StorageClassName, pv.Spec.StorageClassName)
	}
}

// TestVolumeMaterializer_AdoptsRatherThanProvisioning is the behaviour that turns a destroyed disk
// into a moved one. In a cluster that never provisioned this disk, the materializer must bind the
// recorded image and must NOT create a DataVolume: a DataVolume would provision a second, blank
// image and the data would be silently gone.
func TestVolumeMaterializer_AdoptsRatherThanProvisioning(t *testing.T) {
	c, ctx := startDiskIdentityEnv(t)
	cva := adoptable("vm1-disk")
	if err := c.Create(ctx, cva); err != nil {
		t.Fatalf("create cva: %v", err)
	}

	r := &VolumeMaterializerReconciler{Client: c}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cva)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var pv corev1.PersistentVolume
	if err := c.Get(ctx, client.ObjectKey{Name: adoptedPVName(cva)}, &pv); err != nil {
		t.Fatalf("adopted PV not created: %v", err)
	}
	if pv.Spec.CSI == nil || pv.Spec.CSI.VolumeAttributes["imageName"] != "csi-vol-aaaa" {
		t.Errorf("adopted PV points at the wrong image: %+v", pv.Spec.CSI)
	}
	var pvc corev1.PersistentVolumeClaim
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "vm1-disk"}, &pvc); err != nil {
		t.Fatalf("adopted PVC not created: %v", err)
	}

	var dv cdiv1.DataVolume
	err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "vm1-disk"}, &dv)
	if err == nil {
		t.Fatal("a DataVolume was created for an adopted disk; it would provision a second, blank image")
	}
	if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error checking for a DataVolume: %v", err)
	}

	// Idempotent: the PV and PVC already exist on a second pass.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cva)}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
}

// TestVolumeMaterializer_StillProvisionsWithoutAnIdentity pins that nothing changes for a disk that
// has never existed: there is nothing to adopt, so CDI provisions it exactly as before.
func TestVolumeMaterializer_StillProvisionsWithoutAnIdentity(t *testing.T) {
	c, ctx := startDiskIdentityEnv(t)
	cva := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm2-disk"},
		Spec:       compiledv1.CompiledVolumeAttachmentSpec{ClusterName: "c1", Size: resource.MustParse("1Gi"), StorageClass: "ceph-rbd", VolumeRef: "disk"},
	}
	if err := c.Create(ctx, cva); err != nil {
		t.Fatalf("create cva: %v", err)
	}

	r := &VolumeMaterializerReconciler{Client: c}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cva)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var dv cdiv1.DataVolume
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "vm2-disk"}, &dv); err != nil {
		t.Fatalf("DataVolume not created for a disk with no identity: %v", err)
	}
	var pv corev1.PersistentVolume
	if err := c.Get(ctx, client.ObjectKey{Name: adoptedPVName(cva)}, &pv); !apierrors.IsNotFound(err) {
		t.Fatalf("a static PV was created for a disk that has to be provisioned: %v", err)
	}
}

// TestVolumeMaterializer_DoesNotAdoptWhereItAlreadyProvisioned is the case that only shows up once
// the whole chain is connected, and it would be destructive if missed.
//
// After a disk is provisioned, its identity is recorded and mirrored onto the Volume, and the NEXT
// compile stamps that identity into EVERY attachment of it — including the one in the cluster that
// provisioned it and is still running the VM. That cluster must keep its DataVolume rather than
// suddenly try to statically adopt a disk it already has, which would fight over the PVC name.
func TestVolumeMaterializer_DoesNotAdoptWhereItAlreadyProvisioned(t *testing.T) {
	c, ctx := startDiskIdentityEnv(t)
	cva := adoptable("vm3-disk")
	cva.Spec.ClusterName = "c1"
	if err := c.Create(ctx, cva); err != nil {
		t.Fatalf("create cva: %v", err)
	}
	// The DataVolume this cluster already provisioned the disk through.
	dv := buildDataVolume(cva)
	if err := c.Create(ctx, dv); err != nil {
		t.Fatalf("create pre-existing datavolume: %v", err)
	}

	r := &VolumeMaterializerReconciler{Client: c}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cva)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var pv corev1.PersistentVolume
	if err := c.Get(ctx, client.ObjectKey{Name: adoptedPVName(cva)}, &pv); !apierrors.IsNotFound(err) {
		t.Fatalf("adopted a disk in the cluster that provisioned it: %v", err)
	}
	var got cdiv1.DataVolume
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "vm3-disk"}, &got); err != nil {
		t.Fatalf("the existing DataVolume was abandoned: %v", err)
	}
}

// TestBuildVM_AdoptedDiskIsAttachedAsAClaim closes the last gap: an adopted disk has no DataVolume,
// so a VM referencing one by DataVolume source would wait forever for an object that is never
// created. The disk NAME is unchanged so guest-visible device ordering does not shift under a move.
func TestBuildVM_AdoptedDiskIsAttachedAsAClaim(t *testing.T) {
	cvm := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm1"}}
	atts := []compiledv1.CompiledVolumeAttachment{*adoptable("vm1-disk")}

	vm := buildVM(cvm, atts)
	if len(vm.Spec.Template.Spec.Volumes) != 1 {
		t.Fatalf("volumes: %+v", vm.Spec.Template.Spec.Volumes)
	}
	v := vm.Spec.Template.Spec.Volumes[0]
	if v.Name != "vm1-disk" {
		t.Errorf("volume name = %q, want the attachment name so disk order is stable", v.Name)
	}
	if v.DataVolume != nil {
		t.Error("an adopted disk must not be referenced as a DataVolume; none will ever exist")
	}
	if v.PersistentVolumeClaim == nil || v.PersistentVolumeClaim.ClaimName != "vm1-disk" {
		t.Fatalf("want a PVC source named vm1-disk, got %+v", v.PersistentVolumeClaim)
	}
}

// TestBuildVM_ProvisionedDiskStillUsesItsDataVolume keeps the unchanged path honest.
func TestBuildVM_ProvisionedDiskStillUsesItsDataVolume(t *testing.T) {
	cvm := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm1"}}
	atts := []compiledv1.CompiledVolumeAttachment{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm1-disk"},
		Spec:       compiledv1.CompiledVolumeAttachmentSpec{Size: resource.MustParse("1Gi")},
	}}
	vm := buildVM(cvm, atts)
	v := vm.Spec.Template.Spec.Volumes[0]
	if v.DataVolume == nil || v.DataVolume.Name != "vm1-disk" {
		t.Fatalf("want a DataVolume source, got %+v", v)
	}
}
