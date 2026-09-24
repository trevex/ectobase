// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func mirrorScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		compiledv1.AddToScheme, computev1.AddToScheme, storagev1.AddToScheme, corev1.AddToScheme,
	} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func compiledIdentity(image string) *compiledv1.DiskIdentity {
	return &compiledv1.DiskIdentity{
		CSI: &corev1.CSIPersistentVolumeSource{
			Driver:           "rbd.csi.ceph.com",
			VolumeHandle:     "0001-0024-fsid-0000000000000002-" + image,
			VolumeAttributes: map[string]string{"imageName": "csi-vol-" + image},
		},
		Capacity: resource.MustParse("1Gi"),
	}
}

// reportedAttachment is a dispatch-side attachment carrying a reported identity, stamped with its
// source VirtualMachine and naming the Volume it attaches.
func reportedAttachment(id *compiledv1.DiskIdentity) *compiledv1.CompiledVolumeAttachment {
	cva := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: validate.PoolNamespace("c1"), Name: "default-vm1-disk"},
		Spec:       compiledv1.CompiledVolumeAttachmentSpec{ClusterName: "c1", Size: resource.MustParse("1Gi"), VolumeRef: "disk"},
		Status:     compiledv1.CompiledVolumeAttachmentStatus{DiskIdentity: id},
	}
	stampSource(cva, "default", "vm1")
	return cva
}

// TestDiskIdentityMirror_LandsTheIdentityOnTheVolume is the hop that makes the identity durable. The
// attachment is deleted by a clusterName change; the Volume is not, so the Volume is where a record
// that must survive the move has to end up.
func TestDiskIdentityMirror_LandsTheIdentityOnTheVolume(t *testing.T) {
	s := mirrorScheme(t)
	vol := &storagev1.Volume{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "disk"}}
	cva := reportedAttachment(compiledIdentity("aaaa"))

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(vol, cva).WithStatusSubresource(vol, cva).Build()
	r := &DiskIdentityMirrorReconciler{Client: c}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cva)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got storagev1.Volume
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "disk"}, &got); err != nil {
		t.Fatalf("get volume: %v", err)
	}
	if got.Status.DiskIdentity == nil || got.Status.DiskIdentity.CSI == nil {
		t.Fatalf("identity not mirrored onto the Volume: %+v", got.Status)
	}
	if want := "csi-vol-aaaa"; got.Status.DiskIdentity.CSI.VolumeAttributes["imageName"] != want {
		t.Errorf("imageName = %q, want %q", got.Status.DiskIdentity.CSI.VolumeAttributes["imageName"], want)
	}
	if got.Status.DiskIdentity.Capacity.Cmp(resource.MustParse("1Gi")) != 0 {
		t.Errorf("capacity = %v, want 1Gi", got.Status.DiskIdentity.Capacity)
	}
}

// TestDiskIdentityMirror_ResolvesTheVolumeByRefNotByName pins why spec.volumeRef exists. The
// attachment's name is <vmNamespace>-<vmName>-<volumeRef>, so splitting it on '-' is ambiguous as
// soon as a component contains one — here the VM is "vm-1" and the volume is "boot-disk", and any
// name-splitting scheme picks a wrong boundary.
func TestDiskIdentityMirror_ResolvesTheVolumeByRefNotByName(t *testing.T) {
	s := mirrorScheme(t)
	vol := &storagev1.Volume{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "boot-disk"}}
	decoy := &storagev1.Volume{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "disk"}}
	cva := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: validate.PoolNamespace("c1"), Name: "default-vm-1-boot-disk"},
		Spec:       compiledv1.CompiledVolumeAttachmentSpec{ClusterName: "c1", Size: resource.MustParse("1Gi"), VolumeRef: "boot-disk"},
		Status:     compiledv1.CompiledVolumeAttachmentStatus{DiskIdentity: compiledIdentity("bbbb")},
	}
	stampSource(cva, "default", "vm-1")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(vol, decoy, cva).WithStatusSubresource(vol, decoy, cva).Build()
	r := &DiskIdentityMirrorReconciler{Client: c}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cva)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got storagev1.Volume
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "boot-disk"}, &got); err != nil {
		t.Fatalf("get volume: %v", err)
	}
	if got.Status.DiskIdentity == nil {
		t.Error("the identity did not reach boot-disk, the volume spec.volumeRef names")
	}
	var other storagev1.Volume
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "disk"}, &other); err != nil {
		t.Fatalf("get decoy volume: %v", err)
	}
	if other.Status.DiskIdentity != nil {
		t.Error("the identity landed on 'disk', which is what splitting the attachment name would pick")
	}
}

// TestDiskIdentityMirror_IgnoresAnAttachmentWithNothingReported guards the ordinary case: most
// attachments have no identity yet, and those must not blank out a Volume that already has one.
func TestDiskIdentityMirror_IgnoresAnAttachmentWithNothingReported(t *testing.T) {
	s := mirrorScheme(t)
	vol := &storagev1.Volume{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "disk"},
		Status:     storagev1.VolumeStatus{DiskIdentity: &storagev1.DiskIdentity{CSI: &corev1.CSIPersistentVolumeSource{VolumeHandle: "keep-me"}}},
	}
	cva := reportedAttachment(nil)

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(vol, cva).WithStatusSubresource(vol, cva).Build()
	r := &DiskIdentityMirrorReconciler{Client: c}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cva)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got storagev1.Volume
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "disk"}, &got); err != nil {
		t.Fatalf("get volume: %v", err)
	}
	if got.Status.DiskIdentity == nil || got.Status.DiskIdentity.CSI.VolumeHandle != "keep-me" {
		t.Fatalf("an attachment reporting nothing erased the Volume's identity: %+v", got.Status.DiskIdentity)
	}
}

// TestDiskIdentityMirror_DoesNotRewriteAnIdentityOnceRecorded is the property the whole move depends
// on. A rebind creates a NEW attachment in the target pool, which provisions nothing and so reports
// nothing until it has adopted; if the mirror tracked the newest attachment it would clear the
// identity exactly when the next stamp needs to read it, and the disk would be lost.
func TestDiskIdentityMirror_DoesNotRewriteAnIdentityOnceRecorded(t *testing.T) {
	s := mirrorScheme(t)
	vol := &storagev1.Volume{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "disk"},
		Status:     storagev1.VolumeStatus{DiskIdentity: &storagev1.DiskIdentity{CSI: &corev1.CSIPersistentVolumeSource{VolumeHandle: "original"}}},
	}
	// The attachment in the new pool: same source VM and volume, no identity of its own yet.
	fresh := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: validate.PoolNamespace("c2"), Name: "default-vm1-disk"},
		Spec:       compiledv1.CompiledVolumeAttachmentSpec{ClusterName: "c2", Size: resource.MustParse("1Gi"), VolumeRef: "disk"},
	}
	stampSource(fresh, "default", "vm1")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(vol, fresh).WithStatusSubresource(vol, fresh).Build()
	r := &DiskIdentityMirrorReconciler{Client: c}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fresh)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got storagev1.Volume
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "disk"}, &got); err != nil {
		t.Fatalf("get volume: %v", err)
	}
	if got.Status.DiskIdentity == nil || got.Status.DiskIdentity.CSI.VolumeHandle != "original" {
		t.Fatalf("the mid-move attachment clobbered the recorded identity: %+v", got.Status.DiskIdentity)
	}
}
