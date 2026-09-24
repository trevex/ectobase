package controllers

import (
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCompileVolumeAttachments(t *testing.T) {
	vm := &computev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1"},
		Spec:       computev1.VirtualMachineSpec{ClusterName: "c1", VolumeRefs: []computev1.LocalObjectReference{{Name: "boot"}, {Name: "data"}}},
	}
	volumes := []storagev1.Volume{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "boot"}, Spec: storagev1.VolumeSpec{Size: resource.MustParse("10Gi"), BootImage: "quay.io/containerdisks/fedora:41", StorageClass: "ceph-rbd"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "data"}, Spec: storagev1.VolumeSpec{Size: resource.MustParse("5Gi")}},
	}
	atts := CompileVolumeAttachments(vm, volumes, Placement{ClusterName: "c1", WorkloadID: "vm1"})
	if len(atts) != 2 {
		t.Fatalf("want 2 attachments, got %d", len(atts))
	}
	byName := map[string]compiledv1.CompiledVolumeAttachment{}
	for _, a := range atts {
		byName[a.Name] = a
	}
	// Namespace-qualified: "<vm.Namespace>-<vm.Name>-<ref.Name>", so two same-named VMs in
	// different tenant namespaces cannot collide once they share one pool namespace.
	boot := byName["ns-vm1-boot"]
	if boot.Namespace != "pool-c1" || boot.Labels["workload"] != "vm1" || boot.Spec.ClusterName != "c1" {
		t.Fatalf("boot meta: %+v", boot)
	}
	if !boot.Spec.Boot || boot.Spec.BootImage != "quay.io/containerdisks/fedora:41" || boot.Spec.StorageClass != "ceph-rbd" || boot.Spec.Size.Cmp(resource.MustParse("10Gi")) != 0 {
		t.Fatalf("boot spec: %+v", boot.Spec)
	}
	data := byName["ns-vm1-data"]
	if data.Spec.Boot || data.Spec.BootImage != "" || data.Spec.Size.Cmp(resource.MustParse("5Gi")) != 0 {
		t.Fatalf("data spec: %+v", data.Spec)
	}
}

// TestCompileVolumeAttachments_StampsTheRecordedIdentity is what turns a rebind into a move: when a
// Volume already has a disk, every attachment compiled for it — including one compiled into a
// DIFFERENT cluster — must carry that disk's identity, so the target adopts it instead of
// provisioning a blank one.
//
// The identity travels in SPEC, not status: the target cluster has to be handed it, never have to
// go and read an observation from a cluster it cannot see.
func TestCompileVolumeAttachments_StampsTheRecordedIdentity(t *testing.T) {
	vm := &computev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1"},
		Spec:       computev1.VirtualMachineSpec{ClusterName: "c2", VolumeRefs: []computev1.LocalObjectReference{{Name: "boot"}, {Name: "fresh"}}},
	}
	volumes := []storagev1.Volume{
		// Already provisioned somewhere: has an identity, and it must follow the VM to c2.
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "boot"},
			Spec:       storagev1.VolumeSpec{Size: resource.MustParse("10Gi"), StorageClass: "ceph-rbd"},
			Status: storagev1.VolumeStatus{DiskIdentity: &storagev1.DiskIdentity{
				CSI:      &corev1.CSIPersistentVolumeSource{Driver: "rbd.csi.ceph.com", VolumeHandle: "handle-1", VolumeAttributes: map[string]string{"imageName": "csi-vol-1"}},
				Capacity: resource.MustParse("10Gi"),
			}},
		},
		// Never provisioned: nothing to adopt, so it must compile exactly as before.
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "fresh"}, Spec: storagev1.VolumeSpec{Size: resource.MustParse("5Gi")}},
	}
	atts := CompileVolumeAttachments(vm, volumes, Placement{ClusterName: "c2", WorkloadID: "vm1"})
	byName := map[string]compiledv1.CompiledVolumeAttachment{}
	for _, a := range atts {
		byName[a.Name] = a
	}

	boot := byName["ns-vm1-boot"]
	if boot.Spec.DiskIdentity == nil || boot.Spec.DiskIdentity.CSI == nil {
		t.Fatalf("an attachment for a Volume with a disk must carry its identity: %+v", boot.Spec)
	}
	if got := boot.Spec.DiskIdentity.CSI.VolumeHandle; got != "handle-1" {
		t.Errorf("volumeHandle = %q, want handle-1", got)
	}
	if got := boot.Spec.DiskIdentity.CSI.VolumeAttributes["imageName"]; got != "csi-vol-1" {
		t.Errorf("imageName = %q, want csi-vol-1", got)
	}
	if boot.Spec.DiskIdentity.Capacity.Cmp(resource.MustParse("10Gi")) != 0 {
		t.Errorf("capacity = %v, want the recorded 10Gi", boot.Spec.DiskIdentity.Capacity)
	}
	// VolumeRef is what lets the mirror find its way back to the Volume without taking the
	// attachment's name apart.
	if boot.Spec.VolumeRef != "boot" {
		t.Errorf("volumeRef = %q, want boot", boot.Spec.VolumeRef)
	}

	if fresh := byName["ns-vm1-fresh"]; fresh.Spec.DiskIdentity != nil {
		t.Errorf("a Volume with no disk yet must not claim one: %+v", fresh.Spec.DiskIdentity)
	} else if fresh.Spec.VolumeRef != "fresh" {
		t.Errorf("volumeRef = %q, want fresh", fresh.Spec.VolumeRef)
	}
}
