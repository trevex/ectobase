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

// TestUnprotectedRebinds is the guard for the one window in which a cluster rebind still loses
// data, and the plan for this work named it as a risk left unaddressed.
//
// A disk becomes safe to move only once the pool that provisioned it has observed the bound claim:
// that is when its PersistentVolume is flipped to Retain and its identity recorded. Before that the
// PV still carries the StorageClass's Delete, so pruning the old attachment destroys the image while
// the target provisions a blank one. The compiler can see this coming — it has the existing twins,
// the desired ones, and the Volumes — so it should say so rather than proceed quietly.
//
// What must NOT be flagged is a first provisioning: a Volume with no identity and no prior
// attachment is simply a new disk, which is the common case.
func TestUnprotectedRebinds(t *testing.T) {
	withIdentity := storagev1.Volume{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "boot"},
		Status: storagev1.VolumeStatus{DiskIdentity: &storagev1.DiskIdentity{
			CSI: &corev1.CSIPersistentVolumeSource{VolumeHandle: "h"},
		}},
	}
	noIdentity := storagev1.Volume{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "boot"}}

	att := func(ns, name, volumeRef string) compiledv1.CompiledVolumeAttachment {
		return compiledv1.CompiledVolumeAttachment{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       compiledv1.CompiledVolumeAttachmentSpec{VolumeRef: volumeRef},
		}
	}

	cases := []struct {
		name    string
		have    []compiledv1.CompiledVolumeAttachment
		desired []compiledv1.CompiledVolumeAttachment
		volumes []storagev1.Volume
		want    int
	}{{
		name:    "rebind of an unprotected disk is flagged",
		have:    []compiledv1.CompiledVolumeAttachment{att("pool-c1", "ns-vm1-boot", "boot")},
		desired: []compiledv1.CompiledVolumeAttachment{att("pool-c2", "ns-vm1-boot", "boot")},
		volumes: []storagev1.Volume{noIdentity},
		want:    1,
	}, {
		name:    "rebind of a protected disk is not flagged — that is the whole point of the identity",
		have:    []compiledv1.CompiledVolumeAttachment{att("pool-c1", "ns-vm1-boot", "boot")},
		desired: []compiledv1.CompiledVolumeAttachment{att("pool-c2", "ns-vm1-boot", "boot")},
		volumes: []storagev1.Volume{withIdentity},
		want:    0,
	}, {
		name:    "staying put is not a rebind, however unprotected the disk is",
		have:    []compiledv1.CompiledVolumeAttachment{att("pool-c1", "ns-vm1-boot", "boot")},
		desired: []compiledv1.CompiledVolumeAttachment{att("pool-c1", "ns-vm1-boot", "boot")},
		volumes: []storagev1.Volume{noIdentity},
		want:    0,
	}, {
		name:    "first provisioning is not a rebind: no prior attachment to lose",
		have:    nil,
		desired: []compiledv1.CompiledVolumeAttachment{att("pool-c1", "ns-vm1-boot", "boot")},
		volumes: []storagev1.Volume{noIdentity},
		want:    0,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := unprotectedRebinds(c.desired, c.have, c.volumes)
			if len(got) != c.want {
				t.Fatalf("got %d unprotected rebinds %+v, want %d", len(got), got, c.want)
			}
			if c.want == 1 {
				if got[0].Volume != "boot" || got[0].From != "pool-c1" || got[0].To != "pool-c2" {
					t.Fatalf("flagged the wrong move: %+v", got[0])
				}
			}
		})
	}
}
