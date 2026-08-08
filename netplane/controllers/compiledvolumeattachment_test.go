package controllers

import (
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCompileVolumeAttachments(t *testing.T) {
	vm := &netv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1"},
		Spec:       netv1.VirtualMachineSpec{ClusterName: "c1", VolumeRefs: []netv1.LocalObjectReference{{Name: "boot"}, {Name: "data"}}},
	}
	volumes := []netv1.Volume{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "boot"}, Spec: netv1.VolumeSpec{Size: resource.MustParse("10Gi"), BootImage: "quay.io/containerdisks/fedora:41", StorageClass: "ceph-rbd"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "data"}, Spec: netv1.VolumeSpec{Size: resource.MustParse("5Gi")}},
	}
	atts := CompileVolumeAttachments(vm, volumes, Placement{ClusterName: "c1", WorkloadID: "vm1"})
	if len(atts) != 2 {
		t.Fatalf("want 2 attachments, got %d", len(atts))
	}
	byName := map[string]compiledv1.CompiledVolumeAttachment{}
	for _, a := range atts {
		byName[a.Name] = a
	}
	boot := byName["vm1-boot"]
	if boot.Namespace != "ns" || boot.Labels["workload"] != "vm1" || boot.Spec.ClusterName != "c1" {
		t.Fatalf("boot meta: %+v", boot)
	}
	if !boot.Spec.Boot || boot.Spec.BootImage != "quay.io/containerdisks/fedora:41" || boot.Spec.StorageClass != "ceph-rbd" || boot.Spec.Size.Cmp(resource.MustParse("10Gi")) != 0 {
		t.Fatalf("boot spec: %+v", boot.Spec)
	}
	data := byName["vm1-data"]
	if data.Spec.Boot || data.Spec.BootImage != "" || data.Spec.Size.Cmp(resource.MustParse("5Gi")) != 0 {
		t.Fatalf("data spec: %+v", data.Spec)
	}
}
