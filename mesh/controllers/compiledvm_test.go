package controllers

import (
	"slices"
	"testing"

	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCompileVM(t *testing.T) {
	vm := &computev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1"},
		Spec: computev1.VirtualMachineSpec{
			ClusterName:   "c1",
			Image:         "quay.io/containerdisks/fedora:41",
			InterfaceRefs: []computev1.LocalObjectReference{{Name: "nic-a"}},
			Resources:     corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")}},
		},
	}
	nics := []netv1.NetworkInterface{{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "nic-a"}, Spec: netv1.NetworkInterfaceSpec{MAC: "02:00:00:00:00:01"}}}

	cvm := CompileVM(vm, nics, nil, Placement{ClusterName: "c1", WorkloadID: "vm1"}, "flowplane-overlay")

	if cvm.Name != "ns-vm1" || cvm.Namespace != "pool-c1" {
		t.Fatalf("name/ns: %s/%s", cvm.Namespace, cvm.Name)
	}
	if cvm.Spec.ClusterName != "c1" {
		t.Fatalf("clusterName: %q", cvm.Spec.ClusterName)
	}
	if cvm.Labels["workload"] != "vm1" {
		t.Fatalf("workload label: %v", cvm.Labels)
	}
	if cvm.Spec.Image != "quay.io/containerdisks/fedora:41" {
		t.Fatalf("image: %q", cvm.Spec.Image)
	}
	if cvm.Spec.RunStrategy != "RerunOnFailure" {
		t.Fatalf("runStrategy default: %q", cvm.Spec.RunStrategy)
	}
	if len(cvm.Spec.Interfaces) != 1 || cvm.Spec.Interfaces[0].MAC != "02:00:00:00:00:01" || cvm.Spec.Interfaces[0].NetworkName != "flowplane-overlay" {
		t.Fatalf("interfaces: %+v", cvm.Spec.Interfaces)
	}
	if cvm.Spec.Resources.Requests.Memory().Cmp(resource.MustParse("1Gi")) != 0 {
		t.Fatalf("mem: %v", cvm.Spec.Resources.Requests.Memory())
	}

	// An explicit RunStrategy passes through unchanged (not overwritten by the default).
	vm.Spec.RunStrategy = "Always"
	if got := CompileVM(vm, nics, nil, Placement{ClusterName: "c1", WorkloadID: "vm1"}, "flowplane-overlay"); got.Spec.RunStrategy != "Always" {
		t.Fatalf("explicit runStrategy overwritten: %q", got.Spec.RunStrategy)
	}

	// No CloudInit intent -> none lowered (so the materializer adds no cloud-init disk).
	if cvm.Spec.CloudInit != nil {
		t.Fatalf("unset CloudInit should stay nil, got %+v", cvm.Spec.CloudInit)
	}
}

func TestCompileVM_CloudInit(t *testing.T) {
	userData := "#cloud-config\nusers:\n  - name: fedora\n    ssh_authorized_keys: [ssh-ed25519 AAAA...]\n"
	vm := &computev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1"},
		Spec: computev1.VirtualMachineSpec{
			Image:     "quay.io/containerdisks/fedora:41",
			CloudInit: &computev1.CloudInit{UserData: userData},
		},
	}
	cvm := CompileVM(vm, nil, nil, Placement{ClusterName: "c1", WorkloadID: "vm1"}, "flowplane-overlay")
	if cvm.Spec.CloudInit == nil || cvm.Spec.CloudInit.UserData != userData {
		t.Fatalf("cloud-init userData not lowered onto the CompiledVM: %+v", cvm.Spec.CloudInit)
	}
}

// TestCompileVM_Volumes: the CompiledVM names the attachments it boots from, so a pool can hold the
// VM back until all of them have arrived. The names must be exactly the attachments' own — the
// materializer matches on them — and a Volume that does not exist yet is left out, as it is from
// the attachments, or the VM would wait for a disk nothing is going to compile.
func TestCompileVM_Volumes(t *testing.T) {
	vm := &computev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1"},
		Spec: computev1.VirtualMachineSpec{
			ClusterName: "c1",
			VolumeRefs:  []computev1.LocalObjectReference{{Name: "boot"}, {Name: "data"}, {Name: "missing"}},
		},
	}
	volumes := []storagev1.Volume{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "data"}, Spec: storagev1.VolumeSpec{Size: resource.MustParse("5Gi")}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "boot"}, Spec: storagev1.VolumeSpec{Size: resource.MustParse("10Gi"), BootImage: "quay.io/containerdisks/fedora:41"}},
	}
	placement := Placement{ClusterName: "c1", WorkloadID: "vm1"}

	cvm := CompileVM(vm, nil, volumes, placement, "flowplane-overlay")
	if want := []string{"ns-vm1-boot", "ns-vm1-data"}; !slices.Equal(cvm.Spec.Volumes, want) {
		t.Fatalf("volumes: got %v, want %v (the VM's volumeRefs order, missing Volumes skipped)", cvm.Spec.Volumes, want)
	}
	var attNames []string
	for _, a := range CompileVolumeAttachments(vm, volumes, placement) {
		attNames = append(attNames, a.Name)
	}
	if !slices.Equal(cvm.Spec.Volumes, attNames) {
		t.Fatalf("CompiledVM names %v, but the attachments compiled for it are %v", cvm.Spec.Volumes, attNames)
	}

	// A containerDisk VM attaches nothing and names nothing.
	vm.Spec.VolumeRefs = nil
	if got := CompileVM(vm, nil, volumes, placement, "flowplane-overlay").Spec.Volumes; got != nil {
		t.Fatalf("a VM without volumeRefs should name no volumes, got %v", got)
	}
}
