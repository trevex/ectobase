package controllers

import (
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestCompileVM(t *testing.T) {
	vm := &netv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1"},
		Spec: netv1.VirtualMachineSpec{
			ClusterName:   "c1",
			Image:         "quay.io/containerdisks/fedora:41",
			InterfaceRefs: []netv1.LocalObjectReference{{Name: "nic-a"}},
			Resources:     corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")}},
		},
	}
	nics := []netv1.NetworkInterface{{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "nic-a"}, Spec: netv1.NetworkInterfaceSpec{MAC: "02:00:00:00:00:01"}}}

	cvm := CompileVM(vm, nics, Placement{ClusterName: "c1", WorkloadID: "vm1"}, "flowplane-overlay")

	if cvm.Name != "ns-vm1" || cvm.Namespace != "ns" {
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
	if got := CompileVM(vm, nics, Placement{ClusterName: "c1", WorkloadID: "vm1"}, "flowplane-overlay"); got.Spec.RunStrategy != "Always" {
		t.Fatalf("explicit runStrategy overwritten: %q", got.Spec.RunStrategy)
	}
}
