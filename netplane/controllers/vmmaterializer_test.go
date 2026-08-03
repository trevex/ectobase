// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// kubeVirtCRDPath is the vendored minimal structural CRD for kubevirt.io/v1 VirtualMachine.
func kubeVirtCRDPath() string { return filepath.Join("..", "test", "crds") }

// TestKubeVirtCRDLoads is the Phase-4 spike: prove the pinned kubevirt.io/api VirtualMachine
// type registers in a controller-runtime scheme and its CRD loads in envtest, so a trivial VM
// can be created and read back through a real apiserver. Skips outside the nix devShell.
func TestKubeVirtCRDLoads(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}

	scheme := runtime.NewScheme()
	if err := kubevirtv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{kubeVirtCRDPath()},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	defer func() { _ = env.Stop() }()

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx := context.Background()

	rs := kubevirtv1.RunStrategyRerunOnFailure
	vm := &kubevirtv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "spike-vm"},
		Spec: kubevirtv1.VirtualMachineSpec{
			RunStrategy: &rs,
			Template: &kubevirtv1.VirtualMachineInstanceTemplateSpec{
				Spec: kubevirtv1.VirtualMachineInstanceSpec{
					Domain: kubevirtv1.DomainSpec{
						Devices: kubevirtv1.Devices{},
					},
				},
			},
		},
	}
	if err := c.Create(ctx, vm); err != nil {
		t.Fatalf("create vm: %v", err)
	}

	var got kubevirtv1.VirtualMachine
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "spike-vm"}, &got); err != nil {
		t.Fatalf("get vm: %v", err)
	}
	if got.Spec.RunStrategy == nil || *got.Spec.RunStrategy != kubevirtv1.RunStrategyRerunOnFailure {
		t.Fatalf("runStrategy round-trip: %v", got.Spec.RunStrategy)
	}
}

func TestBuildVM(t *testing.T) {
	cvm := &netv1.CompiledVM{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ns-vm1", Labels: map[string]string{"workload": "vm1"}},
		Spec: netv1.CompiledVMSpec{
			Image:       "quay.io/containerdisks/fedora:41",
			RunStrategy: "RerunOnFailure",
			Resources:   corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")}},
			Interfaces:  []netv1.CompiledVMInterface{{MAC: "02:00:00:00:00:01", NetworkName: "flowplane-overlay"}},
		},
	}
	vm := buildVM(cvm, nil)
	if vm.Name != "ns-vm1" || vm.Namespace != "ns" {
		t.Fatalf("meta: %s/%s", vm.Namespace, vm.Name)
	}
	if vm.Spec.RunStrategy == nil || *vm.Spec.RunStrategy != kubevirtv1.RunStrategyRerunOnFailure {
		t.Fatalf("runStrategy: %v", vm.Spec.RunStrategy)
	}
	vols := vm.Spec.Template.Spec.Volumes
	if len(vols) != 1 || vols[0].ContainerDisk == nil || vols[0].ContainerDisk.Image != "quay.io/containerdisks/fedora:41" {
		t.Fatalf("volumes: %+v", vols)
	}
	ifaces := vm.Spec.Template.Spec.Domain.Devices.Interfaces
	if len(ifaces) != 1 || ifaces[0].MacAddress != "02:00:00:00:00:01" {
		t.Fatalf("interfaces: %+v", ifaces)
	}
	nets := vm.Spec.Template.Spec.Networks
	if len(nets) != 1 || nets[0].Multus == nil || nets[0].Multus.NetworkName != "flowplane-overlay" {
		t.Fatalf("networks: %+v", nets)
	}
	if vm.Spec.Template.Spec.Domain.Resources.Requests.Memory().Cmp(resource.MustParse("1Gi")) != 0 {
		t.Fatalf("mem")
	}
}

func TestBuildVM_FromDataVolumes(t *testing.T) {
	cvm := &netv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ns-vm1", Labels: map[string]string{"workload": "vm1"}},
		Spec: netv1.CompiledVMSpec{Image: "ignored-when-volumes", RunStrategy: "RerunOnFailure"}}
	atts := []netv1.CompiledVolumeAttachment{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1-data"}, Spec: netv1.CompiledVolumeAttachmentSpec{Boot: false}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1-boot"}, Spec: netv1.CompiledVolumeAttachmentSpec{Boot: true}},
	}
	vm := buildVM(cvm, atts)
	vols := vm.Spec.Template.Spec.Volumes
	if len(vols) != 2 {
		t.Fatalf("want 2 volumes, got %+v", vols)
	}
	// boot disk first, referencing its DataVolume; no containerDisk.
	if vols[0].DataVolume == nil || vols[0].DataVolume.Name != "vm1-boot" {
		t.Fatalf("boot vol first: %+v", vols)
	}
	if vols[1].DataVolume == nil || vols[1].DataVolume.Name != "vm1-data" {
		t.Fatalf("data vol: %+v", vols)
	}
	for _, v := range vols {
		if v.ContainerDisk != nil {
			t.Fatalf("no containerDisk when volumes present: %+v", vols)
		}
	}
	// disks must pair with the volumes by name.
	disks := vm.Spec.Template.Spec.Domain.Devices.Disks
	if len(disks) != 2 || disks[0].Name != "vm1-boot" || disks[1].Name != "vm1-data" {
		t.Fatalf("disks: %+v", disks)
	}
}

// TestMaterializer_CreatesVM runs the reconciler against a real downstream apiserver with BOTH
// the CompiledVM CRD and the KubeVirt VirtualMachine CRD installed, and asserts the reconciler
// materializes a VirtualMachine with the right image/runStrategy/interface-MAC/multus-network.
func TestMaterializer_CreatesVM(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}

	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := kubevirtv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})

	env := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
			kubeVirtCRDPath(),
		},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	defer func() { _ = env.Stop() }()

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx := context.Background()

	cvm := &netv1.CompiledVM{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-vm1", Labels: map[string]string{"workload": "vm1"}},
		Spec: netv1.CompiledVMSpec{
			ClusterName: "cluster-a",
			Image:       "quay.io/containerdisks/fedora:41",
			RunStrategy: "RerunOnFailure",
			Resources:   corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")}},
			Interfaces:  []netv1.CompiledVMInterface{{MAC: "02:00:00:00:00:01", NetworkName: "flowplane-overlay"}},
		},
	}
	if err := c.Create(ctx, cvm); err != nil {
		t.Fatalf("create compiledvm: %v", err)
	}

	r := &VMMaterializerReconciler{Client: c}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "default-vm1"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var vm kubevirtv1.VirtualMachine
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "default-vm1"}, &vm); err != nil {
		t.Fatalf("get materialized vm: %v", err)
	}
	if vm.Spec.RunStrategy == nil || *vm.Spec.RunStrategy != kubevirtv1.RunStrategyRerunOnFailure {
		t.Fatalf("runStrategy: %v", vm.Spec.RunStrategy)
	}
	vols := vm.Spec.Template.Spec.Volumes
	if len(vols) != 1 || vols[0].ContainerDisk == nil || vols[0].ContainerDisk.Image != "quay.io/containerdisks/fedora:41" {
		t.Fatalf("volumes: %+v", vols)
	}
	ifaces := vm.Spec.Template.Spec.Domain.Devices.Interfaces
	if len(ifaces) != 1 || ifaces[0].MacAddress != "02:00:00:00:00:01" {
		t.Fatalf("interfaces: %+v", ifaces)
	}
	nets := vm.Spec.Template.Spec.Networks
	if len(nets) != 1 || nets[0].Multus == nil || nets[0].Multus.NetworkName != "flowplane-overlay" {
		t.Fatalf("networks: %+v", nets)
	}

	// Idempotent: a second reconcile must not error and must not duplicate.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "default-vm1"}}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
}
