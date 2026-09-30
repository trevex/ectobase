// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
	cvm := &compiledv1.CompiledVM{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ns-vm1", Labels: map[string]string{"workload": "vm1"}},
		Spec: compiledv1.CompiledVMSpec{
			Image:       "quay.io/containerdisks/fedora:41",
			RunStrategy: "RerunOnFailure",
			Resources:   corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")}},
			Interfaces:  []compiledv1.CompiledVMInterface{{MAC: "02:00:00:00:00:01", NetworkName: "ectobase-system/flowplane"}},
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
	if len(nets) != 1 || nets[0].Multus == nil || nets[0].Multus.NetworkName != "ectobase-system/flowplane" {
		t.Fatalf("networks: %+v", nets)
	}
	if vm.Spec.Template.Spec.Domain.Resources.Requests.Memory().Cmp(resource.MustParse("1Gi")) != 0 {
		t.Fatalf("mem")
	}
}

func TestBuildVM_CloudInit(t *testing.T) {
	userData := "#cloud-config\nusers: [{name: fedora, ssh_authorized_keys: [ssh-ed25519 AAAA...]}]\n"
	cvm := &compiledv1.CompiledVM{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ns-vm1"},
		Spec: compiledv1.CompiledVMSpec{
			Image:      "quay.io/containerdisks/fedora:41",
			CloudInit:  &compiledv1.CloudInit{UserData: userData},
			Interfaces: []compiledv1.CompiledVMInterface{{MAC: "02:00:00:00:00:01", NetworkName: "ectobase-system/flowplane"}},
		},
	}
	vm := buildVM(cvm, nil)
	vols := vm.Spec.Template.Spec.Volumes
	// containerDisk boot volume + the cloud-init NoCloud volume.
	var ci *kubevirtv1.CloudInitNoCloudSource
	for _, v := range vols {
		if v.Name == cloudInitDiskName {
			ci = v.CloudInitNoCloud
		}
	}
	if ci == nil || ci.UserData != userData {
		t.Fatalf("expected a %q NoCloud volume with the userData, got volumes %+v", cloudInitDiskName, vols)
	}
	// A matching disk must pair the cloud-init volume by name.
	var haveDisk bool
	for _, d := range vm.Spec.Template.Spec.Domain.Devices.Disks {
		if d.Name == cloudInitDiskName {
			haveDisk = true
		}
	}
	if !haveDisk {
		t.Fatalf("cloud-init volume has no paired disk: %+v", vm.Spec.Template.Spec.Domain.Devices.Disks)
	}

	// No cloud-init intent -> no cloud-init disk/volume (guard the nil path).
	cvm.Spec.CloudInit = nil
	for _, v := range buildVM(cvm, nil).Spec.Template.Spec.Volumes {
		if v.Name == cloudInitDiskName {
			t.Fatalf("cloud-init volume present without intent")
		}
	}
}

func TestBuildVM_FromDataVolumes(t *testing.T) {
	cvm := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ns-vm1", Labels: map[string]string{"workload": "vm1"}},
		Spec: compiledv1.CompiledVMSpec{Image: "ignored-when-volumes", RunStrategy: "RerunOnFailure"}}
	atts := []compiledv1.CompiledVolumeAttachment{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1-data"}, Spec: compiledv1.CompiledVolumeAttachmentSpec{Boot: false}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1-boot"}, Spec: compiledv1.CompiledVolumeAttachmentSpec{Boot: true}},
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
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := kubevirtv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})

	env := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "charts", "ectobase-pool", "crd-bases"),
			filepath.Join("..", "..", "test", "crds"),
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

	cvm := &compiledv1.CompiledVM{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-vm1", Labels: map[string]string{"workload": "vm1"}},
		Spec: compiledv1.CompiledVMSpec{
			ClusterName: "cluster-a",
			Image:       "quay.io/containerdisks/fedora:41",
			RunStrategy: "RerunOnFailure",
			Resources:   corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")}},
			Interfaces:  []compiledv1.CompiledVMInterface{{MAC: "02:00:00:00:00:01", NetworkName: "ectobase-system/flowplane"}},
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
	if len(nets) != 1 || nets[0].Multus == nil || nets[0].Multus.NetworkName != "ectobase-system/flowplane" {
		t.Fatalf("networks: %+v", nets)
	}

	// Idempotent: a second reconcile must not error and must not duplicate.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "default-vm1"}}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
}

func TestReadyToMaterialize(t *testing.T) {
	att := func(name string, boot bool) compiledv1.CompiledVolumeAttachment {
		return compiledv1.CompiledVolumeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name}, Spec: compiledv1.CompiledVolumeAttachmentSpec{Boot: boot}}
	}
	type atts = []compiledv1.CompiledVolumeAttachment
	for _, tc := range []struct {
		name  string
		image string
		vols  []string
		atts  atts
		ready bool
	}{
		{name: "every named disk present", vols: []string{"ns-vm1-boot", "ns-vm1-data"}, atts: atts{att("ns-vm1-data", false), att("ns-vm1-boot", true)}, ready: true},
		{name: "one of two disks present", vols: []string{"ns-vm1-boot", "ns-vm1-data"}, atts: atts{att("ns-vm1-boot", true)}},
		{name: "no disk present yet", vols: []string{"ns-vm1-boot"}},
		// The image is no substitute for a named disk: booting from it would be the empty-template
		// failure all over again for a disk-booted VM, and the wrong disk for any other.
		{name: "named disk missing, image set", image: "quay.io/containerdisks/fedora:41", vols: []string{"ns-vm1-boot"}},
		{name: "an unnamed extra attachment is not a named one", vols: []string{"ns-vm1-boot"}, atts: atts{att("ns-vm1-other", true)}},
		// The boot Volume compiled late, so only the data disk is named: every named disk is here,
		// but with no image nothing of it is bootable, and a VMI started from it runs forever
		// without booting — KubeVirt never recreates it.
		{name: "only a data disk named, no image", vols: []string{"ns-vm1-data"}, atts: atts{att("ns-vm1-data", false)}},
		{name: "a named boot disk present, no image", vols: []string{"ns-vm1-boot"}, atts: atts{att("ns-vm1-boot", true)}, ready: true},
		// A boot disk that is present but not named does not count: it is not going into the VM.
		{name: "boot disk present but not named", vols: []string{"ns-vm1-data"}, atts: atts{att("ns-vm1-data", false), att("ns-vm1-boot", true)}},
		{name: "a data disk alongside an image", image: "quay.io/containerdisks/fedora:41", vols: []string{"ns-vm1-data"}, atts: atts{att("ns-vm1-data", false)}, ready: true},
		{name: "containerDisk VM", image: "quay.io/containerdisks/fedora:41", ready: true},
		{name: "nothing to boot from", ready: false},
		// Compiled before spec.volumes existed (or before its Volumes did): whatever attachments are
		// here is all it knows — but it still needs one of them to boot from.
		{name: "legacy twin with a boot attachment", atts: atts{att("ns-vm1-data", false), att("ns-vm1-boot", true)}, ready: true},
		{name: "legacy twin with only a data attachment", atts: atts{att("ns-vm1-data", false)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cvm := &compiledv1.CompiledVM{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ns-vm1"},
				Spec:       compiledv1.CompiledVMSpec{Image: tc.image, Volumes: tc.vols},
			}
			ok, why := readyToMaterialize(cvm, tc.atts)
			if ok != tc.ready {
				t.Fatalf("ready = %v (%q), want %v", ok, why, tc.ready)
			}
			if !ok && why == "" {
				t.Fatalf("not ready but no reason given")
			}
		})
	}
}

// TestMaterializer_WaitsForItsDisks is the live failure: the broker delivered a disk-booted
// CompiledVM before its attachments, and the materializer created the KubeVirt VM from a template
// with an empty containerDisk — whose VMI then stayed Pending for good. The VM must not be
// created until the disks it names are here, and a VM created before this rule (an upgrade) is
// left exactly as it is.
func TestMaterializer_WaitsForItsDisks(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{compiledv1.AddToScheme, kubevirtv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	cvm := &compiledv1.CompiledVM{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-vm1", Labels: map[string]string{"workload": "vm1"}},
		Spec:       compiledv1.CompiledVMSpec{RunStrategy: "Always", Volumes: []string{"default-vm1-boot", "default-vm1-data"}},
	}
	boot := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-vm1-boot", Labels: map[string]string{"workload": "vm1"}},
		Spec:       compiledv1.CompiledVolumeAttachmentSpec{Boot: true},
	}
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "default-vm1"}}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cvm, boot).Build()
	if _, err := (&VMMaterializerReconciler{Client: c}).Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := c.Get(ctx, req.NamespacedName, &kubevirtv1.VirtualMachine{}); !apierrors.IsNotFound(err) {
		t.Fatalf("a VM was materialized with one of its two disks still missing (get err = %v)", err)
	}

	// Upgrade: the KubeVirt VM already exists. Waiting must not rewrite it either.
	existing := &kubevirtv1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-vm1"}}
	c = fake.NewClientBuilder().WithScheme(scheme).WithObjects(cvm, boot, existing).Build()
	var before kubevirtv1.VirtualMachine
	if err := c.Get(ctx, req.NamespacedName, &before); err != nil {
		t.Fatal(err)
	}
	if _, err := (&VMMaterializerReconciler{Client: c}).Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var after kubevirtv1.VirtualMachine
	if err := c.Get(ctx, req.NamespacedName, &after); err != nil {
		t.Fatal(err)
	}
	if after.ResourceVersion != before.ResourceVersion {
		t.Fatalf("an existing VM was rewritten while its disks were still missing")
	}
}

// TestMaterializer_CreatesVMOnceItsDisksArrive runs the same arrival order against a real
// apiserver (so the CRD must also carry spec.volumes, or it is pruned and nothing waits): nothing
// while the attachment is missing, then a VM booting from it — never from a containerDisk.
func TestMaterializer_CreatesVMOnceItsDisksArrive(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{compiledv1.AddToScheme, kubevirtv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "charts", "ectobase-pool", "crd-bases"), kubeVirtCRDPath()},
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
	req := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "default-vm1"}}
	r := &VMMaterializerReconciler{Client: c}

	cvm := &compiledv1.CompiledVM{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-vm1", Labels: map[string]string{"workload": "vm1"}},
		Spec:       compiledv1.CompiledVMSpec{ClusterName: "cluster-a", RunStrategy: "Always", Volumes: []string{"default-vm1-boot"}},
	}
	if err := c.Create(ctx, cvm); err != nil {
		t.Fatalf("create compiledvm: %v", err)
	}
	// A disk whose volumeRef was removed but which the dispatch has not collected yet: it still
	// carries the workload label, and must neither satisfy the wait nor enter the template.
	stale := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-vm1-old", Labels: map[string]string{"workload": "vm1"}},
		Spec:       compiledv1.CompiledVolumeAttachmentSpec{ClusterName: "cluster-a", Size: resource.MustParse("1Gi")},
	}
	if err := c.Create(ctx, stale); err != nil {
		t.Fatalf("create stale attachment: %v", err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := c.Get(ctx, req.NamespacedName, &kubevirtv1.VirtualMachine{}); !apierrors.IsNotFound(err) {
		t.Fatalf("VM materialized before its disk arrived (get err = %v)", err)
	}

	att := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-vm1-boot", Labels: map[string]string{"workload": "vm1"}},
		Spec:       compiledv1.CompiledVolumeAttachmentSpec{ClusterName: "cluster-a", Size: resource.MustParse("1Gi"), Boot: true},
	}
	if err := c.Create(ctx, att); err != nil {
		t.Fatalf("create attachment: %v", err)
	}
	// The attachment's arrival is what re-enqueues the VM; the mapping must name it.
	if got := r.cvmsForAttachment(ctx, att); len(got) != 1 || got[0].NamespacedName != req.NamespacedName {
		t.Fatalf("attachment maps to %v, want %v", got, req.NamespacedName)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var vm kubevirtv1.VirtualMachine
	if err := c.Get(ctx, req.NamespacedName, &vm); err != nil {
		t.Fatalf("get materialized vm: %v", err)
	}
	vols := vm.Spec.Template.Spec.Volumes
	if len(vols) != 1 || vols[0].DataVolume == nil || vols[0].DataVolume.Name != "default-vm1-boot" {
		t.Fatalf("want the VM to boot from its DataVolume and nothing else, got volumes %+v", vols)
	}
}
