// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	kubevirtv1 "kubevirt.io/api/core/v1"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	netinstall "github.com/trevex/ectobase/api/net/install"
	platforminstall "github.com/trevex/ectobase/api/platform/install"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	compiledinstall "github.com/trevex/ectobase/api/compiled/install"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/central/pkg/broker"
	"github.com/trevex/ectobase/central/pkg/clusterpool"
	"github.com/trevex/ectobase/central/pkg/scheduler"
	"github.com/trevex/ectobase/netplane/controllers"
)

// TestCeph_ScheduleCompileSyncMaterializeVolume_E2E extends the Phase-4 chain one
// storage stage further: from a scheduled VirtualMachine that references a Volume
// all the way to a KubeVirt VirtualMachine booting from a CDI DataVolume (RBD PVC)
// on the downstream cluster — across TWO real in-process apiservers.
//
//  1. ClusterPool c1 is created + a fresh broker heartbeat is simulated, then
//     clusterpool.Reconciler derives Ready;
//  2. a Volume boot (10Gi, ceph-rbd, fedora BootImage) + a VirtualMachine vm1
//     (VolumeRefs:[boot]) owning nic-a are created; scheduler.Reconciler binds vm1 to c1;
//  3. the netplane CompiledVMReconciler lowers vm1 -> a central CompiledVM default-vm1
//     AND the CompiledVolumeAttachmentReconciler emits a central CompiledVolumeAttachment
//     vm1-boot (clusterName c1, Boot, BootImage, workload=vm1);
//  4. the c1 broker's SyncCompiledVMs + SyncCompiledVolumeAttachments materialize both
//     downstream;
//  5. the downstream VolumeMaterializerReconciler turns vm1-boot into a
//     cdiv1.DataVolume (registry source docker://fedora, storageClass ceph-rbd, 10Gi);
//  6. the downstream VMMaterializerReconciler turns default-vm1 into a kubevirt.io/v1
//     VirtualMachine that boots from the vm1-boot DataVolume (NO containerDisk).
//
// The downstream envtest loads the net CRDs (config/crd/bases) + the vendored
// KubeVirt VirtualMachine + CDI DataVolume CRD fixtures (netplane/test/crds), and its
// client scheme registers netv1 + kubevirtv1 + cdiv1 so all three object families
// (de)serialize.
func TestCeph_ScheduleCompileSyncMaterializeVolume_E2E(t *testing.T) {
	t.Setenv("GOWORK", "off")

	const ns = "default"

	scheme := runtime.NewScheme()
	platforminstall.Install(scheme)
	netinstall.Install(scheme)
	compiledinstall.Install(scheme)
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiregistration scheme: %v", err)
	}
	if err := kubevirtv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register kubevirt scheme: %v", err)
	}
	if err := cdiv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register cdi scheme: %v", err)
	}

	// --- CENTRAL: kit aggregated apiserver. ---
	centralEnv, err := kitenvtest.NewEnvironment(
		"github.com/trevex/ectobase/central/cmd/apiserver",
		nil,
		[]string{filepath.Join(".", "fixtures")},
	)
	if err != nil {
		t.Fatalf("central NewEnvironment: %v", err)
	}
	if _, err := centralEnv.Start(scheme, os.Stderr); err != nil {
		t.Fatalf("central env.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := centralEnv.Stop(); err != nil {
			t.Errorf("central env.Stop: %v", err)
		}
	})
	if err := centralEnv.WaitUntilReadyWithTimeout(apiServiceTimeout); err != nil {
		t.Fatalf("central WaitUntilReadyWithTimeout: %v", err)
	}
	centralClient, err := client.New(centralEnv.GetRESTConfig(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("central client.New: %v", err)
	}

	// --- DOWNSTREAM: plain controller-runtime apiserver with the net CRDs +
	//     the KubeVirt VirtualMachine + CDI DataVolume CRD fixtures. ---
	downEnv := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
			filepath.Join("..", "..", "netplane", "test", "crds"),
		},
		ErrorIfCRDPathMissing: true,
	}
	downCfg, err := downEnv.Start()
	if err != nil {
		t.Fatalf("downstream envtest.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := downEnv.Stop(); err != nil {
			t.Errorf("downstream env.Stop: %v", err)
		}
	})
	downstreamClient, err := client.New(downCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("downstream client.New: %v", err)
	}

	ctx := kitenvtest.Context()

	// ================================================================
	// (1) HEARTBEAT + POOL PHASE: create pool c1, simulate a fresh beat, derive Ready.
	// ================================================================
	if err := centralClient.Create(ctx, &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c1"}}); err != nil {
		t.Fatalf("central create pool c1: %v", err)
	}
	pool := &platformv1.ClusterPool{}
	if err := centralClient.Get(ctx, client.ObjectKey{Name: "c1"}, pool); err != nil {
		t.Fatalf("get pool c1: %v", err)
	}
	now := metav1.NewMicroTime(time.Now())
	pool.Status.Lease = &platformv1.ClusterPoolLease{HolderIdentity: "b", RenewTime: &now}
	pool.Status.Allocatable = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("8"),
		corev1.ResourceMemory: resource.MustParse("16Gi"),
	}
	if err := centralClient.Status().Update(ctx, pool); err != nil {
		t.Fatalf("heartbeat status update pool c1: %v", err)
	}

	pr := &clusterpool.Reconciler{Client: centralClient, HealthStale: time.Minute}
	if _, err := pr.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "c1"}}); err != nil {
		t.Fatalf("clusterpool Reconcile: %v", err)
	}
	gotPool := &platformv1.ClusterPool{}
	if err := centralClient.Get(ctx, client.ObjectKey{Name: "c1"}, gotPool); err != nil {
		t.Fatalf("get pool c1 after reconcile: %v", err)
	}
	if gotPool.Status.Phase != clusterpool.PhaseReady {
		t.Fatalf("expected pool c1 Phase=Ready, got %q", gotPool.Status.Phase)
	}
	t.Log("(1) pool phase: PASS (c1 Ready)")

	// ================================================================
	// (2) SCHEDULE: create nic-a (with a VNI via status), a Volume boot, and an
	//     unbound vm1 (VolumeRefs:[boot]) owning nic-a, then bind vm1 to c1.
	// ================================================================
	node1 := "node-1"
	nicA := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nic-a"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:   netv1.LocalObjectReference{Name: "vpc-1"},
			IPs:      []string{"10.0.0.5"},
			MAC:      "02:00:00:00:00:01",
			NodeName: &node1,
		},
	}
	if err := centralClient.Create(ctx, nicA); err != nil {
		t.Fatalf("central create nic-a: %v", err)
	}
	curNic := &netv1.NetworkInterface{}
	if err := centralClient.Get(ctx, client.ObjectKeyFromObject(nicA), curNic); err != nil {
		t.Fatalf("central get nic-a for status: %v", err)
	}
	curNic.Status.VNI = 1000
	if err := centralClient.Status().Update(ctx, curNic); err != nil {
		t.Fatalf("central status update nic-a: %v", err)
	}

	boot := &netv1.Volume{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "boot"},
		Spec: netv1.VolumeSpec{
			Size:         resource.MustParse("10Gi"),
			StorageClass: "ceph-rbd",
			BootImage:    "quay.io/containerdisks/fedora:41",
		},
	}
	if err := centralClient.Create(ctx, boot); err != nil {
		t.Fatalf("central create volume boot: %v", err)
	}

	vm1 := &netv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm1"},
		Spec: netv1.VirtualMachineSpec{
			Image:         "quay.io/containerdisks/fedora:41",
			InterfaceRefs: []netv1.LocalObjectReference{{Name: "nic-a"}},
			VolumeRefs:    []netv1.LocalObjectReference{{Name: "boot"}},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")},
			},
		},
	}
	if err := centralClient.Create(ctx, vm1); err != nil {
		t.Fatalf("central create vm1: %v", err)
	}

	sr := &scheduler.Reconciler{Client: centralClient}
	if _, err := sr.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: "vm1"}}); err != nil {
		t.Fatalf("scheduler Reconcile: %v", err)
	}
	boundVM := &netv1.VirtualMachine{}
	if err := centralClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm1"}, boundVM); err != nil {
		t.Fatalf("get vm1 after schedule: %v", err)
	}
	if boundVM.Spec.ClusterName != "c1" {
		t.Fatalf("expected vm1 scheduled to c1, got %q", boundVM.Spec.ClusterName)
	}
	t.Log("(2) schedule: PASS (vm1 -> c1, refs volume boot)")

	// ================================================================
	// (3) COMPILE: CompiledVMReconciler lowers vm1 -> default-vm1 AND
	//     CompiledVolumeAttachmentReconciler emits vm1-boot (bound c1, Boot, fedora).
	// ================================================================
	cr := &controllers.CompiledVMReconciler{Client: centralClient, NetworkName: "flowplane-overlay"}
	if _, err := cr.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: "vm1"}}); err != nil {
		t.Fatalf("compile Reconcile vm1 (CompiledVM): %v", err)
	}
	cva := &controllers.CompiledVolumeAttachmentReconciler{Client: centralClient}
	if _, err := cva.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: "vm1"}}); err != nil {
		t.Fatalf("compile Reconcile vm1 (CompiledVolumeAttachment): %v", err)
	}

	compiled := &compiledv1.CompiledVM{}
	if err := centralClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "default-vm1"}, compiled); err != nil {
		t.Fatalf("central get default-vm1: %v", err)
	}
	if compiled.Spec.ClusterName != "c1" {
		t.Fatalf("expected default-vm1 clusterName=c1, got %q", compiled.Spec.ClusterName)
	}

	att := &compiledv1.CompiledVolumeAttachment{}
	if err := centralClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm1-boot"}, att); err != nil {
		t.Fatalf("central get CompiledVolumeAttachment vm1-boot: %v", err)
	}
	if att.Spec.ClusterName != "c1" {
		t.Fatalf("expected vm1-boot clusterName=c1, got %q", att.Spec.ClusterName)
	}
	if !att.Spec.Boot {
		t.Fatalf("expected vm1-boot Boot=true (BootImage set)")
	}
	if att.Spec.BootImage != "quay.io/containerdisks/fedora:41" {
		t.Fatalf("expected vm1-boot BootImage=fedora, got %q", att.Spec.BootImage)
	}
	if att.Labels["workload"] != "vm1" {
		t.Fatalf("expected vm1-boot workload=vm1 label, got %q", att.Labels["workload"])
	}
	wantSize := resource.MustParse("10Gi")
	if att.Spec.Size.Cmp(wantSize) != 0 {
		t.Fatalf("expected vm1-boot Size=10Gi, got %s", att.Spec.Size.String())
	}
	t.Log("(3) compile: PASS (default-vm1 + vm1-boot bound c1, Boot fedora, workload label)")

	// ================================================================
	// (4) SYNC: the c1 broker materializes default-vm1 + vm1-boot DOWNSTREAM.
	// ================================================================
	b := &broker.Broker{Central: centralClient, Downstream: downstreamClient, ClusterName: "c1"}
	if err := b.SyncCompiledVMs(ctx); err != nil {
		t.Fatalf("broker SyncCompiledVMs: %v", err)
	}
	if err := b.SyncCompiledVolumeAttachments(ctx); err != nil {
		t.Fatalf("broker SyncCompiledVolumeAttachments: %v", err)
	}
	downVMs := &compiledv1.CompiledVMList{}
	if err := downstreamClient.List(ctx, downVMs); err != nil {
		t.Fatalf("downstream List CompiledVM: %v", err)
	}
	if len(downVMs.Items) != 1 || downVMs.Items[0].Name != "default-vm1" {
		t.Fatalf("sync: expected downstream CompiledVM=[default-vm1], got %d items", len(downVMs.Items))
	}
	downAtts := &compiledv1.CompiledVolumeAttachmentList{}
	if err := downstreamClient.List(ctx, downAtts); err != nil {
		t.Fatalf("downstream List CompiledVolumeAttachment: %v", err)
	}
	if len(downAtts.Items) != 1 || downAtts.Items[0].Name != "vm1-boot" {
		t.Fatalf("sync: expected downstream CompiledVolumeAttachment=[vm1-boot], got %d items", len(downAtts.Items))
	}
	if downAtts.Items[0].Spec.ClusterName != "c1" || downAtts.Items[0].Spec.BootImage != "quay.io/containerdisks/fedora:41" {
		t.Fatalf("sync: expected downstream vm1-boot clusterName=c1 bootImage=fedora, got clusterName=%q bootImage=%q",
			downAtts.Items[0].Spec.ClusterName, downAtts.Items[0].Spec.BootImage)
	}
	t.Log("(4) sync: PASS (downstream=[default-vm1] + [vm1-boot] bound c1)")

	// ================================================================
	// (5) MATERIALIZE VOLUME: VolumeMaterializerReconciler turns vm1-boot into a
	//     cdiv1.DataVolume (registry source docker://fedora, ceph-rbd, 10Gi).
	// ================================================================
	volr := &controllers.VolumeMaterializerReconciler{Client: downstreamClient}
	if _, err := volr.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: "vm1-boot"}}); err != nil {
		t.Fatalf("materialize Reconcile vm1-boot (DataVolume): %v", err)
	}
	dv := &cdiv1.DataVolume{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm1-boot"}, dv); err != nil {
		t.Fatalf("downstream get DataVolume vm1-boot: %v", err)
	}
	if dv.Spec.Source == nil || dv.Spec.Source.Registry == nil || dv.Spec.Source.Registry.URL == nil {
		t.Fatalf("materialize: expected DataVolume registry source, got %+v", dv.Spec.Source)
	}
	if *dv.Spec.Source.Registry.URL != "docker://quay.io/containerdisks/fedora:41" {
		t.Fatalf("materialize: expected registry URL=docker://quay.io/containerdisks/fedora:41, got %q", *dv.Spec.Source.Registry.URL)
	}
	if dv.Spec.Storage == nil || dv.Spec.Storage.StorageClassName == nil || *dv.Spec.Storage.StorageClassName != "ceph-rbd" {
		t.Fatalf("materialize: expected DataVolume storageClass=ceph-rbd, got %+v", dv.Spec.Storage)
	}
	gotStorage := dv.Spec.Storage.Resources.Requests[corev1.ResourceStorage]
	if gotStorage.Cmp(wantSize) != 0 {
		t.Fatalf("materialize: expected DataVolume storage=10Gi, got %s", gotStorage.String())
	}
	t.Log("(5) materialize volume: PASS (DataVolume vm1-boot: registry docker://fedora, ceph-rbd, 10Gi)")

	// ================================================================
	// (6) MATERIALIZE VM: VMMaterializerReconciler turns default-vm1 into a
	//     kubevirt.io/v1.VirtualMachine booting from the vm1-boot DataVolume (NO
	//     containerDisk).
	// ================================================================
	vmr := &controllers.VMMaterializerReconciler{Client: downstreamClient}
	if _, err := vmr.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: "default-vm1"}}); err != nil {
		t.Fatalf("materialize Reconcile default-vm1 (VM): %v", err)
	}
	kvm := &kubevirtv1.VirtualMachine{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "default-vm1"}, kvm); err != nil {
		t.Fatalf("downstream get kubevirt VM default-vm1: %v", err)
	}
	if kvm.Spec.Template == nil {
		t.Fatalf("materialize: expected a VMI template, got nil")
	}
	vols := kvm.Spec.Template.Spec.Volumes
	if len(vols) != 1 {
		t.Fatalf("materialize: expected exactly one volume, got %d: %+v", len(vols), vols)
	}
	if vols[0].ContainerDisk != nil {
		t.Fatalf("materialize: expected NO containerDisk (booting from DataVolume), got %+v", vols[0].ContainerDisk)
	}
	if vols[0].DataVolume == nil || vols[0].DataVolume.Name != "vm1-boot" {
		t.Fatalf("materialize: expected dataVolume volume named vm1-boot, got %+v", vols[0].DataVolume)
	}
	if vols[0].Name != "vm1-boot" {
		t.Fatalf("materialize: expected volume name=vm1-boot, got %q", vols[0].Name)
	}
	t.Log("(6) materialize vm: PASS (kubevirt VM default-vm1 boots from DataVolume vm1-boot, no containerDisk)")
}
