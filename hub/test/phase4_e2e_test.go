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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netinstall "github.com/trevex/ectobase/api/net/install"
	computeinstall "github.com/trevex/ectobase/api/compute/install"
	platforminstall "github.com/trevex/ectobase/api/platform/install"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	compiledinstall "github.com/trevex/ectobase/api/compiled/install"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/hub/pkg/broker"
	"github.com/trevex/ectobase/hub/pkg/clusterpool"
	"github.com/trevex/ectobase/hub/pkg/scheduler"
	"github.com/trevex/ectobase/netplane/controllers"
)

// TestPhase4_ScheduleCompileSyncMaterialize_E2E extends the Phase-3 chain one
// stage further — from a scheduled VirtualMachine all the way to a KubeVirt
// VirtualMachine on the downstream cluster — across TWO real in-process
// apiservers:
//
//  1. ClusterPool c1 is created + a fresh broker heartbeat is simulated (lease
//     RenewTime=now, Allocatable), then clusterpool.Reconciler derives Ready;
//  2. scheduler.Reconciler binds the unbound vm1 (owning nic-a) to c1;
//  3. the netplane CompiledVMReconciler lowers vm1 -> a hub CompiledVM
//     default-vm1 (image, resolved MAC, flowplane-overlay network) bound to c1;
//  4. the c1 broker's SyncCompiledVMs materializes default-vm1 downstream;
//  5. the downstream VMMaterializerReconciler turns default-vm1 into a
//     kubevirt.io/v1.VirtualMachine (RerunOnFailure default, containerDisk boot,
//     pinned-MAC interface on the flowplane-overlay multus network).
//
// The downstream envtest loads THREE CRD dirs — the net+compiled CRDs under
// charts/ectobase-pool/crd-bases, the compute/storage/platform CRDs under
// test/crds, and the vendored KubeVirt VirtualMachine CRD fixture under
// netplane/test/crds — and its client scheme registers BOTH netv1 and kubevirtv1
// so both object families (de)serialize.
func TestPhase4_ScheduleCompileSyncMaterialize_E2E(t *testing.T) {
	t.Setenv("GOWORK", "off")

	const ns = "default"

	scheme := runtime.NewScheme()
	platforminstall.Install(scheme)
	netinstall.Install(scheme)
	compiledinstall.Install(scheme)
	computeinstall.Install(scheme)
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiregistration scheme: %v", err)
	}
	if err := kubevirtv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register kubevirt scheme: %v", err)
	}

	// --- HUB: kit aggregated apiserver. ---
	hubEnv, err := kitenvtest.NewEnvironment(
		"github.com/trevex/ectobase/hub/cmd/apiserver",
		nil,
		[]string{filepath.Join(".", "fixtures")},
	)
	if err != nil {
		t.Fatalf("hub NewEnvironment: %v", err)
	}
	if _, err := hubEnv.Start(scheme, os.Stderr); err != nil {
		t.Fatalf("hub env.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := hubEnv.Stop(); err != nil {
			t.Errorf("hub env.Stop: %v", err)
		}
	})
	if err := hubEnv.WaitUntilReadyWithTimeout(apiServiceTimeout); err != nil {
		t.Fatalf("hub WaitUntilReadyWithTimeout: %v", err)
	}
	hubClient, err := client.New(hubEnv.GetRESTConfig(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("hub client.New: %v", err)
	}

	// --- DOWNSTREAM: plain controller-runtime apiserver with the net+compiled CRDs,
	//     compute/storage/platform CRDs, AND the KubeVirt VirtualMachine CRD fixture. ---
	downEnv := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "charts", "ectobase-pool", "crd-bases"),
			filepath.Join("..", "..", "test", "crds"),
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
	if err := hubClient.Create(ctx, &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c1"}}); err != nil {
		t.Fatalf("hub create pool c1: %v", err)
	}
	pool := &platformv1.ClusterPool{}
	if err := hubClient.Get(ctx, client.ObjectKey{Name: "c1"}, pool); err != nil {
		t.Fatalf("get pool c1: %v", err)
	}
	now := metav1.NewMicroTime(time.Now())
	pool.Status.Lease = &platformv1.ClusterPoolLease{HolderIdentity: "b", RenewTime: &now}
	pool.Status.Allocatable = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("8"),
		corev1.ResourceMemory: resource.MustParse("16Gi"),
	}
	if err := hubClient.Status().Update(ctx, pool); err != nil {
		t.Fatalf("heartbeat status update pool c1: %v", err)
	}

	pr := &clusterpool.Reconciler{Client: hubClient, HealthStale: time.Minute}
	if _, err := pr.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "c1"}}); err != nil {
		t.Fatalf("clusterpool Reconcile: %v", err)
	}
	gotPool := &platformv1.ClusterPool{}
	if err := hubClient.Get(ctx, client.ObjectKey{Name: "c1"}, gotPool); err != nil {
		t.Fatalf("get pool c1 after reconcile: %v", err)
	}
	if gotPool.Status.Phase != clusterpool.PhaseReady {
		t.Fatalf("expected pool c1 Phase=Ready, got %q", gotPool.Status.Phase)
	}
	t.Log("(1) pool phase: PASS (c1 Ready)")

	// ================================================================
	// (2) SCHEDULE: create nic-a (with a VNI via status) + unbound vm1 (with boot
	//     intent: fedora image + memory request) owning it, then bind vm1 to c1.
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
	if err := hubClient.Create(ctx, nicA); err != nil {
		t.Fatalf("hub create nic-a: %v", err)
	}
	curNic := &netv1.NetworkInterface{}
	if err := hubClient.Get(ctx, client.ObjectKeyFromObject(nicA), curNic); err != nil {
		t.Fatalf("hub get nic-a for status: %v", err)
	}
	curNic.Status.VNI = 1000
	if err := hubClient.Status().Update(ctx, curNic); err != nil {
		t.Fatalf("hub status update nic-a: %v", err)
	}

	vm1 := &computev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm1"},
		Spec: computev1.VirtualMachineSpec{
			Image:         "quay.io/containerdisks/fedora:41",
			InterfaceRefs: []computev1.LocalObjectReference{{Name: "nic-a"}},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")},
			},
		},
	}
	if err := hubClient.Create(ctx, vm1); err != nil {
		t.Fatalf("hub create vm1: %v", err)
	}

	sr := &scheduler.Reconciler{Client: hubClient}
	if _, err := sr.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: "vm1"}}); err != nil {
		t.Fatalf("scheduler Reconcile: %v", err)
	}
	boundVM := &computev1.VirtualMachine{}
	if err := hubClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm1"}, boundVM); err != nil {
		t.Fatalf("get vm1 after schedule: %v", err)
	}
	if boundVM.Spec.ClusterName != "c1" {
		t.Fatalf("expected vm1 scheduled to c1, got %q", boundVM.Spec.ClusterName)
	}
	t.Log("(2) schedule: PASS (vm1 -> c1)")

	// ================================================================
	// (3) COMPILE: the netplane CompiledVMReconciler lowers vm1 -> default-vm1
	//     bound to c1 (image + resolved MAC on the flowplane-overlay network).
	// ================================================================
	cr := &controllers.CompiledVMReconciler{Client: hubClient, NetworkName: "flowplane-overlay"}
	if _, err := cr.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: "vm1"}}); err != nil {
		t.Fatalf("compile Reconcile vm1: %v", err)
	}
	compiled := &compiledv1.CompiledVM{}
	if err := hubClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "default-vm1"}, compiled); err != nil {
		t.Fatalf("hub get default-vm1: %v", err)
	}
	if compiled.Spec.ClusterName != "c1" {
		t.Fatalf("expected default-vm1 clusterName=c1 (from scheduled vm1), got %q", compiled.Spec.ClusterName)
	}
	if compiled.Spec.Image != "quay.io/containerdisks/fedora:41" {
		t.Fatalf("expected default-vm1 image=quay.io/containerdisks/fedora:41, got %q", compiled.Spec.Image)
	}
	if len(compiled.Spec.Interfaces) != 1 {
		t.Fatalf("expected default-vm1 to have 1 interface, got %d", len(compiled.Spec.Interfaces))
	}
	if compiled.Spec.Interfaces[0].MAC != "02:00:00:00:00:01" || compiled.Spec.Interfaces[0].NetworkName != "flowplane-overlay" {
		t.Fatalf("expected default-vm1 iface {MAC:02:00:00:00:00:01 NetworkName:flowplane-overlay}, got %+v", compiled.Spec.Interfaces[0])
	}
	t.Log("(3) compile: PASS (default-vm1 -> c1, fedora, mac+overlay)")

	// ================================================================
	// (4) SYNC: the c1 broker materializes default-vm1 into the DOWNSTREAM cluster.
	// ================================================================
	b := &broker.Broker{Hub: hubClient, Downstream: downstreamClient, ClusterName: "c1"}
	if err := b.SyncCompiledVMs(ctx); err != nil {
		t.Fatalf("broker SyncCompiledVMs: %v", err)
	}
	downList := &compiledv1.CompiledVMList{}
	if err := downstreamClient.List(ctx, downList); err != nil {
		t.Fatalf("downstream List CompiledVM: %v", err)
	}
	if len(downList.Items) != 1 || downList.Items[0].Name != "default-vm1" {
		names := make([]string, len(downList.Items))
		for i := range downList.Items {
			names[i] = downList.Items[i].Name
		}
		t.Fatalf("sync: expected downstream=[default-vm1], got %v", names)
	}
	if downList.Items[0].Spec.ClusterName != "c1" || downList.Items[0].Spec.Image != "quay.io/containerdisks/fedora:41" {
		t.Fatalf("sync: expected downstream clusterName=c1 image=fedora, got clusterName=%q image=%q",
			downList.Items[0].Spec.ClusterName, downList.Items[0].Spec.Image)
	}
	t.Log("(4) sync: PASS (downstream=[default-vm1] bound c1)")

	// ================================================================
	// (5) MATERIALIZE: the downstream VMMaterializerReconciler turns default-vm1
	//     into a kubevirt.io/v1.VirtualMachine (RerunOnFailure default, containerDisk
	//     boot, pinned-MAC interface on the flowplane-overlay multus network).
	// ================================================================
	vmr := &controllers.VMMaterializerReconciler{Client: downstreamClient}
	if _, err := vmr.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: "default-vm1"}}); err != nil {
		t.Fatalf("materialize Reconcile default-vm1: %v", err)
	}
	kvm := &kubevirtv1.VirtualMachine{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "default-vm1"}, kvm); err != nil {
		t.Fatalf("downstream get kubevirt VM default-vm1: %v", err)
	}
	if kvm.Spec.RunStrategy == nil || *kvm.Spec.RunStrategy != kubevirtv1.RunStrategyRerunOnFailure {
		t.Fatalf("materialize: expected RunStrategy=RerunOnFailure, got %v", kvm.Spec.RunStrategy)
	}
	if kvm.Spec.Template == nil {
		t.Fatalf("materialize: expected a VMI template, got nil")
	}
	vols := kvm.Spec.Template.Spec.Volumes
	if len(vols) != 1 || vols[0].ContainerDisk == nil {
		t.Fatalf("materialize: expected one containerDisk volume, got %+v", vols)
	}
	if vols[0].ContainerDisk.Image != "quay.io/containerdisks/fedora:41" {
		t.Fatalf("materialize: expected containerDisk image=fedora, got %q", vols[0].ContainerDisk.Image)
	}
	ifaces := kvm.Spec.Template.Spec.Domain.Devices.Interfaces
	if len(ifaces) != 1 || ifaces[0].MacAddress != "02:00:00:00:00:01" {
		t.Fatalf("materialize: expected one interface MAC=02:00:00:00:00:01, got %+v", ifaces)
	}
	// The flowplane tap binding (not a plain bridge/masquerade) is the whole point of
	// the overlay-as-primary-network design — assert it explicitly.
	if ifaces[0].Binding == nil || ifaces[0].Binding.Name != "flowplane" {
		t.Fatalf("materialize: expected interface Binding.Name=flowplane, got %+v", ifaces[0].Binding)
	}
	nets := kvm.Spec.Template.Spec.Networks
	if len(nets) != 1 || nets[0].Multus == nil || nets[0].Multus.NetworkName != "flowplane-overlay" {
		t.Fatalf("materialize: expected one multus network=flowplane-overlay, got %+v", nets)
	}
	t.Log("(5) materialize: PASS (kubevirt VM default-vm1: RerunOnFailure, fedora containerDisk, pinned MAC on flowplane-overlay)")
}
