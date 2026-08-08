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

// TestPhase3_HeartbeatScheduleCompileSync_E2E chains the whole Phase-3 control
// loop across TWO real in-process apiservers (extends the Phase-1b chain with
// the heartbeat + pool-phase + scheduler stages that precede compile+sync):
//
//  1. a fresh broker heartbeat is simulated on ClusterPool c1 (lease RenewTime=now,
//     Allocatable cpu:8) — heartbeatOnce is unexported and already unit-tested, so
//     the e2e sets the status directly, exactly what heartbeatOnce would write;
//  2. clusterpool.Reconciler derives Phase=Ready from the fresh lease;
//  3. scheduler.Reconciler binds the unbound vm1 (owning nic-a) to c1;
//  4. the netplane CompiledNICReconciler compiles nic-a -> default-nic-a, inheriting
//     spec.clusterName=c1 from vm1;
//  5. the c1 broker syncs default-nic-a into the DOWNSTREAM cluster.
func TestPhase3_HeartbeatScheduleCompileSync_E2E(t *testing.T) {
	t.Setenv("GOWORK", "off")

	const ns = "default"

	scheme := runtime.NewScheme()
	platforminstall.Install(scheme)
	netinstall.Install(scheme)
	compiledinstall.Install(scheme)
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiregistration scheme: %v", err)
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

	// --- DOWNSTREAM: plain controller-runtime apiserver with the CompiledNIC CRD. ---
	downEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
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
	// (1) HEARTBEAT: create pool c1, simulate a fresh broker beat by writing the
	//     lease + Allocatable directly (what Heartbeater.heartbeatOnce would write;
	//     that method is unexported and covered by its own unit test).
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
	pool.Status.Allocatable = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("8")}
	if err := centralClient.Status().Update(ctx, pool); err != nil {
		t.Fatalf("heartbeat status update pool c1: %v", err)
	}

	// ================================================================
	// (2) POOL PHASE: the clusterpool reconciler derives Ready from the fresh lease.
	// ================================================================
	pr := &clusterpool.Reconciler{Client: centralClient, HealthStale: time.Minute}
	if _, err := pr.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "c1"}}); err != nil {
		t.Fatalf("clusterpool Reconcile: %v", err)
	}
	got := &platformv1.ClusterPool{}
	if err := centralClient.Get(ctx, client.ObjectKey{Name: "c1"}, got); err != nil {
		t.Fatalf("get pool c1 after reconcile: %v", err)
	}
	if got.Status.Phase != clusterpool.PhaseReady {
		t.Fatalf("expected pool c1 Phase=Ready, got %q", got.Status.Phase)
	}
	t.Log("(2) pool phase: PASS (c1 Ready)")

	// ================================================================
	// (3) SCHEDULE: create nic-a (with a VNI via status) + unbound vm1 owning it,
	//     then bind vm1 to c1.
	// ================================================================
	node1 := "node-1"
	nicA := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nic-a"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:   netv1.LocalObjectReference{Name: "vpc-1"},
			IPs:      []string{"10.0.0.5"},
			MAC:      "aa:bb:cc:dd:ee:01",
			NodeName: &node1,
		},
	}
	if err := centralClient.Create(ctx, nicA); err != nil {
		t.Fatalf("central create nic-a: %v", err)
	}
	// Give nic-a an effective VNI via the status subresource so the compiled NIC's
	// required vni is populated without a Ready VPC (mirrors phase1b_e2e).
	curNic := &netv1.NetworkInterface{}
	if err := centralClient.Get(ctx, client.ObjectKeyFromObject(nicA), curNic); err != nil {
		t.Fatalf("central get nic-a for status: %v", err)
	}
	curNic.Status.VNI = 1000
	if err := centralClient.Status().Update(ctx, curNic); err != nil {
		t.Fatalf("central status update nic-a: %v", err)
	}

	vm1 := &netv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm1"},
		Spec: netv1.VirtualMachineSpec{
			InterfaceRefs: []netv1.LocalObjectReference{{Name: "nic-a"}},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
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
	t.Log("(3) schedule: PASS (vm1 -> c1)")

	// ================================================================
	// (4) COMPILE: the netplane reconciler compiles nic-a -> default-nic-a bound to c1.
	// ================================================================
	cr := &controllers.CompiledNICReconciler{Client: centralClient, DefaultClusterName: "default"}
	if _, err := cr.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: "nic-a"}}); err != nil {
		t.Fatalf("compile Reconcile nic-a: %v", err)
	}
	compiled := &compiledv1.CompiledNIC{}
	if err := centralClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "default-nic-a"}, compiled); err != nil {
		t.Fatalf("central get default-nic-a: %v", err)
	}
	if compiled.Spec.ClusterName != "c1" {
		t.Fatalf("expected default-nic-a clusterName=c1 (from scheduled vm1), got %q", compiled.Spec.ClusterName)
	}
	if compiled.Spec.VNI != 1000 {
		t.Fatalf("expected default-nic-a vni=1000, got %d", compiled.Spec.VNI)
	}
	t.Log("(4) compile: PASS (default-nic-a -> c1)")

	// ================================================================
	// (5) SYNC: the c1 broker materializes default-nic-a downstream.
	// ================================================================
	b := &broker.Broker{Central: centralClient, Downstream: downstreamClient, ClusterName: "c1"}
	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("broker SyncOnce: %v", err)
	}
	downList := &compiledv1.CompiledNICList{}
	if err := downstreamClient.List(ctx, downList); err != nil {
		t.Fatalf("downstream List: %v", err)
	}
	if len(downList.Items) != 1 || downList.Items[0].Name != "default-nic-a" {
		names := make([]string, len(downList.Items))
		for i := range downList.Items {
			names[i] = downList.Items[i].Name
		}
		t.Fatalf("sync: expected downstream=[default-nic-a], got %v", names)
	}
	if downList.Items[0].Spec.ClusterName != "c1" || downList.Items[0].Spec.VNI != 1000 {
		t.Fatalf("sync: expected downstream clusterName=c1 vni=1000, got clusterName=%q vni=%d",
			downList.Items[0].Spec.ClusterName, downList.Items[0].Spec.VNI)
	}
	t.Log("(5) sync: PASS (downstream=[default-nic-a] bound c1)")
}
