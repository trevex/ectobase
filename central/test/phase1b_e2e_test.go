// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os"
	"path/filepath"
	"testing"

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
	"github.com/trevex/ectobase/central/pkg/broker"
	"github.com/trevex/ectobase/netplane/controllers"
)

// TestPhase1b_CompileBindSync_E2E proves the whole Phase-1b chain in one test,
// end to end across TWO real in-process apiservers:
//
//  1. high-level VirtualMachine + NetworkInterface land in CENTRAL (the kit
//     aggregated apiserver serving net.ectobase.dev);
//  2. the netplane CompiledNICReconciler compiles each NIC into a CompiledNIC in
//     CENTRAL, inheriting spec.clusterName from the owning VM plus a
//     workload=<vm> label (via resolvePlacement);
//  3. the per-cluster broker syncs the c1-bound CompiledNIC into a DOWNSTREAM
//     cluster, bounded by clusterName — the c2 workload never crosses.
//
// The reconciler is driven directly via Reconcile (no manager/informer) so the
// assertions are deterministic. CompiledNIC/NetworkInterface/VirtualMachine are
// namespaced; both apiservers serve the "default" namespace out of the box
// (central registers no core-namespace REST handler), so objects land there.
func TestPhase1b_CompileBindSync_E2E(t *testing.T) {
	// The kit envtest harness builds the aggregated apiserver with `-mod mod`,
	// which conflicts with the repo's go.work workspace mode. Disable workspace
	// mode for the in-test build so the aggregated server compiles.
	t.Setenv("GOWORK", "off")

	const ns = "default"

	scheme := runtime.NewScheme()
	// The aggregated server binary serves both groups; the client scheme must know
	// the net types (external api/v1alpha1, registered via netinstall — central's
	// versioned types are aliases to it) to (de)serialize the objects. The
	// reconciler uses the same external netv1 types, so its GVK lookups resolve
	// against this scheme.
	platforminstall.Install(scheme)
	netinstall.Install(scheme)
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
	// Seed CENTRAL with the high-level objects for two workloads.
	//   - vm1 (cluster c1) owns nic-a  -> compiled NIC must bind to c1
	//   - vm2 (cluster c2) owns nic-b  -> compiled NIC must bind to c2 (must NOT
	//     cross into the c1-bound downstream).
	// ================================================================
	node1 := "node-1"
	node2 := "node-2"

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
		t.Fatalf("central Create nic-a: %v", err)
	}
	nicB := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nic-b"},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:   netv1.LocalObjectReference{Name: "vpc-1"},
			IPs:      []string{"10.0.0.6"},
			MAC:      "aa:bb:cc:dd:ee:02",
			NodeName: &node2,
		},
	}
	if err := centralClient.Create(ctx, nicB); err != nil {
		t.Fatalf("central Create nic-b: %v", err)
	}

	// Give each NIC an effective VNI directly via the status subresource so the
	// CompiledNIC's required `vni` is populated without needing a Ready VPC.
	// (The compiler resolves vni from nic.Status.VNI first, else the VPC's
	// status.vni; setting it here keeps the test self-contained.) This must
	// precede Reconcile: no watch loop runs here, so Reconcile reads the status
	// as it stands when we call it — the ordering is fully explicit.
	setVNI := func(nic *netv1.NetworkInterface, vni int32) {
		t.Helper()
		cur := &netv1.NetworkInterface{}
		if err := centralClient.Get(ctx, client.ObjectKeyFromObject(nic), cur); err != nil {
			t.Fatalf("central Get %s for status: %v", nic.Name, err)
		}
		cur.Status.VNI = vni
		if err := centralClient.Status().Update(ctx, cur); err != nil {
			t.Fatalf("central Status().Update %s: %v", nic.Name, err)
		}
	}
	setVNI(nicA, 1000)
	setVNI(nicB, 2000)

	vm1 := &netv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm1"},
		Spec: netv1.VirtualMachineSpec{
			ClusterName:   "c1",
			InterfaceRefs: []netv1.LocalObjectReference{{Name: "nic-a"}},
		},
	}
	if err := centralClient.Create(ctx, vm1); err != nil {
		t.Fatalf("central Create vm1: %v", err)
	}
	vm2 := &netv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm2"},
		Spec: netv1.VirtualMachineSpec{
			ClusterName:   "c2",
			InterfaceRefs: []netv1.LocalObjectReference{{Name: "nic-b"}},
		},
	}
	if err := centralClient.Create(ctx, vm2); err != nil {
		t.Fatalf("central Create vm2: %v", err)
	}

	// ================================================================
	// COMPILE: run the real netplane reconciler once per NIC against central.
	// ================================================================
	// DefaultClusterName is the fallback for a NIC with no owning VM; it is not
	// exercised here (both NICs are owned by a VM) — the fallback is covered by
	// the netplane compiler unit tests.
	r := &controllers.CompiledNICReconciler{Client: centralClient, DefaultClusterName: "default"}
	for _, name := range []string{"nic-a", "nic-b"} {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: name}}); err != nil {
			t.Fatalf("compile Reconcile %s: %v", name, err)
		}
	}

	// ================================================================
	// ASSERT (central): nic-a compiled to name "default-nic-a", bound to c1, with
	// the workload=vm1 label inherited from its owning VM.
	// ================================================================
	compiledA := &netv1.CompiledNIC{}
	if err := centralClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "default-nic-a"}, compiledA); err != nil {
		t.Fatalf("central Get default-nic-a: %v", err)
	}
	if compiledA.Spec.ClusterName != "c1" {
		t.Fatalf("compile: expected default-nic-a clusterName=c1 (from vm1), got %q", compiledA.Spec.ClusterName)
	}
	if compiledA.Labels["workload"] != "vm1" {
		t.Fatalf("compile: expected default-nic-a label workload=vm1, got %q", compiledA.Labels["workload"])
	}
	if compiledA.Spec.VNI != 1000 {
		t.Fatalf("compile: expected default-nic-a vni=1000, got %d", compiledA.Spec.VNI)
	}
	if compiledA.Spec.NodeName != "node-1" {
		t.Fatalf("compile: expected default-nic-a nodeName=node-1, got %q", compiledA.Spec.NodeName)
	}

	// nic-b compiled to c2 (owned by vm2) — used to prove bounded pull below.
	compiledB := &netv1.CompiledNIC{}
	if err := centralClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "default-nic-b"}, compiledB); err != nil {
		t.Fatalf("central Get default-nic-b: %v", err)
	}
	if compiledB.Spec.ClusterName != "c2" {
		t.Fatalf("compile: expected default-nic-b clusterName=c2 (from vm2), got %q", compiledB.Spec.ClusterName)
	}
	if compiledB.Spec.VNI != 2000 {
		t.Fatalf("compile: expected default-nic-b vni=2000 (distinct from nic-a), got %d", compiledB.Spec.VNI)
	}
	t.Log("compile: PASS (default-nic-a -> c1/workload=vm1, default-nic-b -> c2)")

	// ================================================================
	// BIND+SYNC: the c1 broker pulls central -> downstream, bounded by clusterName.
	// ================================================================
	b := &broker.Broker{Central: centralClient, Downstream: downstreamClient, ClusterName: "c1"}
	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("broker SyncOnce: %v", err)
	}

	// ================================================================
	// ASSERT (downstream): exactly ONE CompiledNIC (nic-a's), bound to c1; the c2
	// workload (default-nic-b) did NOT cross.
	// ================================================================
	downList := &netv1.CompiledNICList{}
	if err := downstreamClient.List(ctx, downList); err != nil {
		t.Fatalf("downstream List: %v", err)
	}
	if len(downList.Items) != 1 {
		names := make([]string, len(downList.Items))
		for i := range downList.Items {
			names[i] = downList.Items[i].Namespace + "/" + downList.Items[i].Name
		}
		t.Fatalf("sync: expected exactly 1 downstream CompiledNIC, got %d: %v", len(downList.Items), names)
	}
	got := downList.Items[0]
	if got.Name != "default-nic-a" {
		t.Fatalf("sync: expected downstream CompiledNIC=default-nic-a, got %q", got.Name)
	}
	if got.Spec.ClusterName != "c1" {
		t.Fatalf("sync: expected downstream clusterName=c1, got %q", got.Spec.ClusterName)
	}
	if got.Spec.VNI != 1000 || got.Spec.NodeName != "node-1" {
		t.Fatalf("sync: expected downstream vni=1000 node=node-1, got vni=%d node=%q", got.Spec.VNI, got.Spec.NodeName)
	}
	t.Log("bind+sync: PASS (downstream=[default/default-nic-a], c2 excluded)")
}
