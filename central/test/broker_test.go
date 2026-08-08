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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	netinstall "github.com/trevex/ectobase/central/apis/net/install"
	platforminstall "github.com/trevex/ectobase/central/apis/platform/install"
	"github.com/trevex/ectobase/central/pkg/broker"
)

// TestBroker_Loopback is the Phase-1b integration gate: it runs the broker
// engine between TWO real in-process apiservers and asserts the full sync
// contract (bounded pull, update propagation, GC, partition-survive) over the
// REAL, namespaced CompiledNIC type (group net.ectobase.dev).
//
//   - CENTRAL   = the kit aggregated apiserver (serves CompiledNIC with a
//     selectable spec.clusterName field), started via kitenvtest.
//   - DOWNSTREAM = a plain controller-runtime envtest apiserver with the
//     CompiledNIC CRD installed from config/crd/bases.
//
// The broker is driven directly via SyncOnce (no informer/WatchListClient) so
// the assertions are deterministic. CompiledNIC is namespaced; both apiservers
// serve the "default" namespace out of the box (central does not register a
// core-namespace REST handler, so we cannot create an arbitrary namespace on it —
// "default" is the namespace present on BOTH sides), so objects land there.
func TestBroker_Loopback(t *testing.T) {
	// The kit envtest harness builds the aggregated apiserver with `-mod mod`,
	// which conflicts with the repo's go.work workspace mode. Disable workspace
	// mode for the in-test build so the aggregated server compiles.
	t.Setenv("GOWORK", "off")

	const ns = "default"

	scheme := runtime.NewScheme()
	// The aggregated server binary serves both groups; the client scheme must
	// know the net types (external api/v1alpha1, registered via netinstall) to
	// (de)serialize CompiledNIC. platforminstall is retained because the server
	// still serves the platform group.
	platforminstall.Install(scheme)
	netinstall.Install(scheme)
	// APIService (apiregistration.k8s.io) must be registered so the kit envtest
	// harness can poll the aggregated APIService for readiness.
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
	// centralEnv is explicitly Stopped in assertion (d) to simulate a central
	// outage; guard the cleanup so a double-Stop is harmless.
	centralStopped := false
	t.Cleanup(func() {
		if centralStopped {
			return
		}
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

	b := &broker.Broker{
		Central:     centralClient,
		Downstream:  downstreamClient,
		ClusterName: "c1",
	}

	// newNIC constructs a valid CompiledNIC: the CRD marks nodeName, vni, port and
	// firewall as required, so all are set (firewall/port take empty-but-present values).
	newNIC := func(name, cluster, node string) *netv1.CompiledNIC {
		return &netv1.CompiledNIC{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec: netv1.CompiledNICSpec{
				ClusterName: cluster,
				NodeName:    node,
				VNI:         1000,
				Port:        netv1.PortStatus{Type: netv1.PortTypeTap, Name: "dtapvf_0"},
				Firewall:    netv1.CompiledFirewall{},
			},
		}
	}

	// downKeys returns the current downstream CompiledNIC "namespace/name" keys.
	downKeys := func() []string {
		t.Helper()
		list := &netv1.CompiledNICList{}
		if err := downstreamClient.List(ctx, list); err != nil {
			t.Fatalf("downstream List: %v", err)
		}
		keys := make([]string, len(list.Items))
		for i := range list.Items {
			keys[i] = list.Items[i].Namespace + "/" + list.Items[i].Name
		}
		return keys
	}

	// downVMKeys returns the current downstream CompiledVM "namespace/name" keys.
	downVMKeys := func() []string {
		t.Helper()
		list := &netv1.CompiledVMList{}
		if err := downstreamClient.List(ctx, list); err != nil {
			t.Fatalf("downstream VM List: %v", err)
		}
		keys := make([]string, len(list.Items))
		for i := range list.Items {
			keys[i] = list.Items[i].Namespace + "/" + list.Items[i].Name
		}
		return keys
	}

	// downAttKeys returns the current downstream CompiledVolumeAttachment "namespace/name" keys.
	downAttKeys := func() []string {
		t.Helper()
		list := &netv1.CompiledVolumeAttachmentList{}
		if err := downstreamClient.List(ctx, list); err != nil {
			t.Fatalf("downstream Att List: %v", err)
		}
		keys := make([]string, len(list.Items))
		for i := range list.Items {
			keys[i] = list.Items[i].Namespace + "/" + list.Items[i].Name
		}
		return keys
	}

	// downCtrKeys returns the current downstream CompiledContainer "namespace/name" keys.
	downCtrKeys := func() []string {
		t.Helper()
		list := &netv1.CompiledContainerList{}
		if err := downstreamClient.List(ctx, list); err != nil {
			t.Fatalf("downstream Ctr List: %v", err)
		}
		keys := make([]string, len(list.Items))
		for i := range list.Items {
			keys[i] = list.Items[i].Namespace + "/" + list.Items[i].Name
		}
		return keys
	}

	// newVM constructs a minimal CompiledVM bound to a cluster.
	newVM := func(name, cluster, image string) *netv1.CompiledVM {
		return &netv1.CompiledVM{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       netv1.CompiledVMSpec{ClusterName: cluster, Image: image},
		}
	}

	// newAtt constructs a minimal CompiledVolumeAttachment bound to a cluster.
	newAtt := func(name, cluster, bootImage string) *netv1.CompiledVolumeAttachment {
		return &netv1.CompiledVolumeAttachment{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       netv1.CompiledVolumeAttachmentSpec{ClusterName: cluster, BootImage: bootImage},
		}
	}

	// newCtr constructs a minimal CompiledContainer bound to a cluster.
	newCtr := func(name, cluster, image string) *netv1.CompiledContainer {
		return &netv1.CompiledContainer{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       netv1.CompiledContainerSpec{ClusterName: cluster, Image: image},
		}
	}

	// ================================================================
	// (a) BOUNDED PULL: c2 must never cross into a c1-bound downstream.
	// ================================================================
	if err := centralClient.Create(ctx, newNIC("nic-a", "c1", "node-1")); err != nil {
		t.Fatalf("central Create nic-a: %v", err)
	}
	if err := centralClient.Create(ctx, newNIC("nic-b", "c2", "node-2")); err != nil {
		t.Fatalf("central Create nic-b: %v", err)
	}

	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("(a) SyncOnce: %v", err)
	}
	keys := downKeys()
	if len(keys) != 1 || keys[0] != ns+"/nic-a" {
		t.Fatalf("(a) bounded pull: expected downstream=[%s/nic-a], got %v", ns, keys)
	}
	got := &netv1.CompiledNIC{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "nic-a"}, got); err != nil {
		t.Fatalf("(a) downstream Get nic-a: %v", err)
	}
	if got.Spec.NodeName != "node-1" {
		t.Fatalf("(a) expected nic-a nodeName=node-1, got %q", got.Spec.NodeName)
	}
	t.Logf("(a) bounded pull: PASS (downstream=[%s/nic-a], c2 excluded)", ns)

	// ================================================================
	// (b) UPDATE: central nic-a nodeName node-1->node-1b propagates downstream.
	// ================================================================
	cur := &netv1.CompiledNIC{}
	if err := centralClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "nic-a"}, cur); err != nil {
		t.Fatalf("(b) central Get nic-a: %v", err)
	}
	cur.Spec.NodeName = "node-1b"
	if err := centralClient.Update(ctx, cur); err != nil {
		t.Fatalf("(b) central Update nic-a: %v", err)
	}

	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("(b) SyncOnce: %v", err)
	}
	got = &netv1.CompiledNIC{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "nic-a"}, got); err != nil {
		t.Fatalf("(b) downstream Get nic-a: %v", err)
	}
	if got.Spec.NodeName != "node-1b" {
		t.Fatalf("(b) update: expected downstream nic-a nodeName=node-1b, got %q", got.Spec.NodeName)
	}
	t.Log("(b) update: PASS (downstream nic-a nodeName=node-1b)")

	// ================================================================
	// (c) GC: deleting central nic-a empties downstream.
	// ================================================================
	del := &netv1.CompiledNIC{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nic-a"}}
	if err := centralClient.Delete(ctx, del); err != nil {
		t.Fatalf("(c) central Delete nic-a: %v", err)
	}

	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("(c) SyncOnce: %v", err)
	}
	if keys := downKeys(); len(keys) != 0 {
		t.Fatalf("(c) gc: expected empty downstream, got %v", keys)
	}
	t.Log("(c) gc: PASS (downstream empty)")

	// ================================================================
	// (d) PARTITION-SURVIVE: sync nic-c, stop central, downstream persists.
	// ================================================================
	if err := centralClient.Create(ctx, newNIC("nic-c", "c1", "node-3")); err != nil {
		t.Fatalf("(d) central Create nic-c: %v", err)
	}
	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("(d) SyncOnce: %v", err)
	}
	if keys := downKeys(); len(keys) != 1 || keys[0] != ns+"/nic-c" {
		t.Fatalf("(d) pre-partition: expected downstream=[%s/nic-c], got %v", ns, keys)
	}

	// Simulate a central outage: stop the central apiserver entirely.
	if err := centralEnv.Stop(); err != nil {
		t.Fatalf("(d) central env.Stop: %v", err)
	}
	centralStopped = true

	// No SyncOnce here: prove the already-synced state persists without central.
	if keys := downKeys(); len(keys) != 1 || keys[0] != ns+"/nic-c" {
		t.Fatalf("(d) partition-survive: expected downstream=[%s/nic-c] after central outage, got %v", ns, keys)
	}
	t.Logf("(d) partition-survive: PASS (downstream=[%s/nic-c] survives central outage)", ns)

	// Restart central so we can run the CompiledVM assertions.
	centralEnv2, err := kitenvtest.NewEnvironment(
		"github.com/trevex/ectobase/central/cmd/apiserver",
		nil,
		[]string{filepath.Join(".", "fixtures")},
	)
	if err != nil {
		t.Fatalf("(e) central NewEnvironment restart: %v", err)
	}
	if _, err := centralEnv2.Start(scheme, os.Stderr); err != nil {
		t.Fatalf("(e) central env2.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := centralEnv2.Stop(); err != nil {
			t.Errorf("central env2.Stop: %v", err)
		}
	})
	if err := centralEnv2.WaitUntilReadyWithTimeout(apiServiceTimeout); err != nil {
		t.Fatalf("(e) central env2 WaitUntilReadyWithTimeout: %v", err)
	}
	centralClient2, err := client.New(centralEnv2.GetRESTConfig(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("(e) central2 client.New: %v", err)
	}
	b2 := &broker.Broker{
		Central:     centralClient2,
		Downstream:  downstreamClient,
		ClusterName: "c1",
	}

	// ================================================================
	// (e) CompiledVM: bounded pull, update, GC.
	// ================================================================
	if err := centralClient2.Create(ctx, newVM("vm-a", "c1", "fedora")); err != nil {
		t.Fatalf("(e) central Create vm-a: %v", err)
	}
	if err := centralClient2.Create(ctx, newVM("vm-b", "c2", "ubuntu")); err != nil {
		t.Fatalf("(e) central Create vm-b (c2): %v", err)
	}

	if err := b2.SyncCompiledVMs(ctx); err != nil {
		t.Fatalf("(e) SyncCompiledVMs: %v", err)
	}
	vmKeys := downVMKeys()
	if len(vmKeys) != 1 || vmKeys[0] != ns+"/vm-a" {
		t.Fatalf("(e) bounded pull: expected downstream=[%s/vm-a], got %v", ns, vmKeys)
	}
	gotVM := &netv1.CompiledVM{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm-a"}, gotVM); err != nil {
		t.Fatalf("(e) downstream Get vm-a: %v", err)
	}
	if gotVM.Spec.Image != "fedora" {
		t.Fatalf("(e) expected vm-a image=fedora, got %q", gotVM.Spec.Image)
	}
	t.Logf("(e) CompiledVM bounded pull: PASS (downstream=[%s/vm-a], c2 excluded)", ns)

	// Update vm-a image central->downstream.
	curVM := &netv1.CompiledVM{}
	if err := centralClient2.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm-a"}, curVM); err != nil {
		t.Fatalf("(e) central Get vm-a: %v", err)
	}
	curVM.Spec.Image = "fedora-updated"
	if err := centralClient2.Update(ctx, curVM); err != nil {
		t.Fatalf("(e) central Update vm-a: %v", err)
	}
	if err := b2.SyncCompiledVMs(ctx); err != nil {
		t.Fatalf("(e) SyncCompiledVMs after update: %v", err)
	}
	gotVM = &netv1.CompiledVM{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm-a"}, gotVM); err != nil {
		t.Fatalf("(e) downstream Get vm-a after update: %v", err)
	}
	if gotVM.Spec.Image != "fedora-updated" {
		t.Fatalf("(e) update: expected vm-a image=fedora-updated, got %q", gotVM.Spec.Image)
	}
	t.Log("(e) CompiledVM update: PASS (downstream vm-a image=fedora-updated)")

	// GC: delete central vm-a, downstream should be empty.
	delVM := &netv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm-a"}}
	if err := centralClient2.Delete(ctx, delVM); err != nil {
		t.Fatalf("(e) central Delete vm-a: %v", err)
	}
	if err := b2.SyncCompiledVMs(ctx); err != nil {
		t.Fatalf("(e) SyncCompiledVMs after delete: %v", err)
	}
	if vmKeys := downVMKeys(); len(vmKeys) != 0 {
		t.Fatalf("(e) gc: expected empty downstream VMs, got %v", vmKeys)
	}
	t.Log("(e) CompiledVM GC: PASS (downstream VMs empty)")

	// ================================================================
	// (f) CompiledVolumeAttachment: bounded pull, update, GC.
	// ================================================================
	if err := centralClient2.Create(ctx, newAtt("att-a", "c1", "fedora")); err != nil {
		t.Fatalf("(f) central Create att-a: %v", err)
	}
	if err := centralClient2.Create(ctx, newAtt("att-b", "c2", "ubuntu")); err != nil {
		t.Fatalf("(f) central Create att-b (c2): %v", err)
	}

	if err := b2.SyncCompiledVolumeAttachments(ctx); err != nil {
		t.Fatalf("(f) SyncCompiledVolumeAttachments: %v", err)
	}
	attKeys := downAttKeys()
	if len(attKeys) != 1 || attKeys[0] != ns+"/att-a" {
		t.Fatalf("(f) bounded pull: expected downstream=[%s/att-a], got %v", ns, attKeys)
	}
	gotAtt := &netv1.CompiledVolumeAttachment{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "att-a"}, gotAtt); err != nil {
		t.Fatalf("(f) downstream Get att-a: %v", err)
	}
	if gotAtt.Spec.BootImage != "fedora" {
		t.Fatalf("(f) expected att-a bootImage=fedora, got %q", gotAtt.Spec.BootImage)
	}
	t.Logf("(f) CompiledVolumeAttachment bounded pull: PASS (downstream=[%s/att-a], c2 excluded)", ns)

	// Update att-a bootImage central->downstream.
	curAtt := &netv1.CompiledVolumeAttachment{}
	if err := centralClient2.Get(ctx, client.ObjectKey{Namespace: ns, Name: "att-a"}, curAtt); err != nil {
		t.Fatalf("(f) central Get att-a: %v", err)
	}
	curAtt.Spec.BootImage = "fedora-updated"
	if err := centralClient2.Update(ctx, curAtt); err != nil {
		t.Fatalf("(f) central Update att-a: %v", err)
	}
	if err := b2.SyncCompiledVolumeAttachments(ctx); err != nil {
		t.Fatalf("(f) SyncCompiledVolumeAttachments after update: %v", err)
	}
	gotAtt = &netv1.CompiledVolumeAttachment{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "att-a"}, gotAtt); err != nil {
		t.Fatalf("(f) downstream Get att-a after update: %v", err)
	}
	if gotAtt.Spec.BootImage != "fedora-updated" {
		t.Fatalf("(f) update: expected att-a bootImage=fedora-updated, got %q", gotAtt.Spec.BootImage)
	}
	t.Log("(f) CompiledVolumeAttachment update: PASS (downstream att-a bootImage=fedora-updated)")

	// GC: delete central att-a, downstream should be empty.
	delAtt := &netv1.CompiledVolumeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "att-a"}}
	if err := centralClient2.Delete(ctx, delAtt); err != nil {
		t.Fatalf("(f) central Delete att-a: %v", err)
	}
	if err := b2.SyncCompiledVolumeAttachments(ctx); err != nil {
		t.Fatalf("(f) SyncCompiledVolumeAttachments after delete: %v", err)
	}
	if attKeys := downAttKeys(); len(attKeys) != 0 {
		t.Fatalf("(f) gc: expected empty downstream attachments, got %v", attKeys)
	}
	t.Log("(f) CompiledVolumeAttachment GC: PASS (downstream attachments empty)")

	// ================================================================
	// (g) CompiledContainer: bounded pull, update, GC.
	// ================================================================
	if err := centralClient2.Create(ctx, newCtr("ctr-a", "c1", "nginx")); err != nil {
		t.Fatalf("(g) central Create ctr-a: %v", err)
	}
	if err := centralClient2.Create(ctx, newCtr("ctr-b", "c2", "redis")); err != nil {
		t.Fatalf("(g) central Create ctr-b (c2): %v", err)
	}

	if err := b2.SyncCompiledContainers(ctx); err != nil {
		t.Fatalf("(g) SyncCompiledContainers: %v", err)
	}
	ctrKeys := downCtrKeys()
	if len(ctrKeys) != 1 || ctrKeys[0] != ns+"/ctr-a" {
		t.Fatalf("(g) bounded pull: expected downstream=[%s/ctr-a], got %v", ns, ctrKeys)
	}
	gotCtr := &netv1.CompiledContainer{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctr-a"}, gotCtr); err != nil {
		t.Fatalf("(g) downstream Get ctr-a: %v", err)
	}
	if gotCtr.Spec.Image != "nginx" {
		t.Fatalf("(g) expected ctr-a image=nginx, got %q", gotCtr.Spec.Image)
	}
	t.Logf("(g) CompiledContainer bounded pull: PASS (downstream=[%s/ctr-a], c2 excluded)", ns)

	// Update ctr-a image central->downstream.
	curCtr := &netv1.CompiledContainer{}
	if err := centralClient2.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctr-a"}, curCtr); err != nil {
		t.Fatalf("(g) central Get ctr-a: %v", err)
	}
	curCtr.Spec.Image = "nginx-updated"
	if err := centralClient2.Update(ctx, curCtr); err != nil {
		t.Fatalf("(g) central Update ctr-a: %v", err)
	}
	if err := b2.SyncCompiledContainers(ctx); err != nil {
		t.Fatalf("(g) SyncCompiledContainers after update: %v", err)
	}
	gotCtr = &netv1.CompiledContainer{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctr-a"}, gotCtr); err != nil {
		t.Fatalf("(g) downstream Get ctr-a after update: %v", err)
	}
	if gotCtr.Spec.Image != "nginx-updated" {
		t.Fatalf("(g) update: expected ctr-a image=nginx-updated, got %q", gotCtr.Spec.Image)
	}
	t.Log("(g) CompiledContainer update: PASS (downstream ctr-a image=nginx-updated)")

	// GC: delete central ctr-a, downstream should be empty.
	delCtr := &netv1.CompiledContainer{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ctr-a"}}
	if err := centralClient2.Delete(ctx, delCtr); err != nil {
		t.Fatalf("(g) central Delete ctr-a: %v", err)
	}
	if err := b2.SyncCompiledContainers(ctx); err != nil {
		t.Fatalf("(g) SyncCompiledContainers after delete: %v", err)
	}
	if ctrKeys := downCtrKeys(); len(ctrKeys) != 0 {
		t.Fatalf("(g) gc: expected empty downstream containers, got %v", ctrKeys)
	}
	t.Log("(g) CompiledContainer GC: PASS (downstream containers empty)")
}
