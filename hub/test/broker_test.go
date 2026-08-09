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

	compiledinstall "github.com/trevex/ectobase/api/compiled/install"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	netinstall "github.com/trevex/ectobase/api/net/install"
	platforminstall "github.com/trevex/ectobase/api/platform/install"
	"github.com/trevex/ectobase/hub/pkg/broker"
)

// TestBroker_Loopback is the Phase-1b integration gate: it runs the broker
// engine between TWO real in-process apiservers and asserts the full sync
// contract (bounded pull, update propagation, GC, partition-survive) over the
// REAL, namespaced CompiledNIC type (group compiled.ectobase.dev).
//
//   - HUB   = the kit aggregated apiserver (serves CompiledNIC with a
//     selectable spec.clusterName field), started via kitenvtest.
//   - DOWNSTREAM = a plain controller-runtime envtest apiserver with the
//     CompiledNIC CRD installed from config/crd/bases.
//
// The broker is driven directly via SyncOnce (no informer/WatchListClient) so
// the assertions are deterministic. CompiledNIC is namespaced; both apiservers
// serve the "default" namespace out of the box (hub does not register a
// core-namespace REST handler, so we cannot create an arbitrary namespace on it —
// "default" is the namespace present on BOTH sides), so objects land there.
func TestBroker_Loopback(t *testing.T) {
	// The kit envtest harness builds the aggregated apiserver with `-mod mod`,
	// which conflicts with the repo's go.work workspace mode. Disable workspace
	// mode for the in-test build so the aggregated server compiles.
	t.Setenv("GOWORK", "off")

	const ns = "default"

	scheme := runtime.NewScheme()
	// The aggregated server binary serves all groups; the client scheme must
	// know both net and compiled types to (de)serialize CompiledNIC.
	// platforminstall is retained because the server still serves the platform group.
	platforminstall.Install(scheme)
	netinstall.Install(scheme)
	compiledinstall.Install(scheme)
	// APIService (apiregistration.k8s.io) must be registered so the kit envtest
	// harness can poll the aggregated APIService for readiness.
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiregistration scheme: %v", err)
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
	// hubEnv is explicitly Stopped in assertion (d) to simulate a hub
	// outage; guard the cleanup so a double-Stop is harmless.
	hubStopped := false
	t.Cleanup(func() {
		if hubStopped {
			return
		}
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
		Hub:     hubClient,
		Downstream:  downstreamClient,
		ClusterName: "c1",
	}

	// newNIC constructs a valid CompiledNIC: the CRD marks nodeName, vni, port and
	// firewall as required, so all are set (firewall/port take empty-but-present values).
	newNIC := func(name, cluster, node string) *compiledv1.CompiledNIC {
		return &compiledv1.CompiledNIC{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec: compiledv1.CompiledNICSpec{
				ClusterName: cluster,
				NodeName:    node,
				VNI:         1000,
				Port:        compiledv1.PortStatus{Type: compiledv1.PortTypeTap, Name: "dtapvf_0"},
				Firewall:    compiledv1.CompiledFirewall{},
			},
		}
	}

	// downKeys returns the current downstream CompiledNIC "namespace/name" keys.
	downKeys := func() []string {
		t.Helper()
		list := &compiledv1.CompiledNICList{}
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
		list := &compiledv1.CompiledVMList{}
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
		list := &compiledv1.CompiledVolumeAttachmentList{}
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
		list := &compiledv1.CompiledContainerList{}
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
	newVM := func(name, cluster, image string) *compiledv1.CompiledVM {
		return &compiledv1.CompiledVM{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       compiledv1.CompiledVMSpec{ClusterName: cluster, Image: image},
		}
	}

	// newAtt constructs a minimal CompiledVolumeAttachment bound to a cluster.
	newAtt := func(name, cluster, bootImage string) *compiledv1.CompiledVolumeAttachment {
		return &compiledv1.CompiledVolumeAttachment{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       compiledv1.CompiledVolumeAttachmentSpec{ClusterName: cluster, BootImage: bootImage},
		}
	}

	// newCtr constructs a minimal CompiledContainer bound to a cluster.
	newCtr := func(name, cluster, image string) *compiledv1.CompiledContainer {
		return &compiledv1.CompiledContainer{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       compiledv1.CompiledContainerSpec{ClusterName: cluster, Image: image},
		}
	}

	// ================================================================
	// (a) BOUNDED PULL: c2 must never cross into a c1-bound downstream.
	// ================================================================
	if err := hubClient.Create(ctx, newNIC("nic-a", "c1", "node-1")); err != nil {
		t.Fatalf("hub Create nic-a: %v", err)
	}
	if err := hubClient.Create(ctx, newNIC("nic-b", "c2", "node-2")); err != nil {
		t.Fatalf("hub Create nic-b: %v", err)
	}

	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("(a) SyncOnce: %v", err)
	}
	keys := downKeys()
	if len(keys) != 1 || keys[0] != ns+"/nic-a" {
		t.Fatalf("(a) bounded pull: expected downstream=[%s/nic-a], got %v", ns, keys)
	}
	got := &compiledv1.CompiledNIC{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "nic-a"}, got); err != nil {
		t.Fatalf("(a) downstream Get nic-a: %v", err)
	}
	if got.Spec.NodeName != "node-1" {
		t.Fatalf("(a) expected nic-a nodeName=node-1, got %q", got.Spec.NodeName)
	}
	t.Logf("(a) bounded pull: PASS (downstream=[%s/nic-a], c2 excluded)", ns)

	// ================================================================
	// (b) UPDATE: hub nic-a nodeName node-1->node-1b propagates downstream.
	// ================================================================
	cur := &compiledv1.CompiledNIC{}
	if err := hubClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "nic-a"}, cur); err != nil {
		t.Fatalf("(b) hub Get nic-a: %v", err)
	}
	cur.Spec.NodeName = "node-1b"
	if err := hubClient.Update(ctx, cur); err != nil {
		t.Fatalf("(b) hub Update nic-a: %v", err)
	}

	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("(b) SyncOnce: %v", err)
	}
	got = &compiledv1.CompiledNIC{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "nic-a"}, got); err != nil {
		t.Fatalf("(b) downstream Get nic-a: %v", err)
	}
	if got.Spec.NodeName != "node-1b" {
		t.Fatalf("(b) update: expected downstream nic-a nodeName=node-1b, got %q", got.Spec.NodeName)
	}
	t.Log("(b) update: PASS (downstream nic-a nodeName=node-1b)")

	// ================================================================
	// (c) GC: deleting hub nic-a empties downstream.
	// ================================================================
	del := &compiledv1.CompiledNIC{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nic-a"}}
	if err := hubClient.Delete(ctx, del); err != nil {
		t.Fatalf("(c) hub Delete nic-a: %v", err)
	}

	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("(c) SyncOnce: %v", err)
	}
	if keys := downKeys(); len(keys) != 0 {
		t.Fatalf("(c) gc: expected empty downstream, got %v", keys)
	}
	t.Log("(c) gc: PASS (downstream empty)")

	// ================================================================
	// (d) PARTITION-SURVIVE: sync nic-c, stop hub, downstream persists.
	// ================================================================
	if err := hubClient.Create(ctx, newNIC("nic-c", "c1", "node-3")); err != nil {
		t.Fatalf("(d) hub Create nic-c: %v", err)
	}
	if err := b.SyncOnce(ctx); err != nil {
		t.Fatalf("(d) SyncOnce: %v", err)
	}
	if keys := downKeys(); len(keys) != 1 || keys[0] != ns+"/nic-c" {
		t.Fatalf("(d) pre-partition: expected downstream=[%s/nic-c], got %v", ns, keys)
	}

	// Simulate a hub outage: stop the hub apiserver entirely.
	if err := hubEnv.Stop(); err != nil {
		t.Fatalf("(d) hub env.Stop: %v", err)
	}
	hubStopped = true

	// No SyncOnce here: prove the already-synced state persists without hub.
	if keys := downKeys(); len(keys) != 1 || keys[0] != ns+"/nic-c" {
		t.Fatalf("(d) partition-survive: expected downstream=[%s/nic-c] after hub outage, got %v", ns, keys)
	}
	t.Logf("(d) partition-survive: PASS (downstream=[%s/nic-c] survives hub outage)", ns)

	// Restart hub so we can run the CompiledVM assertions.
	hubEnv2, err := kitenvtest.NewEnvironment(
		"github.com/trevex/ectobase/hub/cmd/apiserver",
		nil,
		[]string{filepath.Join(".", "fixtures")},
	)
	if err != nil {
		t.Fatalf("(e) hub NewEnvironment restart: %v", err)
	}
	if _, err := hubEnv2.Start(scheme, os.Stderr); err != nil {
		t.Fatalf("(e) hub env2.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := hubEnv2.Stop(); err != nil {
			t.Errorf("hub env2.Stop: %v", err)
		}
	})
	if err := hubEnv2.WaitUntilReadyWithTimeout(apiServiceTimeout); err != nil {
		t.Fatalf("(e) hub env2 WaitUntilReadyWithTimeout: %v", err)
	}
	hubClient2, err := client.New(hubEnv2.GetRESTConfig(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("(e) central2 client.New: %v", err)
	}
	b2 := &broker.Broker{
		Hub:     hubClient2,
		Downstream:  downstreamClient,
		ClusterName: "c1",
	}

	// ================================================================
	// (e) CompiledVM: bounded pull, update, GC.
	// ================================================================
	if err := hubClient2.Create(ctx, newVM("vm-a", "c1", "fedora")); err != nil {
		t.Fatalf("(e) hub Create vm-a: %v", err)
	}
	if err := hubClient2.Create(ctx, newVM("vm-b", "c2", "ubuntu")); err != nil {
		t.Fatalf("(e) hub Create vm-b (c2): %v", err)
	}

	if err := b2.SyncCompiledVMs(ctx); err != nil {
		t.Fatalf("(e) SyncCompiledVMs: %v", err)
	}
	vmKeys := downVMKeys()
	if len(vmKeys) != 1 || vmKeys[0] != ns+"/vm-a" {
		t.Fatalf("(e) bounded pull: expected downstream=[%s/vm-a], got %v", ns, vmKeys)
	}
	gotVM := &compiledv1.CompiledVM{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm-a"}, gotVM); err != nil {
		t.Fatalf("(e) downstream Get vm-a: %v", err)
	}
	if gotVM.Spec.Image != "fedora" {
		t.Fatalf("(e) expected vm-a image=fedora, got %q", gotVM.Spec.Image)
	}
	t.Logf("(e) CompiledVM bounded pull: PASS (downstream=[%s/vm-a], c2 excluded)", ns)

	// Update vm-a image hub->downstream.
	curVM := &compiledv1.CompiledVM{}
	if err := hubClient2.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm-a"}, curVM); err != nil {
		t.Fatalf("(e) hub Get vm-a: %v", err)
	}
	curVM.Spec.Image = "fedora-updated"
	if err := hubClient2.Update(ctx, curVM); err != nil {
		t.Fatalf("(e) hub Update vm-a: %v", err)
	}
	if err := b2.SyncCompiledVMs(ctx); err != nil {
		t.Fatalf("(e) SyncCompiledVMs after update: %v", err)
	}
	gotVM = &compiledv1.CompiledVM{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm-a"}, gotVM); err != nil {
		t.Fatalf("(e) downstream Get vm-a after update: %v", err)
	}
	if gotVM.Spec.Image != "fedora-updated" {
		t.Fatalf("(e) update: expected vm-a image=fedora-updated, got %q", gotVM.Spec.Image)
	}
	t.Log("(e) CompiledVM update: PASS (downstream vm-a image=fedora-updated)")

	// GC: delete hub vm-a, downstream should be empty.
	delVM := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm-a"}}
	if err := hubClient2.Delete(ctx, delVM); err != nil {
		t.Fatalf("(e) hub Delete vm-a: %v", err)
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
	if err := hubClient2.Create(ctx, newAtt("att-a", "c1", "fedora")); err != nil {
		t.Fatalf("(f) hub Create att-a: %v", err)
	}
	if err := hubClient2.Create(ctx, newAtt("att-b", "c2", "ubuntu")); err != nil {
		t.Fatalf("(f) hub Create att-b (c2): %v", err)
	}

	if err := b2.SyncCompiledVolumeAttachments(ctx); err != nil {
		t.Fatalf("(f) SyncCompiledVolumeAttachments: %v", err)
	}
	attKeys := downAttKeys()
	if len(attKeys) != 1 || attKeys[0] != ns+"/att-a" {
		t.Fatalf("(f) bounded pull: expected downstream=[%s/att-a], got %v", ns, attKeys)
	}
	gotAtt := &compiledv1.CompiledVolumeAttachment{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "att-a"}, gotAtt); err != nil {
		t.Fatalf("(f) downstream Get att-a: %v", err)
	}
	if gotAtt.Spec.BootImage != "fedora" {
		t.Fatalf("(f) expected att-a bootImage=fedora, got %q", gotAtt.Spec.BootImage)
	}
	t.Logf("(f) CompiledVolumeAttachment bounded pull: PASS (downstream=[%s/att-a], c2 excluded)", ns)

	// Update att-a bootImage hub->downstream.
	curAtt := &compiledv1.CompiledVolumeAttachment{}
	if err := hubClient2.Get(ctx, client.ObjectKey{Namespace: ns, Name: "att-a"}, curAtt); err != nil {
		t.Fatalf("(f) hub Get att-a: %v", err)
	}
	curAtt.Spec.BootImage = "fedora-updated"
	if err := hubClient2.Update(ctx, curAtt); err != nil {
		t.Fatalf("(f) hub Update att-a: %v", err)
	}
	if err := b2.SyncCompiledVolumeAttachments(ctx); err != nil {
		t.Fatalf("(f) SyncCompiledVolumeAttachments after update: %v", err)
	}
	gotAtt = &compiledv1.CompiledVolumeAttachment{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "att-a"}, gotAtt); err != nil {
		t.Fatalf("(f) downstream Get att-a after update: %v", err)
	}
	if gotAtt.Spec.BootImage != "fedora-updated" {
		t.Fatalf("(f) update: expected att-a bootImage=fedora-updated, got %q", gotAtt.Spec.BootImage)
	}
	t.Log("(f) CompiledVolumeAttachment update: PASS (downstream att-a bootImage=fedora-updated)")

	// GC: delete hub att-a, downstream should be empty.
	delAtt := &compiledv1.CompiledVolumeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "att-a"}}
	if err := hubClient2.Delete(ctx, delAtt); err != nil {
		t.Fatalf("(f) hub Delete att-a: %v", err)
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
	if err := hubClient2.Create(ctx, newCtr("ctr-a", "c1", "nginx")); err != nil {
		t.Fatalf("(g) hub Create ctr-a: %v", err)
	}
	if err := hubClient2.Create(ctx, newCtr("ctr-b", "c2", "redis")); err != nil {
		t.Fatalf("(g) hub Create ctr-b (c2): %v", err)
	}

	if err := b2.SyncCompiledContainers(ctx); err != nil {
		t.Fatalf("(g) SyncCompiledContainers: %v", err)
	}
	ctrKeys := downCtrKeys()
	if len(ctrKeys) != 1 || ctrKeys[0] != ns+"/ctr-a" {
		t.Fatalf("(g) bounded pull: expected downstream=[%s/ctr-a], got %v", ns, ctrKeys)
	}
	gotCtr := &compiledv1.CompiledContainer{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctr-a"}, gotCtr); err != nil {
		t.Fatalf("(g) downstream Get ctr-a: %v", err)
	}
	if gotCtr.Spec.Image != "nginx" {
		t.Fatalf("(g) expected ctr-a image=nginx, got %q", gotCtr.Spec.Image)
	}
	t.Logf("(g) CompiledContainer bounded pull: PASS (downstream=[%s/ctr-a], c2 excluded)", ns)

	// Update ctr-a image hub->downstream.
	curCtr := &compiledv1.CompiledContainer{}
	if err := hubClient2.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctr-a"}, curCtr); err != nil {
		t.Fatalf("(g) hub Get ctr-a: %v", err)
	}
	curCtr.Spec.Image = "nginx-updated"
	if err := hubClient2.Update(ctx, curCtr); err != nil {
		t.Fatalf("(g) hub Update ctr-a: %v", err)
	}
	if err := b2.SyncCompiledContainers(ctx); err != nil {
		t.Fatalf("(g) SyncCompiledContainers after update: %v", err)
	}
	gotCtr = &compiledv1.CompiledContainer{}
	if err := downstreamClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctr-a"}, gotCtr); err != nil {
		t.Fatalf("(g) downstream Get ctr-a after update: %v", err)
	}
	if gotCtr.Spec.Image != "nginx-updated" {
		t.Fatalf("(g) update: expected ctr-a image=nginx-updated, got %q", gotCtr.Spec.Image)
	}
	t.Log("(g) CompiledContainer update: PASS (downstream ctr-a image=nginx-updated)")

	// GC: delete hub ctr-a, downstream should be empty.
	delCtr := &compiledv1.CompiledContainer{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ctr-a"}}
	if err := hubClient2.Delete(ctx, delCtr); err != nil {
		t.Fatalf("(g) hub Delete ctr-a: %v", err)
	}
	if err := b2.SyncCompiledContainers(ctx); err != nil {
		t.Fatalf("(g) SyncCompiledContainers after delete: %v", err)
	}
	if ctrKeys := downCtrKeys(); len(ctrKeys) != 0 {
		t.Fatalf("(g) gc: expected empty downstream containers, got %v", ctrKeys)
	}
	t.Log("(g) CompiledContainer GC: PASS (downstream containers empty)")
}
