// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
)

// TestSync_NamespacedCreateUpdateGC drives the set-reconcile over the REAL,
// namespaced CompiledNIC across TWO namespaces: create, update (drift),
// GC (extra), and bounded-by-clusterName (c2 must not cross).
func TestSync_NamespacedCreateUpdateGC(t *testing.T) {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	wl := func(ns, name, cn, node string) *netv1.CompiledNIC {
		return &netv1.CompiledNIC{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       netv1.CompiledNICSpec{ClusterName: cn, NodeName: node},
		}
	}
	idx := func(o client.Object) []string { return []string{o.(*netv1.CompiledNIC).Spec.ClusterName} }
	central := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&netv1.CompiledNIC{}, "spec.clusterName", idx).
		WithObjects(wl("ns1", "a", "c1", "n1"), wl("ns2", "b", "c1", "n2"), wl("ns1", "c", "c2", "n3")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(wl("ns1", "stale", "c1", "old"), wl("ns1", "a", "c1", "OLD")).Build()

	b := &Broker{Central: central, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	list := &netv1.CompiledNICList{}
	if err := downstream.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	// exactly {ns1/a(node n1), ns2/b(node n2)}: c is c2 (bounded out), ns1/stale GC'd, ns1/a updated OLD->n1.
	if len(list.Items) != 2 {
		t.Fatalf("want 2 items, got %d: %+v", len(list.Items), list.Items)
	}
	got := map[string]string{}
	for _, it := range list.Items {
		got[it.Namespace+"/"+it.Name] = it.Spec.NodeName
	}
	if got["ns1/a"] != "n1" || got["ns2/b"] != "n2" {
		t.Fatalf("unexpected downstream set: %+v", got)
	}
	if _, ok := got["ns1/stale"]; ok {
		t.Fatalf("stale not GC'd: %+v", got)
	}
	if _, ok := got["ns1/c"]; ok {
		t.Fatalf("c2 object crossed the boundary: %+v", got)
	}

	// Idempotent: a second sync is a no-op (still exactly 2 items).
	if err := b.SyncOnce(context.Background()); err != nil {
		t.Fatalf("second SyncOnce: %v", err)
	}
	if err := downstream.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 2 {
		t.Fatalf("second sync not idempotent: %+v", list.Items)
	}
}

func TestSyncCompiledVMs_NamespacedCreateUpdateGC(t *testing.T) {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	vm := func(ns, name, cn, img string) *netv1.CompiledVM {
		return &netv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: netv1.CompiledVMSpec{ClusterName: cn, Image: img}}
	}
	idx := func(o client.Object) []string { return []string{o.(*netv1.CompiledVM).Spec.ClusterName} }
	central := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&netv1.CompiledVM{}, "spec.clusterName", idx).
		WithObjects(vm("ns1", "a", "c1", "fedora"), vm("ns1", "b", "c2", "x")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(vm("ns1", "stale", "c1", "old"), vm("ns1", "a", "c1", "OLD")).Build()

	b := &Broker{Central: central, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncCompiledVMs(context.Background()); err != nil {
		t.Fatal(err)
	}

	list := &netv1.CompiledVMList{}
	if err := downstream.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("want 1 (a), got %d: %+v", len(list.Items), list.Items)
	}
	if list.Items[0].Name != "a" || list.Items[0].Spec.Image != "fedora" {
		t.Fatalf("want a(fedora), got %+v", list.Items[0])
	}

	// Idempotency: a second sync of the converged set is a no-op (no create/update/delete).
	if err := b.SyncCompiledVMs(context.Background()); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	list2 := &netv1.CompiledVMList{}
	if err := downstream.List(context.Background(), list2); err != nil {
		t.Fatal(err)
	}
	if len(list2.Items) != 1 || list2.Items[0].Name != "a" || list2.Items[0].Spec.Image != "fedora" {
		t.Fatalf("idempotency: set drifted on re-sync: %+v", list2.Items)
	}
}

func TestSyncCompiledVolumeAttachments_NamespacedCreateUpdateGC(t *testing.T) {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil { t.Fatal(err) }
	att := func(ns, name, cn, img string) *netv1.CompiledVolumeAttachment {
		return &netv1.CompiledVolumeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: netv1.CompiledVolumeAttachmentSpec{ClusterName: cn, BootImage: img}}
	}
	idx := func(o client.Object) []string { return []string{o.(*netv1.CompiledVolumeAttachment).Spec.ClusterName} }
	central := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&netv1.CompiledVolumeAttachment{}, "spec.clusterName", idx).
		WithObjects(att("ns1", "a", "c1", "fedora"), att("ns1", "b", "c2", "x")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(att("ns1", "stale", "c1", "old"), att("ns1", "a", "c1", "OLD")).Build()

	b := &Broker{Central: central, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncCompiledVolumeAttachments(context.Background()); err != nil { t.Fatal(err) }

	list := &netv1.CompiledVolumeAttachmentList{}
	if err := downstream.List(context.Background(), list); err != nil { t.Fatal(err) }
	if len(list.Items) != 1 || list.Items[0].Name != "a" || list.Items[0].Spec.BootImage != "fedora" {
		t.Fatalf("want [a(fedora)], got %+v", list.Items)
	}
	if err := b.SyncCompiledVolumeAttachments(context.Background()); err != nil { t.Fatalf("second sync: %v", err) }
}

func TestSyncCompiledContainers_NamespacedCreateUpdateGC(t *testing.T) {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	ctr := func(ns, name, cn, img string) *netv1.CompiledContainer {
		return &netv1.CompiledContainer{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: netv1.CompiledContainerSpec{ClusterName: cn, Image: img}}
	}
	idx := func(o client.Object) []string { return []string{o.(*netv1.CompiledContainer).Spec.ClusterName} }
	central := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&netv1.CompiledContainer{}, "spec.clusterName", idx).
		WithObjects(ctr("ns1", "a", "c1", "nginx"), ctr("ns1", "b", "c2", "x")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(ctr("ns1", "stale", "c1", "old"), ctr("ns1", "a", "c1", "OLD")).Build()

	b := &Broker{Central: central, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncCompiledContainers(context.Background()); err != nil {
		t.Fatal(err)
	}

	list := &netv1.CompiledContainerList{}
	if err := downstream.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	// exactly {ns1/a(nginx)}: b is c2 (bounded out), stale GC'd, a updated OLD->nginx.
	if len(list.Items) != 1 {
		t.Fatalf("want 1 (a), got %d: %+v", len(list.Items), list.Items)
	}
	if list.Items[0].Name != "a" || list.Items[0].Spec.Image != "nginx" {
		t.Fatalf("want a(nginx), got %+v", list.Items[0])
	}

	// Idempotency: a second sync of the converged set is a no-op.
	if err := b.SyncCompiledContainers(context.Background()); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	list2 := &netv1.CompiledContainerList{}
	if err := downstream.List(context.Background(), list2); err != nil {
		t.Fatal(err)
	}
	if len(list2.Items) != 1 || list2.Items[0].Name != "a" || list2.Items[0].Spec.Image != "nginx" {
		t.Fatalf("idempotency: set drifted on re-sync: %+v", list2.Items)
	}
}

// TestSync_PropagatesLabels guards the load-bearing workload-label propagation: the
// downstream vm-materializer joins a VM to its volume attachments by the workload
// label, so the broker must mirror labels (not just spec) central->downstream.
func TestSync_PropagatesLabels(t *testing.T) {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	att := &netv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "vm1-boot", Labels: map[string]string{"workload": "vm1"}},
		Spec:       netv1.CompiledVolumeAttachmentSpec{ClusterName: "c1"},
	}
	idx := func(o client.Object) []string {
		return []string{o.(*netv1.CompiledVolumeAttachment).Spec.ClusterName}
	}
	central := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&netv1.CompiledVolumeAttachment{}, "spec.clusterName", idx).
		WithObjects(att).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).Build()

	b := &Broker{Central: central, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncCompiledVolumeAttachments(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := &netv1.CompiledVolumeAttachment{}
	if err := downstream.Get(context.Background(), client.ObjectKey{Namespace: "ns1", Name: "vm1-boot"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Labels["workload"] != "vm1" {
		t.Fatalf("workload label not propagated downstream: %v", got.Labels)
	}
}
