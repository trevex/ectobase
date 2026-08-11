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

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
)

// TestSync_NamespacedCreateUpdateGC drives the set-reconcile over the REAL,
// namespaced CompiledNIC across TWO namespaces: create, update (drift),
// GC (extra), and bounded-by-clusterName (c2 must not cross).
func TestSync_NamespacedCreateUpdateGC(t *testing.T) {
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	wl := func(ns, name, cn string) *compiledv1.CompiledNIC {
		return &compiledv1.CompiledNIC{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       compiledv1.CompiledNICSpec{ClusterName: cn},
		}
	}
	idx := func(o client.Object) []string { return []string{o.(*compiledv1.CompiledNIC).Spec.ClusterName} }
	hub := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&compiledv1.CompiledNIC{}, "spec.clusterName", idx).
		WithObjects(wl("ns1", "a", "c1"), wl("ns2", "b", "c1"), wl("ns1", "c", "c2")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(wl("ns1", "stale", "c1"), wl("ns1", "a", "c1")).Build()

	b := &Broker{Hub: hub, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	list := &compiledv1.CompiledNICList{}
	if err := downstream.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	// exactly {ns1/a, ns2/b}: c is c2 (bounded out), ns1/stale GC'd, ns1/a updated from OLD.
	if len(list.Items) != 2 {
		t.Fatalf("want 2 items, got %d: %+v", len(list.Items), list.Items)
	}
	got := map[string]bool{}
	for _, it := range list.Items {
		got[it.Namespace+"/"+it.Name] = true
	}
	if !got["ns1/a"] || !got["ns2/b"] {
		t.Fatalf("unexpected downstream set: %+v", got)
	}
	if got["ns1/stale"] {
		t.Fatalf("stale not GC'd: %+v", got)
	}
	if got["ns1/c"] {
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
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	vm := func(ns, name, cn, img string) *compiledv1.CompiledVM {
		return &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: compiledv1.CompiledVMSpec{ClusterName: cn, Image: img}}
	}
	idx := func(o client.Object) []string { return []string{o.(*compiledv1.CompiledVM).Spec.ClusterName} }
	hub := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&compiledv1.CompiledVM{}, "spec.clusterName", idx).
		WithObjects(vm("ns1", "a", "c1", "fedora"), vm("ns1", "b", "c2", "x")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(vm("ns1", "stale", "c1", "old"), vm("ns1", "a", "c1", "OLD")).Build()

	b := &Broker{Hub: hub, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncCompiledVMs(context.Background()); err != nil {
		t.Fatal(err)
	}

	list := &compiledv1.CompiledVMList{}
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
	list2 := &compiledv1.CompiledVMList{}
	if err := downstream.List(context.Background(), list2); err != nil {
		t.Fatal(err)
	}
	if len(list2.Items) != 1 || list2.Items[0].Name != "a" || list2.Items[0].Spec.Image != "fedora" {
		t.Fatalf("idempotency: set drifted on re-sync: %+v", list2.Items)
	}
}

func TestSyncCompiledVolumeAttachments_NamespacedCreateUpdateGC(t *testing.T) {
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil { t.Fatal(err) }
	att := func(ns, name, cn, img string) *compiledv1.CompiledVolumeAttachment {
		return &compiledv1.CompiledVolumeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: compiledv1.CompiledVolumeAttachmentSpec{ClusterName: cn, BootImage: img}}
	}
	idx := func(o client.Object) []string { return []string{o.(*compiledv1.CompiledVolumeAttachment).Spec.ClusterName} }
	hub := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&compiledv1.CompiledVolumeAttachment{}, "spec.clusterName", idx).
		WithObjects(att("ns1", "a", "c1", "fedora"), att("ns1", "b", "c2", "x")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(att("ns1", "stale", "c1", "old"), att("ns1", "a", "c1", "OLD")).Build()

	b := &Broker{Hub: hub, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncCompiledVolumeAttachments(context.Background()); err != nil { t.Fatal(err) }

	list := &compiledv1.CompiledVolumeAttachmentList{}
	if err := downstream.List(context.Background(), list); err != nil { t.Fatal(err) }
	if len(list.Items) != 1 || list.Items[0].Name != "a" || list.Items[0].Spec.BootImage != "fedora" {
		t.Fatalf("want [a(fedora)], got %+v", list.Items)
	}
	if err := b.SyncCompiledVolumeAttachments(context.Background()); err != nil { t.Fatalf("second sync: %v", err) }
}

func TestSyncCompiledContainers_NamespacedCreateUpdateGC(t *testing.T) {
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	ctr := func(ns, name, cn, img string) *compiledv1.CompiledContainer {
		return &compiledv1.CompiledContainer{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: compiledv1.CompiledContainerSpec{ClusterName: cn, Image: img}}
	}
	idx := func(o client.Object) []string { return []string{o.(*compiledv1.CompiledContainer).Spec.ClusterName} }
	hub := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&compiledv1.CompiledContainer{}, "spec.clusterName", idx).
		WithObjects(ctr("ns1", "a", "c1", "nginx"), ctr("ns1", "b", "c2", "x")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(ctr("ns1", "stale", "c1", "old"), ctr("ns1", "a", "c1", "OLD")).Build()

	b := &Broker{Hub: hub, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncCompiledContainers(context.Background()); err != nil {
		t.Fatal(err)
	}

	list := &compiledv1.CompiledContainerList{}
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
	list2 := &compiledv1.CompiledContainerList{}
	if err := downstream.List(context.Background(), list2); err != nil {
		t.Fatal(err)
	}
	if len(list2.Items) != 1 || list2.Items[0].Name != "a" || list2.Items[0].Spec.Image != "nginx" {
		t.Fatalf("idempotency: set drifted on re-sync: %+v", list2.Items)
	}
}

// TestSync_PropagatesLabels guards the load-bearing workload-label propagation: the
// downstream vm-materializer joins a VM to its volume attachments by the workload
// label, so the broker must mirror labels (not just spec) hub->downstream.
func TestSync_PropagatesLabels(t *testing.T) {
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	att := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "vm1-boot", Labels: map[string]string{"workload": "vm1"}},
		Spec:       compiledv1.CompiledVolumeAttachmentSpec{ClusterName: "c1"},
	}
	idx := func(o client.Object) []string {
		return []string{o.(*compiledv1.CompiledVolumeAttachment).Spec.ClusterName}
	}
	hub := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&compiledv1.CompiledVolumeAttachment{}, "spec.clusterName", idx).
		WithObjects(att).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).Build()

	b := &Broker{Hub: hub, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncCompiledVolumeAttachments(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := &compiledv1.CompiledVolumeAttachment{}
	if err := downstream.Get(context.Background(), client.ObjectKey{Namespace: "ns1", Name: "vm1-boot"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Labels["workload"] != "vm1" {
		t.Fatalf("workload label not propagated downstream: %v", got.Labels)
	}
}
