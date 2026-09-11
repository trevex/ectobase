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
	"github.com/trevex/ectobase/api/validate"
)

// onDispatch places a fixture where the compiler actually writes it: the per-pool namespace, with
// the source back-reference stamped on it. Fixtures are authored in their SOURCE namespace (as the
// workload author sees them) and relocated here, mirroring the real pipeline — the broker is then
// expected to mirror them BACK to that source namespace downstream, which is what keeps the pool
// namespace a dispatch-side detail.
func onDispatch[T client.Object](o T, clusterName string) T {
	ann := o.GetAnnotations()
	if ann == nil {
		ann = map[string]string{}
	}
	ann[compiledv1.SourceNamespaceAnnotation] = o.GetNamespace()
	ann[compiledv1.SourceNameAnnotation] = o.GetName()
	o.SetAnnotations(ann)
	o.SetNamespace(validate.PoolNamespace(clusterName))
	return o
}

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
	dispatch := fake.NewClientBuilder().WithScheme(s).
		WithObjects(onDispatch(wl("ns1", "a", "c1"), "c1"), onDispatch(wl("ns2", "b", "c1"), "c1"), onDispatch(wl("ns1", "c", "c2"), "c2")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(wl("ns1", "stale", "c1"), wl("ns1", "a", "c1")).Build()

	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}
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
	dispatch := fake.NewClientBuilder().WithScheme(s).
		WithObjects(onDispatch(vm("ns1", "a", "c1", "fedora"), "c1"), onDispatch(vm("ns1", "b", "c2", "x"), "c2")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(vm("ns1", "stale", "c1", "old"), vm("ns1", "a", "c1", "OLD")).Build()

	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}
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
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	att := func(ns, name, cn, img string) *compiledv1.CompiledVolumeAttachment {
		return &compiledv1.CompiledVolumeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: compiledv1.CompiledVolumeAttachmentSpec{ClusterName: cn, BootImage: img}}
	}
	dispatch := fake.NewClientBuilder().WithScheme(s).
		WithObjects(onDispatch(att("ns1", "a", "c1", "fedora"), "c1"), onDispatch(att("ns1", "b", "c2", "x"), "c2")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(att("ns1", "stale", "c1", "old"), att("ns1", "a", "c1", "OLD")).Build()

	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncCompiledVolumeAttachments(context.Background()); err != nil {
		t.Fatal(err)
	}

	list := &compiledv1.CompiledVolumeAttachmentList{}
	if err := downstream.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].Name != "a" || list.Items[0].Spec.BootImage != "fedora" {
		t.Fatalf("want [a(fedora)], got %+v", list.Items)
	}
	if err := b.SyncCompiledVolumeAttachments(context.Background()); err != nil {
		t.Fatalf("second sync: %v", err)
	}
}

func TestSyncCompiledContainers_NamespacedCreateUpdateGC(t *testing.T) {
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	ctr := func(ns, name, cn, img string) *compiledv1.CompiledContainer {
		return &compiledv1.CompiledContainer{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: compiledv1.CompiledContainerSpec{ClusterName: cn, Image: img}}
	}
	dispatch := fake.NewClientBuilder().WithScheme(s).
		WithObjects(onDispatch(ctr("ns1", "a", "c1", "nginx"), "c1"), onDispatch(ctr("ns1", "b", "c2", "x"), "c2")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(ctr("ns1", "stale", "c1", "old"), ctr("ns1", "a", "c1", "OLD")).Build()

	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}
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
// label, so the broker must mirror labels (not just spec) dispatch->downstream.
func TestSync_PropagatesLabels(t *testing.T) {
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	att := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "vm1-boot", Labels: map[string]string{"workload": "vm1"}},
		Spec:       compiledv1.CompiledVolumeAttachmentSpec{ClusterName: "c1"},
	}
	dispatch := fake.NewClientBuilder().WithScheme(s).
		WithObjects(onDispatch(att, "c1")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).Build()

	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}
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
