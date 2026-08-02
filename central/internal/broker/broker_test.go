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

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
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
