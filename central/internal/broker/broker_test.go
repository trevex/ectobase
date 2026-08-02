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

	platforminstall "github.com/trevex/ectobase/central/apis/platform/install"
	v1alpha1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	platforminstall.Install(s)
	return s
}

func wl(name, cn, payload string) *v1alpha1.CompiledWorkload {
	return &v1alpha1.CompiledWorkload{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v1alpha1.CompiledWorkloadSpec{ClusterName: cn, Payload: payload},
	}
}

func TestSync_CreatesUpdatesDeletes(t *testing.T) {
	s := newScheme(t)
	idx := func(o client.Object) []string { return []string{o.(*v1alpha1.CompiledWorkload).Spec.ClusterName} }
	central := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&v1alpha1.CompiledWorkload{}, "spec.clusterName", idx).
		WithObjects(wl("a", "c1", "x"), wl("b", "c2", "y")).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(wl("stale", "c1", "old"), wl("a", "c1", "OLD")).Build()

	b := &Broker{Central: central, Downstream: downstream, ClusterName: "c1"}
	if err := b.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	list := &v1alpha1.CompiledWorkloadList{}
	if err := downstream.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].Name != "a" || list.Items[0].Spec.Payload != "x" {
		t.Fatalf("want exactly [a(payload=x)], got %+v", list.Items)
	}

	// Idempotent: a second sync is a no-op (still exactly [a(x)]).
	if err := b.SyncOnce(context.Background()); err != nil {
		t.Fatalf("second SyncOnce: %v", err)
	}
	_ = downstream.List(context.Background(), list)
	if len(list.Items) != 1 {
		t.Fatalf("second sync not idempotent: %+v", list.Items)
	}
}
